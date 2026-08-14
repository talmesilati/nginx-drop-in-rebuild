#!/usr/bin/env python3
"""
Differential compatibility test: nginx:1.25-bookworm vs our rebuild.

"Drop-in replacement" means that for the same config and the same bytes on the
wire, both images produce the same status line, headers and body, and behave the
same at the container boundary. So nothing here asserts an expected response --
upstream's answer is the expected answer.

Requests go over raw sockets so malformed input stays malformed instead of being
sanitised by a client library. Stdlib only.

Date, ETag and Last-Modified are compared for presence but not value: they are
wall clock and file mtime, which differ between builds. Everything else must
match byte for byte.
"""

import os
import re
import socket
import subprocess
import sys
import time
import uuid

BASE_IMAGE = os.environ.get("BASE_IMAGE", "nginx:1.25-bookworm")
TEST_IMAGE = os.environ.get("TEST_IMAGE", "nginx-hardened:1.25.5")

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")

VOLATILE = {"date", "etag", "last-modified"}

RESET, BOLD, RED, GREEN, YELLOW = "\033[0m", "\033[1m", "\033[31m", "\033[32m", "\033[33m"


# --------------------------------------------------------------------- plumbing
def sh(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check)


def docker(*args, check=True):
    return sh("docker", *args, check=check)


class Container:
    """A running nginx under test."""

    def __init__(self, image, name, mounts):
        self.image = image
        self.name = name
        run = ["run", "-d", "--name", name, "-P"]
        for host, dest in mounts:
            run += ["-v", f"{host}:{dest}:ro"]
        run += [image]
        docker("rm", "-f", name, check=False)
        docker(*run)
        self.port = int(
            docker("port", name, "80/tcp").stdout.strip().splitlines()[0].rsplit(":", 1)[1]
        )

    def wait_ready(self, timeout=25.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                    return True
            except OSError:
                time.sleep(0.25)
        raise RuntimeError(f"{self.name} never accepted connections\n{self.logs()}")

    def logs(self):
        r = docker("logs", self.name, check=False)
        return r.stdout + r.stderr

    def exec(self, *cmd):
        return docker("exec", self.name, *cmd, check=False)

    def send(self, payload, read_bytes=1 << 20, timeout=10.0):
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(payload)
            chunks, total = [], 0
            while total < read_bytes:
                try:
                    b = s.recv(65536)
                except (socket.timeout, ConnectionResetError):
                    break
                if not b:
                    break
                chunks.append(b)
                total += len(b)
        return b"".join(chunks)

    def destroy(self):
        docker("rm", "-f", self.name, check=False)


def parse(raw):
    """Split a raw HTTP response into (status_line, headers, body).

    Interim 1xx responses are skipped so an Expect: 100-continue exchange is
    compared on its final response rather than as one opaque body.
    """
    if not raw:
        return None, [], b""
    while raw.startswith(b"HTTP/1.1 1") and b"\r\n\r\n" in raw:
        raw = raw.partition(b"\r\n\r\n")[2]
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = lines[0] if lines else ""
    headers = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip().lower(), v.strip()))
    return status, headers, body


# -------------------------------------------------------------------- scenarios
def req(method, path, host="localhost", version="HTTP/1.1", headers=(), body=b""):
    lines = [f"{method} {path} {version}"]
    if version == "HTTP/1.1":
        lines.append(f"Host: {host}")
    lines += [f"{k}: {v}" for k, v in headers]
    if body:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


BIG = b"x" * (2 * 1024 * 1024)  # over nginx's default 1m client_max_body_size

DEFAULT_SCENARIOS = [
    ("root",                    req("GET", "/")),
    ("index explicit",          req("GET", "/index.html")),
    ("404 missing",             req("GET", "/no/such/thing")),
    ("50x page",                req("GET", "/50x.html")),
    ("HEAD root",               req("HEAD", "/")),
    ("HTTP/1.0 no host",        req("GET", "/", version="HTTP/1.0")),
    ("POST to static",          req("POST", "/", body=b"a=1&b=2")),
    ("PUT to static",           req("PUT", "/index.html", body=b"nope")),
    ("DELETE to static",        req("DELETE", "/index.html")),
    ("unknown method",          req("WOMBAT", "/")),
    ("body over limit (2MiB)",  req("POST", "/", body=BIG)),
    ("directory traversal",     req("GET", "/../../etc/passwd")),
    ("encoded traversal",       req("GET", "/%2e%2e%2f%2e%2e%2fetc/passwd")),
    ("long URI (8KiB)",         req("GET", "/" + "a" * 8192)),
    ("oversized header",        req("GET", "/", headers=[("X-Big", "A" * 16384)])),
    ("many headers",            req("GET", "/", headers=[(f"X-H{i}", str(i)) for i in range(64)])),
    ("absolute-form URI",       req("GET", "http://localhost/index.html")),
    ("missing host 1.1",        b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n"),
    ("malformed request line",  b"GET\r\n\r\n"),
    ("garbage bytes",           b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03\r\n\r\n"),
    ("bad http version",        b"GET / HTTP/9.9\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    ("null in URI",             b"GET /\x00 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    ("bare LF terminators",     b"GET / HTTP/1.1\nHost: localhost\nConnection: close\n\n"),
    ("empty request",           b"\r\n\r\n"),
    ("if-modified-since old",   req("GET", "/", headers=[("If-Modified-Since", "Wed, 01 Jan 2020 00:00:00 GMT")])),
    ("range request",           req("GET", "/index.html", headers=[("Range", "bytes=0-99")])),
    ("unsatisfiable range",     req("GET", "/index.html", headers=[("Range", "bytes=999999-1000000")])),
    ("accept-encoding gzip",    req("GET", "/index.html", headers=[("Accept-Encoding", "gzip")])),
    ("expect 100-continue",     req("GET", "/", headers=[("Expect", "100-continue")])),
]

CUSTOM_SCENARIOS = [
    ("custom conf: return",     req("GET", "/echo")),
    ("custom conf: add_header", req("GET", "/hello.txt")),
    ("custom conf: gzip on",    req("GET", "/big.txt", headers=[("Accept-Encoding", "gzip")])),
    ("custom conf: no gzip",    req("GET", "/big.txt")),
    ("custom docroot file",     req("GET", "/hello.txt")),
    ("custom conf: 404 page",   req("GET", "/definitely-absent")),
    ("custom conf: body limit", req("POST", "/echo", body=b"y" * (512 * 1024))),
    ("custom conf: stub_status",req("GET", "/basic_status")),
]


# ----------------------------------------------------------------- comparison
class Report:
    def __init__(self):
        self.passed = 0
        self.failures = []

    def ok(self, name):
        self.passed += 1
        print(f"  {GREEN}PASS{RESET}  {name}")

    def fail(self, name, detail):
        self.failures.append((name, detail))
        print(f"  {RED}FAIL{RESET}  {name}\n        {detail}")


def normalise_status(status):
    return status.strip()


def compare(name, a_raw, b_raw, report):
    a_status, a_head, a_body = parse(a_raw)
    b_status, b_head, b_body = parse(b_raw)

    if not a_raw and not b_raw:
        report.ok(f"{name} (both closed connection with no response)")
        return

    if normalise_status(a_status) != normalise_status(b_status):
        report.fail(name, f"status: upstream {a_status!r} != ours {b_status!r}")
        return

    a_names = [k for k, _ in a_head]
    b_names = [k for k, _ in b_head]
    if a_names != b_names:
        only_a = [h for h in a_names if h not in b_names]
        only_b = [h for h in b_names if h not in a_names]
        report.fail(
            name,
            f"header set differs: missing from ours {only_a}, extra in ours {only_b}"
            if (only_a or only_b) else f"header order differs: {a_names} vs {b_names}",
        )
        return

    for (ka, va), (kb, vb) in zip(a_head, b_head):
        if ka in VOLATILE:
            if bool(va) != bool(vb):
                report.fail(name, f"volatile header {ka} present on one side only")
                return
            continue
        if va != vb:
            report.fail(name, f"header {ka}: upstream {va!r} != ours {vb!r}")
            return

    if a_body != b_body:
        report.fail(
            name,
            f"body differs ({len(a_body)}B vs {len(b_body)}B): "
            f"{a_body[:120]!r} != {b_body[:120]!r}",
        )
        return

    report.ok(name)


def run_round(title, mounts, scenarios, report):
    print(f"\n{BOLD}{title}{RESET}")
    suffix = uuid.uuid4().hex[:8]
    upstream = Container(BASE_IMAGE, f"compat-base-{suffix}", mounts)
    ours = Container(TEST_IMAGE, f"compat-new-{suffix}", mounts)
    try:
        upstream.wait_ready()
        ours.wait_ready()
        for name, payload in scenarios:
            compare(name, upstream.send(payload), ours.send(payload), report)
        return upstream, ours
    except Exception:
        upstream.destroy()
        ours.destroy()
        raise


# ------------------------------------------------- container-boundary parity
def container_checks(upstream, ours, report):
    print(f"\n{BOLD}Container contract{RESET}")

    # Requests must reach `docker logs`, i.e. the access log is still a symlink
    # to /dev/stdout. An earlier iteration of this build silently lost that.
    for label, c in (("upstream", upstream), ("ours", ours)):
        if 'GET /' not in c.logs():
            report.fail(f"docker logs carries access log ({label})",
                        "no request lines in container output")
            break
    else:
        report.ok("docker logs carries access log (both)")

    va = upstream.exec("nginx", "-v").stderr.strip()
    vb = ours.exec("nginx", "-v").stderr.strip()
    if va == vb:
        report.ok(f"nginx -v identical ({va})")
    else:
        report.fail("nginx -v", f"{va!r} != {vb!r}")

    ua = upstream.exec("sh", "-c", "id -u nginx; id -g nginx").stdout.split()
    ub = ours.exec("sh", "-c", "id -u nginx; id -g nginx").stdout.split()
    if ua == ub:
        report.ok(f"nginx uid/gid identical ({'/'.join(ua)})")
    else:
        report.fail("nginx uid/gid", f"{ua} != {ub}")

    ha = upstream.exec("sh", "-c", "ls /docker-entrypoint.d | sort").stdout.split()
    hb = ours.exec("sh", "-c", "ls /docker-entrypoint.d | sort").stdout.split()
    if ha == hb:
        report.ok(f"/docker-entrypoint.d matches ({len(ha)} scripts)")
    else:
        report.fail("/docker-entrypoint.d", f"{ha} != {hb}")

    la = upstream.exec("sh", "-c", "ls /etc/nginx | sort").stdout.split()
    lb = ours.exec("sh", "-c", "ls /etc/nginx | sort").stdout.split()
    if la == lb:
        report.ok(f"/etc/nginx layout matches ({' '.join(la)})")
    else:
        report.fail("/etc/nginx layout", f"upstream {la} != ours {lb}")

    # The dynamic-module gap is deliberate (upstream's 12 .so files pull in
    # libgd3 and the image-codec stack, worth 148 CVE IDs), so it is asserted
    # rather than described: this fails if either side changes, because then the
    # README is stale in one direction or the other.
    mods_up = sorted(upstream.exec("sh", "-c", "ls /usr/lib/nginx/modules 2>/dev/null").stdout.split())
    mods_our = sorted(ours.exec("sh", "-c", "ls /usr/lib/nginx/modules 2>/dev/null").stdout.split())
    if mods_up and not mods_our:
        report.ok(f"dynamic modules: documented gap holds "
                  f"(upstream {len(mods_up)}, ours 0 -- see README)")
    elif mods_our:
        report.fail("dynamic modules",
                    f"ours now ships {len(mods_our)} module(s) {mods_our} -- the README "
                    f"documents this image as shipping none. Update the docs or the build.")
    else:
        report.fail("dynamic modules",
                    "upstream ships none either -- the documented justification for "
                    "omitting them no longer applies. Re-check the parity claim.")

    # Remediation evidence is not parity, but it is asserted here so a
    # regression in the build fails the test suite rather than only the scan.
    ssl = ours.exec("sh", "-c", "nginx -V 2>&1 | tr ' ' '\\n' | grep -i '^OpenSSL' -A1 | tr '\\n' ' '").stdout
    vv = ours.exec("sh", "-c", "nginx -V 2>&1").stderr + ours.exec("sh", "-c", "nginx -V 2>&1").stdout
    m = re.search(r"built with OpenSSL (\S+)", vv)
    if m and m.group(1) >= "3.0.21":
        report.ok(f"remediation: linked against OpenSSL {m.group(1)} (bumped)")
    else:
        report.fail("remediation: OpenSSL bump", f"unexpected version banner: {ssl or vv[:200]!r}")

    linked = ours.exec("sh", "-c", "ldd /usr/sbin/nginx | grep -E 'libssl|libcrypto'").stdout.strip()
    if "/usr/lib/nginx/openssl" in linked:
        report.ok("remediation: nginx resolves our private libssl/libcrypto")
    else:
        report.fail("remediation: OpenSSL linkage", f"ldd shows: {linked!r}")

    patched = ours.exec("sh", "-c",
                        "grep -c 'unordered mp4 stsc chunks' /usr/sbin/nginx || true").stdout.strip()
    if patched not in ("", "0"):
        report.ok("remediation: CVE-2024-7347 backport present in shipped binary")
    else:
        report.fail("remediation: CVE-2024-7347 backport",
                    "patched log string absent from /usr/sbin/nginx")

    st = ours.exec("sh", "-c", "dpkg-query -W -f='${Package} ${Version}' nginx").stdout.strip()
    if st.startswith("nginx 1.25.5"):
        report.ok(f"dpkg registration: {st}")
    else:
        report.fail("dpkg registration", f"got {st!r}")

    # The check that would have caught the original mistake: the first build
    # copied libssl/libcrypto into the nginx package, where they worked at
    # runtime but had no dpkg entry, so the scanners never saw them and a clean
    # report was partly an artefact of hiding the library. `Source: openssl` is
    # what maps the package onto the openssl advisory feed, so it is asserted too.
    ssl_pkg = ours.exec("sh", "-c",
                        "dpkg-query -W -f='${Package} ${Version} ${source:Package}' "
                        "nginx-openssl").stdout.strip()
    fields = ssl_pkg.split()
    if len(fields) == 3 and fields[0] == "nginx-openssl" \
            and fields[1].startswith("3.0.21") and fields[2] == "openssl":
        report.ok(f"dpkg registration: {fields[0]} {fields[1]} (source: {fields[2]})")
    else:
        report.fail("dpkg registration: nginx-openssl",
                    f"expected 'nginx-openssl 3.0.21-* openssl', got {ssl_pkg!r}. "
                    "A missing source field makes the OpenSSL bump unscannable.")


# ------------------------------------------------------------------------ main
def main():
    os.makedirs(os.path.join(FIXTURES, "html"), exist_ok=True)
    big = os.path.join(FIXTURES, "html", "big.txt")
    if not os.path.exists(big):
        with open(big, "w") as fh:
            fh.write("compressible text. " * 20000)

    print(f"{BOLD}upstream:{RESET} {BASE_IMAGE}")
    print(f"{BOLD}ours:    {RESET} {TEST_IMAGE}")

    report = Report()
    live = []
    try:
        u1, o1 = run_round("Round 1 - default configuration", [], DEFAULT_SCENARIOS, report)
        live += [u1, o1]
        container_checks(u1, o1, report)

        # Round 2 mounts a user config the way people actually use this image.
        # It is what caught /etc/nginx/conf.d missing from the package.
        u2, o2 = run_round(
            "Round 2 - user-supplied config and docroot",
            [(os.path.join(FIXTURES, "conf.d"), "/etc/nginx/conf.d"),
             (os.path.join(FIXTURES, "html"), "/usr/share/nginx/html")],
            CUSTOM_SCENARIOS, report)
        live += [u2, o2]
    finally:
        for c in live:
            c.destroy()

    total = report.passed + len(report.failures)
    print(f"\n{BOLD}{report.passed}/{total} checks matched{RESET}")
    if report.failures:
        print(f"\n{RED}{BOLD}mismatches:{RESET}")
        for name, detail in report.failures:
            print(f"  - {name}: {detail}")
        return 1
    print(f"{GREEN}{BOLD}drop-in compatible.{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
