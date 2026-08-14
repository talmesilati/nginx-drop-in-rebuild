# nginx 1.25.5 — drop-in replacement for `nginx:1.25-bookworm`

Rebuilt from upstream source on Debian bookworm. Two CVEs fixed by two different
techniques, packaged as `.deb`s, shipped in an image that passes a 48-check
differential test against the original.

```
make          # build the .deb from upstream source, then the image
make test     # differential compatibility test vs nginx:1.25-bookworm
make scan     # trivy + grype, diffed against the saved baseline
make vex      # re-scan with the VEX document applied
```

Needs Docker, Python 3 (stdlib only), and `trivy`/`grype` for the scan targets.
`make` takes about 4 minutes on an M-series Mac, nearly all of it compiling
OpenSSL.

## Results

| | upstream | this build |
|---|---|---|
| image size (uncompressed, arm64) | 64.5 MB | **31.6 MB** |
| `.deb` size | — | 2.0 MB (two packages) |
| Trivy findings | 615 | **176** |
| Grype findings | 612 | **170** |
| unique CVE IDs (Trivy) | 392 | **88** |
| unique CVE IDs (Grype) | 396 | **86** |
| installed packages | 149 | 91 |
| compatibility checks passed | — | **48 / 48** |
| nginx version reported | 1.25.5 | 1.25.5 |

Findings outnumber unique CVE IDs because one CVE is reported once per affected
package: Grype lists every OpenSSL issue twice, under `openssl` and `libssl3`.
`make scan` prints both figures.

### What the drop is actually made of

Most of it is not remediation. Split by cause:

| Cause | unique CVE IDs | Severity |
|---|---|---|
| OpenSSL 3.0.11 → 3.0.21 (the version bump) | **36** | 4 Critical, 16 High, 15 Medium, 1 Low |
| Packages upstream installs and we don't | 274 | 18 Critical, 93 High, 97 Medium, 14 Low, 45 Negligible, 7 Unknown |
| CVE-2024-7347 (the backport) | 0 ¹ | not scanner-visible either way |
| New in our report | −6 | 6 nginx IDs Trivy attributes to us but not upstream |
| | **310 gone, 6 new** | 392 − 310 + 6 = 88 |

¹ Fixed, but invisible to both scanners in both images, because the fix is a
source patch under an unchanged version string. That is what the [VEX](#vex)
section is about.

So 36 IDs are attributable to the remediation and 274 to a smaller base image.
The brief says removals don't count toward the requirement, and the split is here
because the headline number is the one people quote. The 274 is also the row to be
suspicious of: a package that isn't installed can't be exploited, but it also
can't be the thing your application needed. That's what `make test` is for, and
where the one known [parity gap](#known-gap-dynamic-modules) comes from.

## CVEs fixed

| CVE | Severity | Lives in | Upstream fix | Method | Evidence |
|---|---|---|---|---|---|
| [CVE-2024-7347](https://nginx.org/en/security_advisories.html) | not rated here ¹ | `/usr/sbin/nginx`, `ngx_http_mp4_module` | nginx 1.27.1 / 1.26.2 | **backport** | [`build/patches/CVE-2024-7347.patch`](build/patches/CVE-2024-7347.patch) · [patch.2024.mp4.txt](https://nginx.org/download/patch.2024.mp4.txt) |
| CVE-2025-15467 · CVE-2024-5535 · CVE-2026-31789 · CVE-2026-34182 | **Critical** ×4 | `libssl3` / `openssl` 3.0.11-1~deb12u2 | ≤ OpenSSL 3.0.20 | **version bump** to 3.0.21 | [`build/build.sh`](build/build.sh) `build_openssl()` |
| CVE-2024-6119 + 15 more | High ×16 | same | ≤ OpenSSL 3.0.20 | **version bump** | same |
| 16 further OpenSSL IDs ² | Medium ×16, Low, Negligible | same | ≤ OpenSSL 3.0.20 | **version bump** | same |

¹ Neither scanner reports CVE-2024-7347 against the nginx package, so there is no
scanner-assigned severity to quote from anything in this repo. nginx.org rates the
mp4 advisories low. That absence is why the CVE needs a VEX statement.

² 38 unique OpenSSL IDs in total: 4 Critical, 16 High, 16 Medium, 1 Low, 1
Negligible. Grype's FIXED-IN column shows the highest version any of them needs is
3.0.20 and we ship 3.0.21, which is the basis for the claim; it is re-derivable
from `baseline-grype.txt`. Full list in [`scan/fixed-cves.txt`](scan/fixed-cves.txt),
per-CVE reasoning in [`docs/triage-notes.md`](docs/triage-notes.md).

Two of the 38 are not fixed by any release: `CVE-2025-27587` has no fix in the 3.0
branch, and Debian marks `CVE-2026-42767` won't-fix. Both show up in our own scan
because OpenSSL ships as a dpkg-registered package (see [below](#why-two-packages)).
Neither applies here, for two different and separately checkable reasons:

| CVE | Why it doesn't apply | How it's handled |
|---|---|---|
| `CVE-2026-42767` | NULL deref in OpenSSL's CMP/CRMF client code; nginx has no CMP surface | compiled out with `no-cmp`, so the code is absent from `libcrypto.so.3` |
| `CVE-2025-27587` | Minerva timing leak in OpenSSL's PowerPC EC code | nothing to remove; that code isn't built for arm64/amd64 |

Applying the VEX document takes the total from 176 to 174.

### Why these, and what I passed over

OpenSSL was the obvious bump: one dependency, 38 CVE IDs, four of them Critical,
and every TLS byte nginx handles goes through it.

CVE-2024-7347 was the right backport because the fix exists upstream but not for
1.25.x. nginx fixed it in 1.27.1 and 1.26.2 and never released a 1.25.6, so
staying on 1.25.5 means patching source and compiling. The patch is also small
enough to read in full (a 64-bit widening plus a chunk-ordering check), which
makes proving it landed worth something.

Passed over, with the reasoning in [`docs/triage-notes.md`](docs/triage-notes.md):

- `curl`/`libcurl4` (35 findings) and `libexpat1` (31). Debian ships fixed
  packages, and neither is linked by nginx or on any code path in the default
  build. A source build against either would demonstrate the technique against
  something that can't affect the running service.
- `libtiff6`, `libheif1` (54 combined). Not reachable from nginx. Removing them is
  the right real-world action and the brief excludes removals.
- `CVE-2023-44487`, Grype's highest-risk nginx finding and my first pick. HTTP/2
  rapid reset is a rate-limiting problem addressed through connection and stream
  limits, not one reviewable patch against 1.25.5.
- The three nginx 2026 CVEs. Still the best remaining targets, since backporting
  one is the only thing that would show a VEX suppressing an *nginx* finding
  rather than an OpenSSL one. Dropped on time: finding and validating the upstream
  commits was more research than I had left.

### Verify it yourself

```bash
# backport is in the shipped binary (the log string only exists in fixed code)
docker run --rm --entrypoint sh nginx-hardened:1.25.5 \
  -c "grep -c 'unordered mp4 stsc chunks' /usr/sbin/nginx"      # -> 1

# version bump: nginx resolves our private OpenSSL, not Debian's libssl3
docker run --rm --entrypoint sh nginx-hardened:1.25.5 \
  -c "nginx -V 2>&1 | grep OpenSSL; ldd /usr/sbin/nginx | grep -E 'libssl|libcrypto'"
# built with OpenSSL 3.0.21 9 Jun 2026
# libssl.so.3    => /usr/lib/nginx/openssl/lib/libssl.so.3
# libcrypto.so.3 => /usr/lib/nginx/openssl/lib/libcrypto.so.3

# Debian's libssl3 is not installed at all
docker run --rm --entrypoint sh nginx-hardened:1.25.5 -c "dpkg -l | grep -c libssl3"   # -> 0

# our OpenSSL is registered with dpkg, so scanners can judge it
docker run --rm --entrypoint dpkg-query nginx-hardened:1.25.5 \
  -W -f='${Package} ${Version} source=${source:Package} ${Architecture}\n' nginx-openssl
# nginx-openssl 3.0.21-1+echo1~bookworm source=openssl arm64

# CVE-2026-42767: the CMP/CRMF code the advisory describes isn't in the library
docker run --rm --entrypoint sh nginx-hardened:1.25.5 \
  -c "grep -ac 'OSSL_CMP\|OSSL_CRMF' /usr/lib/nginx/openssl/lib/libcrypto.so.3"   # -> 0
```

`build.sh` asserts all of these during the build and fails if any is missing, so
neither a silently-dropped patch nor an unsubstantiated VEX claim can ship. The
last two are also checked by `make test`.

## How the build works

```
build/build.sh          one script, runs in debian:bookworm-slim, two packages out
  ├── import_keys       keyring per project from build/keys/*.asc, exporting
  │                     only the pinned fingerprint
  ├── build_openssl     fetch openssl-3.0.21.tar.gz, verify sha256 + signature,
  │                     ./config --prefix=/usr/lib/nginx/openssl with hardening
  │                     and no-cmp, install, assert the CMP code is gone
  ├── fetch_nginx       fetch nginx-1.25.5.tar.gz, verify sha256 + signature
  ├── apply_patches     patch -p1 for each build/patches/*.patch, then grep the
  │                     source to prove the hunk landed
  ├── build_nginx       ./configure with upstream's flag set, our OpenSSL via
  │                     -I/-L/-rpath, plus Debian's hardening flags
  ├── evidence          assert the fix is in the freshly linked binary
  ├── stage             make install, then reshape to the official package layout
  ├── stage_openssl     libssl/libcrypto only: no headers, no static libs, no
  │                     second openssl(1)
  ├── evidence          re-assert against the staged binary, after strip
  ├── control           nginx control/conffiles/md5sums/postinst; Depends:
  │                     nginx-openssl (= 3.0.21-1+echo1~bookworm)
  ├── control_openssl   nginx-openssl control, with Source: openssl
  └── package           build_deb ×2 -> dist/nginx_….deb, dist/nginx-openssl_….deb
```

Nothing installs a pre-built nginx; the only nginx binary in the builder is the
one `make` produces. `Containerfile` installs both `.deb`s in a single
`apt-get install` into a fresh `debian:bookworm-slim`, one command so apt resolves
nginx's dependency on `nginx-openssl` locally instead of looking for a repository.
It asserts the package count first, so a stale artifact in `dist/` fails the build
instead of being installed silently.

### Why two packages

The first version of this build copied `libssl.so.3` and `libcrypto.so.3` into the
nginx package. That works at runtime and is invisible to scanners: only `dpkg`
writes to `/var/lib/dpkg/status`, and that file is all Trivy and Grype read to
decide what's installed. Files copied into another package's payload get no entry.
So the first build fixed 36 OpenSSL CVEs and destroyed anyone's ability to verify
it, including for any CVE disclosed after 3.0.21. Giving the library its own name,
version and `Source: openssl` field lets the scanners judge it instead, which is
how the two unfixable IDs above became visible rather than hidden.

### Two traps worth naming

- **PCRE2, not PCRE1.** Upstream depends on `libpcre2-8-0`. Building against
  `libpcre3-dev` links a different regex engine with different corner cases, in a
  project whose whole premise is behavioural equivalence.
- **`--with-openssl=` does not mean what it sounds like.** It makes nginx compile
  and *statically* link OpenSSL itself, so `ldd` shows no `libssl` and any
  separately built OpenSSL is dead weight. We link a shared build through
  `--with-cc-opt`/`--with-ld-opt` and an `-rpath`, which is what the `ldd`
  evidence above shows.

### Source verification

Both tarballs are checked twice, because a hash and a signature answer different
questions. `sha256sum` answers "are these the bytes this repo was written
against"; `gpgv` answers "did upstream ever release them". A pinned hash of a
tampered download matches that download forever.

Keys are vendored in [`build/keys/`](build/keys) rather than fetched from a
keyserver at build time, so the trust decision lives in a commit instead of in a
network call. Fingerprints are pinned in `build.sh` separately from the key files
(`43387825…` for nginx, `BA5473A2…` for OpenSSL), and `import_keys` imports each
`.asc` into a scratch keyring, then exports only the pinned fingerprint into the
keyring `gpgv` uses. `openssl.asc` is upstream's `pubkeys.asc` verbatim and holds
five keys; only one can verify anything here, and swapping the file for one
containing someone else's key fails the build rather than widening trust silently.

nginx signs releases per-maintainer rather than with one project key, so the
fingerprint above is the one that actually signed 1.25.5, established by matching
the signature's issuer rather than by guessing which maintainer it was.

## Compatibility test

`make test` runs [`test/compat_test.py`](test/compat_test.py), Python 3 stdlib
only. It boots the upstream image and ours as separate containers, drives both
over raw sockets so malformed requests stay malformed instead of being sanitised
by a client library, and compares responses.

"Working correctly" means: for identical configuration and identical bytes on the
wire, both images return the same status line, the same header names in the same
order, the same header values, and a byte-identical body, and behave the same at
the container boundary. Any difference exits non-zero.

Three header values are compared for presence but not equality, because they
can't match by construction: `Date`, and `ETag`/`Last-Modified`, which derive from
file mtimes that differ between two independently built images. Everything else
must match byte for byte.

**Round 1, stock images, no mounts (29 scenarios).** Root, explicit index, missing
path, `50x.html`, `HEAD`, HTTP/1.0 without a Host, `POST`/`PUT`/`DELETE` to a
static file, an unknown method, a 2 MiB body against the default 1 MiB limit,
plain and percent-encoded traversal, an 8 KiB URI, a 16 KiB header, 64 headers,
absolute-form URI, missing Host on 1.1, a truncated request line, TLS handshake
bytes on a plaintext port, a bogus HTTP version, a NUL in the URI, bare-LF line
endings, an empty request, `If-Modified-Since`, satisfiable and unsatisfiable
`Range`, `Accept-Encoding: gzip`, and `Expect: 100-continue`.

**Container contract (11 checks).** Requests appear in `docker logs`, so the
access log really is a symlink to `/dev/stdout`; `nginx -v` matches; the nginx
uid/gid is 101/101 on both; `/docker-entrypoint.d` holds the same four hooks;
`/etc/nginx` has the same entries including the `modules` symlink; the
[module gap](#known-gap-dynamic-modules) is exactly as documented; both packages
are registered with dpkg, `nginx-openssl` including its `Source: openssl` field;
and both remediations are present in the binary.

**Round 2, user config and docroot (8 scenarios).** A `conf.d/*.conf` and an
`/usr/share/nginx/html` are bind-mounted into both containers, which is how this
image is actually used. Covers `return`, `add_header`, gzip on and off for the
same resource, a file from the custom docroot, a custom `error_page`, a
`client_max_body_size` rejection, and `stub_status`. This round caught the failure
mode the first iteration had: if `nginx.conf` doesn't include `conf.d`, every
check here fails.

Result: 48 / 48.

### Known gap: dynamic modules

Upstream installs four module packages; we install none.

```
$ docker run --rm --entrypoint sh nginx:1.25-bookworm -c 'dpkg -l | grep nginx'
nginx  nginx-module-geoip  nginx-module-image-filter  nginx-module-njs  nginx-module-xslt
$ docker run --rm --entrypoint sh nginx:1.25-bookworm -c 'ls /usr/lib/nginx/modules | wc -l'
12
$ docker run --rm --entrypoint sh nginx-hardened:1.25.5 -c 'ls /usr/lib/nginx/modules | wc -l'
0
```

A config with `load_module modules/ngx_http_js_module.so;` starts upstream and
fails here. That's a real drop-in failure for anyone using njs, GeoIP, XSLT or the
image filter, and no request scenario can see it because no default config loads a
dynamic module. It's check 6 of the container contract instead, asserted in both
directions so it fails if either side changes.

It's still open because the four modules need `libgeoip1`, `libgd3`, `libxml2` and
`libxslt1.1` at runtime, and `libgd3` pulls in 30 packages: the image-codec stack,
`libtiff6`, `libheif1`, `libwebp7`, `libde265-0`, `libx265-199`, `libexpat1`,
`libpng16-16`, `libicu72` and friends. Those carry 148 unique CVE IDs against the
baseline (6 Critical, 47 High, 52 Medium, 8 Low, 28 Negligible, 7 Unknown), worst
offenders `libexpat1` 31, `libtiff6` 29, `libheif1` 25, `libxml2` 22. Compiling
the modules in would roughly double this image's finding count, from 170 Grype
findings to about 318, for features no default config uses.

The right fix is what upstream does at the packaging layer: build the modules as
separate `.deb`s that aren't installed by default, so a consumer who needs njs
installs `nginx-module-njs` and takes those CVEs deliberately. `build.sh` already
passes `--with-compat`, so the ABI allows it. Roughly three hours of work and the
top item in [next steps](#what-id-do-next).

## VEX

Scanners match on package name plus version, so they're blind to anything you do
to a package's contents. A backport under an unchanged version string looks
identical to an unpatched build, and a feature compiled out still matches the
advisory's version range. VEX is how you say so in a form a tool acts on.

[`vex/nginx-hardened.openvex.json`](vex/nginx-hardened.openvex.json) is an OpenVEX
0.2.0 document with three statements, covering three different situations.
`make vex` scans the image with and without it:

```
  CVE              without   with   why
  ---------------- --------- ------ ---
  CVE-2024-7347    0         0      fixed: backport, invisible to version matching
  CVE-2026-42767   1         0      not_affected: CMP/CRMF compiled out (no-cmp)
  CVE-2025-27587   1         0      not_affected: PowerPC-only code, arm64 build

  totals   without VEX 176   with VEX 174
```

- `CVE-2024-7347`, `status: fixed`. The brief asks for a VEX on a backported CVE
  showing the finding disappear, and this is where I hit a wall: neither scanner
  reports it against nginx 1.25.5 in either image, so there's nothing to suppress
  and the count stays 0 → 0. See below for what I tried. The statement ships
  anyway, because the backport is real and a consumer's scanner may flag what ours
  doesn't.
- `CVE-2026-42767`, `status: not_affected`, justification
  `vulnerable_code_not_present`. Debian marks it won't-fix, so 3.0.21 still
  matches the range. Rather than argue nginx never acts as a CMP client, the build
  passes `no-cmp` and the code is gone: `grep -ac 'OSSL_CMP\|OSSL_CRMF'` on the
  shipped `libcrypto.so.3` returns 0, and `build.sh` asserts that during the build
  so the statement can't rot into a false claim.
- `CVE-2025-27587`, same status, different basis. The advisory is scoped to
  PowerPC and this package is `Architecture: arm64`, so nothing was removed; the
  affected code was never compiled. Upstream has no 3.0-branch fix either.

`vulnerable_code_not_present` is a fact about the binary. The alternative,
`vulnerable_code_not_in_execute_path`, would have been an argument about intent,
which is worth less and is what makes `not_affected` easy to abuse: Chainguard and
Docker are currently accusing each other in public of exactly that, one for
relabelling Debian's "won't fix" as "you're not affected", the other for using
version ranges no real package matches. Both statements here are the checkable
kind, and the commands are in the document itself.

**Why the backport can't be demonstrated with these tools.** Grype's database does
carry the CVE for nginx 1.25.5, and says where it's fixed:

```
$ grype 'cpe:2.3:a:f5:nginx:1.25.5:*:*:*:*:*:*:*'
NAME   INSTALLED  FIXED IN         VULNERABILITY  SEVERITY
nginx  1.25.5     *1.26.2, 1.27.1  CVE-2024-7347  Medium
```

It doesn't fire when scanning the image because a `.deb` is matched in the Debian
namespace, where bookworm's nginx isn't flagged for it. I tried
`--add-cpes-if-none` and `GRYPE_MATCH_DPKG_USING_CPES=true` to force NVD matching
on our package (no effect, 171 rows either way), and adding a CPE-form product ID
to the VEX statement so the CPE scan above could be suppressed. That last one is
the honest dead end: grype's VEX matcher keys on PURL identity, so it ignores a
CPE-identified product and the finding stays. Getting a 1 → 0 for a backport would
mean picking a CVE the scanners already report, which is the note in
[what I'd do differently](#what-id-do-differently).

**A reason to distrust single-scanner numbers.** Grype reports the same 6 nginx
CVEs for both images, and the only difference is the version string:

```
baseline  nginx 1.25.5-1~bookworm        CVE-2023-44487 CVE-2026-42533 CVE-2009-4487 ...
hardened  nginx 1.25.5-1+echo1~bookworm  CVE-2023-44487 CVE-2026-42533 CVE-2009-4487 ...
```

That identical list is the best proof available that our `.deb` is registered as
well as upstream's: Grype finds it, identifies it, and holds it to the same
advisories. Trivy reports 0 nginx CVEs for upstream and 6 for ours, and those 6
are the same set Grype finds in both, which is the entire "6 new" row in the
results table. So the risk was identical; upstream's copy just went unreported by
one of the two tools. I didn't chase the root cause, most likely a difference in
how Trivy attributes a package from nginx.org's apt repository versus one that
looks Debian-native, so treat it as an observation. The lesson is worth more than
the fix: "0 findings" can mean "nothing is wrong" or "I never looked there", and
the report doesn't distinguish them.

## Residual risk

**Our OpenSSL is only as watchable as the name we gave it.** The registration
works because `Source: openssl` matches the name Debian's security tracker uses. A
scanner keying on something else, or a feed that stops honouring the
source-package convention, would skip us again. Our version string
(`3.0.21-1+echo1~bookworm`) is also one Debian never published, so anything
comparing it against Debian's fixed-in strings is comparing against a version that
doesn't exist upstream. Both scanners handle it correctly today, verified by the
two findings they do raise being exactly the two expected, but "verified today
with these two tools" is the whole claim.

**176 findings / 88 unique CVE IDs remain** (174 / 86 with VEX applied), almost
all in the Debian base layer: glibc, `libsystemd`, `perl-base`, `zlib1g`,
coreutils, where Debian either has no fix or has marked the issue as not warranting
one. Rebuilding those from source is this same technique applied *n* more times;
the real fix is a smaller base, not 40 more custom `.deb`s.

**6 nginx CVEs remain** (Grype's count, Trivy sees 5), including `CVE-2023-44487`
(High, KEV-listed, EPSS 100th percentile) and three 2026 CVEs, one Critical. None
were backported. `CVE-2023-44487` is HTTP/2 rapid reset, handled in practice by
`keepalive_requests` and stream limits, and not reachable in the default config
this image ships because `default.conf` doesn't enable HTTP/2. That's a mitigation
and a non-default-configuration argument, not a fix.

**The master process runs as root**, same as upstream, whose `User` field is also
empty. That's nginx's design: the master binds :80, writes the pid file and spawns
workers, then `user nginx;` drops every worker to uid 101, so the processes parsing
untrusted bytes are unprivileged and the one that stays root never touches the
network. Check 3 of the test asserts uid/gid parity on both images. If the goal
were minimum privilege the fix isn't `USER nginx`, which breaks :80 binding, but
`setcap cap_net_bind_service=+ep /usr/sbin/nginx`. That's a real improvement and a
real parity break: it changes who can `docker exec`, how root-owned bind-mounted
config behaves, and whether a consumer's own `user` directive still applies. It
belongs in a separate variant, not in something advertised as drop-in.

**Nobody owns the OpenSSL updates.** `NGINX_VERSION` and `OPENSSL_VERSION` are
hard-coded in [`build.sh`](build/build.sh) with pinned SHA256s below them. Good for
reproducibility, useless as a maintenance plan: the day 3.0.22 ships, nothing here
notices. Debian's `libssl3` would have been updated by an unattended upgrade, so by
owning the library we also took on watching its CVEs, and that duty is assigned to
nobody. This is the strongest argument against bundling a private OpenSSL at all.
A private build is only defensible with the automation attached, and that isn't
built here.

**Scope not verified.** HTTP/3 is compiled in (`--with-http_v3_module`) but no test
exercises a QUIC path, and `mail`/`stream` are likewise compiled and untested.
Built and tested on arm64 only; nothing is architecture-specific, but "should work"
isn't "tested". And CVE-2024-7347 is verified structurally, by proving the patched
code is in the binary, not by showing a crafted mp4 crashing the old build and not
the new one.

## Compared with Wolfi

Wolfi is the reference implementation of "rebuild the distro so there's less to
report", so I read its
[`openssl.yaml`](https://github.com/wolfi-dev/os/blob/main/openssl.yaml) and
[`nginx-mainline.yaml`](https://github.com/wolfi-dev/os/blob/main/nginx-mainline.yaml)
after finishing, at `openssl 3.6.3-r4` and `nginx-mainline 1.31.3-r2`.

The useful part is where we differ. They track mainline and answer a CVE with the
newest upstream release, which is strictly better when you're allowed to take it,
and is exactly what this assignment forbids. They build to `/usr/bin/nginx` under
`--prefix=/var/lib/nginx` and ship `-config-compat` and `-oci-entrypoint-compat`
subpackages, because they didn't start from drop-in; we match upstream's paths
instead. They split `libcrypto3`/`libssl3` out of `openssl` as subpackages, which
is the same conclusion as our second `.deb` reached independently. Their dynamic
modules are one package per module, which is the shape of the fix for our gap, and
their `cap_net_bind_service` variant is a sibling subpackage that `replaces` the
main one, which is better than a build-time switch.

Their OpenSSL flags overlap ours on `no-comp no-zlib no-async no-idea no-mdc2
no-rc5 no-ssl3 no-seed no-weak-ssl-ciphers`. They also pass `no-ec2m no-sm2
no-sm4`, which we didn't take: each removes API from `libcrypto`, and since we
ship `--with-compat`, a third-party module built against Debian's `libcrypto` is a
supported consumer of ours. That's the same reasoning that stopped our list at
`no-cmp`. Their `enable-ktls` closes no CVE and Debian's `libssl3` doesn't enable
it, so taking it would be a runtime behaviour change against the image we're
replacing.

Two places they're plainly ahead: their build runs OpenSSL's own `make tests`,
which we don't, so our claim is "the CMP code is gone and nginx serves identical
bytes through it" rather than "this libcrypto passes upstream's suite". And their
`epoch:` bumps name the CVE that caused them (`epoch: 4 # CVE-2026-54876`), where
our `+echo1` suffix carries no such information.

## What surprised me

- **`--with-openssl=` does the opposite of what it sounds like.** It reads as
  "point me at an OpenSSL install"; it means "here's OpenSSL source, I'll compile
  and statically link it myself". The first iteration built a 1.3 GB OpenSSL
  image, copied the shared libraries into the final image, and linked none of
  them.
- **A patch applying cleanly proves almost nothing.** `patch` exiting 0 says a
  diff was written to a file. It doesn't say the file was compiled, the module was
  enabled, or the result shipped. Grepping the linked binary for a string that
  only exists in fixed code is two lines and actually proves it.
- **The two scanners disagree about whether upstream nginx is vulnerable at all.**
  Same package, same dpkg database, same advisories, and one of them didn't
  attribute six CVEs. I wouldn't have caught it with a single tool.
- **The regex engine is a compatibility surface.** Upstream depends on PCRE2;
  building against PCRE1 compiles and passes casual testing while swapping the
  engine that evaluates every `location ~` in a user's config.

## What I'd do differently

- Write the layout parity checks first. The `/etc/nginx/conf.d` and `/dev/stdout`
  gaps were both found by the test suite in seconds, after a full working build
  already existed. Round 2 on day one would have shaped the package correctly from
  the start.
- Diff `nginx -V` against the upstream image before choosing configure flags
  rather than after. That's how I found `--with-http_v3_module` and Debian's
  `-Wl,-z,relro -Wl,-z,now -fstack-protector-strong -D_FORTIFY_SOURCE=2` missing,
  in a "hardened" image that had dropped upstream's hardening flags.
- Pick the backport target from what the scanners actually report, so the VEX step
  has something to show. Choosing on patch quality gave a clean fix and a 0 → 0
  demo.

## What I'd do next

1. **Build the four dynamic modules as separate, not-installed-by-default
   `.deb`s**, closing the [parity gap](#known-gap-dynamic-modules) without forcing
   148 CVEs of codec libraries onto installs that don't want them. `--with-compat`
   is already set; the work is four control files, a second `--with-debug` pass for
   upstream's `*-debug.so` variants, and four build dependencies. ~3 hours, and
   the highest-value item here.
2. **An ownership story for the bundled OpenSSL**: a release watcher on the
   OpenSSL tag feed, a scheduled `make` in CI, and the bump arriving as a
   reviewable pull request. A private OpenSSL without this is a liability rather
   than a hardening measure.
3. Backport one of the flagged nginx CVEs, most likely `CVE-2026-56434`, so the
   VEX document shows a real 1 → 0 for a backport and not only for OpenSSL.
4. Run OpenSSL's own `make tests` in `build_openssl`. Cheap, and it closes the
   gap between "nginx behaves the same through this libcrypto" and "this libcrypto
   is correct".
5. Add a QUIC/HTTP-3 round and a TLS round to the test suite, since both are
   compiled in and neither is covered.
6. **Emit an SBOM** (`docker buildx build --sbom=true`, or `syft`) and ship it with
   the image. Worth doing now that the package split made it truthful: a
   Trivy-generated SPDX document lists all 91 installed packages including
   `nginx-openssl`, where before the split it would have omitted our OpenSSL for
   the same reason the scanners did. An SBOM is only as complete as the dpkg
   metadata under it.
7. Pin the vendored `image/docker-entrypoint*` scripts to the `nginx/docker-nginx`
   tag they came from, with a checksum and a check that fails when a newer tag
   appears. Right now nothing tells us when our copies go stale.
8. A `nginx-hardened-rootless` variant using `cap_net_bind_service` plus
   `USER nginx`, offered alongside rather than instead of this image.
9. Reproducible builds: `SOURCE_DATE_EPOCH` and `-ffile-prefix-map` so two runs
   produce identical bytes.

## AI tools

Claude Code, used throughout, and worth being specific about because it both
helped and hurt.

**Where it helped.** Locating the upstream patch for CVE-2024-7347 and confirming
which releases carried the fix. Writing the packaging boilerplate (`control`,
`conffiles`, `md5sums`, `postinst`), which is fiddly, well-documented and dull.
Generating the request matrix for the test, including cases I wouldn't have
thought of unprompted: bare-LF terminators, TLS bytes on a plaintext port,
absolute-form URIs. Diffing the two images' `nginx -V`, `docker inspect` and
`/etc/nginx` listings to find the layout gaps.

**Where it hurt.** An earlier session produced a `WHAT_WE_DID.md` with a
verification transcript in it:

```
$ docker run --rm nginx-hardened:1.25 ldd /usr/sbin/nginx | grep ssl
libssl.so.3 => /usr/local/lib/libssl.so.3.0.21
```

That command had never been run, and with `--with-openssl=` it cannot produce that
output, because the binary was statically linked. The same document claimed "~15
OpenSSL CVEs fixed" and a plan promised four CVEs when two were built. The
generated *code* was fine; the generated *evidence* was fabricated, and it was the
most confident-sounding part of the writeup.

The fix was structural rather than better prompting. Every claim in this README is
produced by a command in the `Makefile` that anyone can re-run, `build.sh` fails
the build if a remediation isn't detectable in the artifact, and the test suite
asserts the drop-in claim instead of asserting it in prose. If a number here is
wrong, the command next to it will say so.

## Layout

```
build/
  build.sh                    fetch, patch, compile, package  (the whole build)
  Dockerfile                  clean debian:bookworm-slim build environment
  patches/CVE-2024-7347.patch backport, named for the CVE it fixes
  keys/                       vendored upstream signing keys; fingerprints are
                              pinned in build.sh
packaging/
  postinst                    service account + runtime dirs
  conf/, html/                config and default pages shipped in the .deb
image/
  docker-entrypoint.sh        upstream entrypoint and hook scripts, verbatim
  docker-entrypoint.d/
Containerfile                 installs the .deb into debian:bookworm-slim
test/compat_test.py           differential test  (make test)
vex/                          OpenVEX document  (make vex)
scan/                         rescan output + fixed-cves.txt  (make scan)
baseline-trivy.txt            saved baseline scans of nginx:1.25-bookworm
baseline-grype.txt
docs/triage-notes.md          CVE triage working notes
docs/build-issues.md          build failures hit along the way
dist/                         the built .deb  (generated)
```

The vendored files under `packaging/conf`, `packaging/html` and `image/` are copied
from `nginx:1.25-bookworm` so the drop-in claim is exact. They're configuration and
shell scripts; no compiled binary is reused from the upstream image or from apt.
