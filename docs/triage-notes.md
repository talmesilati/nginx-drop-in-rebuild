# CVE triage — nginx:1.25-bookworm

Working notes behind the two CVEs I chose. Every number comes from
`baseline-trivy.txt` / `baseline-grype.txt`, which are committed so the counts can
be re-derived.

## The baseline

`nginx:1.25-bookworm` is nginx 1.25.5 on Debian 12.

| | Trivy | Grype |
|---|---|---|
| findings | 615 | 613 |
| unique CVE IDs | 392 | 396 |

Trivy's severity split: 21 Critical, 124 High, 241 Medium, 213 Low, 16 Unknown.
Findings outnumber unique CVEs because one CVE is reported per affected package;
Grype lists OpenSSL issues twice, under the source package `openssl` and the binary
package `libssl3`.

## Where the vulnerabilities live

Findings per package, Grype baseline, top of the list:

```
 38  openssl        \ same 38 CVE IDs, reported twice
 38  libssl3        /
 35  curl           \ same set, source + binary
 35  libcurl4       /
 31  libexpat1
 29  libtiff6
 25  libheif1
 22  libxml2
 22  libgnutls30
 22  libc6 / libc-bin
 20  perl-base
```

Two things follow from this list:

1. **Almost nothing is in nginx.** Grype attributes 6 CVEs to the `nginx` package.
   The other ~390 are in the Debian base layer, including a lot that nothing in the
   image ever calls — `libtiff6`, `libheif1` and `perl-base` are transitive
   dependencies, not features anyone is using.
2. **OpenSSL is the biggest single lever**, and unlike `libtiff6` it's genuinely
   reachable: every TLS byte nginx handles goes through it.

## Chosen: OpenSSL, by version bump

- **Lives in:** `libssl3` / `openssl` 3.0.11-1~deb12u2, loaded by
  `/usr/sbin/nginx` at runtime.
- **38 unique CVE IDs:** 4 Critical, 16 High, 16 Medium, 1 Low, 1 Negligible. The
  Criticals are CVE-2025-15467, CVE-2024-5535, CVE-2026-31789, CVE-2026-34182.
- **Upstream fix:** all of them were fixed in some 3.0.x release. Grype's FIXED-IN
  column spans `3.0.13-1~deb12u1` … `3.0.20-1~deb12u2`, so 3.0.20 is the highest
  version any of them needs.
- **Method:** ship upstream 3.0.21, later than every fixed-in version above, so one
  change covers all 36 fixable IDs.
- **Two exceptions no version fixes:** `CVE-2025-27587` (Negligible, no fix in any
  release) and `CVE-2026-42767` (Medium, Debian won't-fix). Both appear in our own
  scan because `nginx-openssl` is a registered package. Neither applies, for
  different reasons, so they need different instruments:
  - `CVE-2026-42767` is in OpenSSL's CMP/CRMF client code. nginx has no CMP
    surface, so the build passes `no-cmp` and the code isn't in `libcrypto.so.3` at
    all. That turns the VEX statement from an argument about reachability into a
    fact about the artifact. I deliberately did not extend this to `no-cms`,
    `no-ts` or `no-ct`, which nginx also never calls: every disabled feature is a
    divergence from Debian's libcrypto that a third-party dynamic module could hit,
    and those three cost us no findings.
  - `CVE-2025-27587` is scoped to PowerPC, so on arm64/amd64 the affected
    implementation was never compiled. Nothing to remove; the VEX statement rests
    on the package's `Architecture` field.

### What `apt-get upgrade` would have achieved

Worth being exact, because the easy version of this sentence is wrong. Debian does
ship a fixed OpenSSL:

```
$ docker run --rm debian:bookworm-slim sh -c 'apt-get update -qq; apt-cache policy libssl3'
libssl3:
  Candidate: 3.0.20-1~deb12u2        bookworm/main + bookworm-security
```

The baseline carries 3.0.11-1~deb12u2, so `apt-get upgrade` would move it to 3.0.20
and close the same 36 IDs this source build closes. Measured on this CVE set,
compiling 3.0.21 buys nothing over one `apt-get upgrade`.

So the case for compiling isn't "no fix exists". It's:

1. **The brief requires it.** The deliverable is a `.deb` built from upstream source
   with a version bump demonstrated. `apt-get upgrade` is a configuration change,
   not a build.
2. **Release latency.** Debian's backport lands when Debian decides. Owning the
   build means the next OpenSSL release can ship the day it's published. That's
   about *future* CVEs, not these 38, and it's the durable argument.
3. **It exercises the harder path.** Substituting a core dependency at link time is
   where the real failure modes are — silent static linking, ABI assumptions,
   `-rpath` resolution — and none of them appear if apt does it for you.

The cost is that we now own OpenSSL updates forever, which the README states as
residual risk. If this were production rather than an exercise, `apt-get upgrade` to
3.0.20 would be the right call for these 38 CVEs, and the compile would be reserved
for what Debian hasn't covered.

### Why the bump has to be a compile, not a file swap

nginx links OpenSSL at build time. Dropping a newer `libssl.so.3` next to it would
work only by luck of ABI compatibility; the supported approach is to compile nginx
against the headers of the version you intend to run. So the bump and the nginx
build are one operation, which is why `build.sh` builds OpenSSL first.

## Chosen: CVE-2024-7347, by backport

- **Lives in:** `/usr/sbin/nginx`, `ngx_http_mp4_module.c`, function
  `ngx_http_mp4_crop_stsc_data`.
- **Issue:** a crafted mp4 file makes the module read past the end of a buffer.
  Reachable only where `mp4;` is enabled in a location block. Not in the default
  config, but the module is compiled in and upstream compiles it in too, so I kept
  parity and fixed it instead of dropping it.
- **Upstream fix:** nginx 1.27.1 (mainline) and 1.26.2 (stable), published
  standalone as `patch.2024.mp4.txt`.
- **There is no fixed 1.25.x.** Upstream never released a 1.25.6, and the drop-in
  requirement pins 1.25.5, so the only option is to patch source and recompile.
- **Method:** `build/patches/CVE-2024-7347.patch`, two changes — widen a 32-bit
  multiplication to 64-bit, and reject `stsc` atoms whose chunk entries aren't in
  ascending order.
- **Note on scanners:** neither Trivy nor Grype reports this CVE against the nginx
  package in the first place, so its absence afterwards proves nothing. That's why
  the VEX section of the README is shaped the way it is.

## Considered and rejected

| Candidate | Method it would need | Why not |
|---|---|---|
| `curl` / `libcurl4` (35 findings) | version bump | Debian ships a fixed package, and unlike OpenSSL curl is not linked by nginx and not called at runtime, so a source build would demonstrate the technique against a dependency that can't affect the running service. Removing it is the honest action, and the brief excludes removals |
| `libexpat1` (31) | version bump | Same: fixed in Debian, not on any nginx code path in the default build |
| `libtiff6`, `libheif1` (54 combined) | removal | Not reachable from nginx at all. Removing them is the correct real-world action but excluded from the requirement |
| `CVE-2023-44487` (nginx, High, KEV, EPSS 100th pct) | backport | The highest-risk nginx finding and my first pick. Dropped because HTTP/2 rapid reset is an architectural rate-limit problem, addressed upstream through `keepalive_requests` and stream-concurrency handling rather than one reviewable patch against 1.25.5. Still present; documented as residual risk |
| `CVE-2026-42533` (nginx, Critical), `CVE-2026-60005`, `CVE-2026-56434` | backport | Good targets, and reported by both scanners, so a VEX would visibly go 1 → 0. Rejected on time: locating and validating the upstream commits was more research than remained. Top follow-up in the README |
| `CVE-2009-4487`, `CVE-2013-0337` (nginx, Low/Negligible) | none | Config and log-escaping issues, will-not-fix upstream |

## Decision

| CVE(s) | Component | Method | Rationale |
|---|---|---|---|
| 38 OpenSSL IDs, 4 Critical | `libssl3` → our `libssl.so.3` | **version bump** to 3.0.21 | Largest reachable attack surface; one change, many CVEs. Debian's 3.0.20 would close the same 36 — we compile because the brief requires a source build and because owning it decouples us from Debian's backport latency for the next CVE |
| CVE-2024-7347 | `ngx_http_mp4_module` | **backport** from 1.27.1 | The only nginx CVE with a clean reviewable upstream patch and no fixed 1.25.x release, which is the scenario the assignment describes |

Two techniques, both required by the brief, and neither is a removal.
