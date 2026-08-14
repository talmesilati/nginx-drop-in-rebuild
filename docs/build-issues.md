# Build failures hit along the way

Kept because the brief asks what I tried when I hit a wall. Roughly in the order
they happened.

## `--with-openssl=` compiles OpenSSL itself

```
./config: not found
make[1]: *** [objs/Makefile:1855: /opt/openssl-3.0.21/.openssl/include/openssl/ssl.h] Error 127
```

The flag reads as "point me at an OpenSSL installation". It means "here is OpenSSL
*source*, I will compile it". Pointing it at a compiled prefix fails like this.

My first fix was to give it what it wanted: copy the source tree in alongside the
compiled libraries and let nginx build OpenSSL during its own build. That worked
and was wrong. nginx statically links the OpenSSL it builds this way, so `ldd
/usr/sbin/nginx` showed no `libssl` at all, the separately compiled shared
libraries in the image were dead weight, and nothing in the image reported the
OpenSSL version we thought we were shipping.

The build now compiles OpenSSL separately and links it as a shared library through
`--with-cc-opt=-I…`, `--with-ld-opt=-L… -Wl,-rpath,…`, with no `--with-openssl` at
all. `ldd` output is asserted as evidence, which is what would have caught the
first version immediately.

## `lib64` vs `lib`

```
ERROR: "/opt/openssl-3.0.21/lib64": not found
```

OpenSSL's installed library directory is architecture-dependent: `lib64` on
x86_64, `lib` on arm64. The build was written on an arm64 Mac and would have
broken on an amd64 host, or the reverse. Fixed by passing `--libdir=lib` to
OpenSSL's `config` so the path is ours to decide rather than the platform's.

## `/usr/lib/nginx/modules` didn't exist

A from-source install creates no module directory when nothing is built as a
dynamic module, but the upstream package has one and `/etc/nginx/modules` is a
symlink to it. The staging step creates it empty, because the drop-in claim is
about layout as much as behaviour. The empty directory is now also what the test
suite compares against upstream's twelve `.so` files, which is how the module gap
is asserted rather than assumed.

## `no-crmf` is not an OpenSSL option

```
***** Unsupported options: no-crmf
```

When compiling out the code behind CVE-2026-42767 I passed both `no-cmp` and
`no-crmf`. 3.0.21 rejects the second: CRMF isn't separately switchable because CMP
is its only consumer. Rather than guess, I ran `./config no-cmp` in the builder and
checked the generated build plan — zero `crypto/crmf/*.o` objects are scheduled, so
`no-cmp` alone removes both. `build.sh` asserts the result on the shipped
`libcrypto.so.3` instead of trusting the flag.

## Finding the key that signed nginx 1.25.5

`https://nginx.org/keys/` returns 403 for the directory listing, so there's no way
to browse for the right key, and `mdounin.key` — the name I expected — 404s. Rather
than assume which maintainer signed the release, I fetched candidate filenames one
at a time and compared each key's fingerprint against the issuer in
`nginx-1.25.5.tar.gz.asc`. `arut.key` matched
(`43387825DDB1BB97EC36BA5D007C8D7C15D87369`, Roman Arutyunyan), and that's the
fingerprint pinned in `build.sh`.

## `gpg --export` succeeds when the key is absent

Exporting a fingerprint that isn't in the keyring exits 0 and writes nothing. That
would have left an empty keyring and made every later `gpgv` fail with an error
about the keyring rather than about the missing key. `keyring()` checks the file is
non-empty and fails there instead.

## `conf.d` wasn't included

The `.deb` shipped a working `nginx.conf` that didn't `include
/etc/nginx/conf.d/*.conf`. Every stock request passed, so the first round of tests
was green. Round 2 of the test suite bind-mounts a user config into both
containers, and all eight of its scenarios failed at once. This is the failure the
whole differential test exists to catch, and it wouldn't have shown up in manual
checking of the default page.

## The scanner couldn't see the OpenSSL bump

Not a build failure — the build worked — but the same class of problem. The
libraries were being copied into the nginx package's payload, so `dpkg` had no
record of them and both scanners reported nothing about our OpenSSL, in either
direction. Fixed by shipping `nginx-openssl` as a second package with
`Source: openssl`. Written up in the README, since it changed the results table.
