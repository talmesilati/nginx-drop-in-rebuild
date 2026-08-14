#!/usr/bin/env bash
#
# Builds nginx and its OpenSSL from upstream source into two .debs.
# Runs inside a clean debian:bookworm-slim (see build/Dockerfile); nothing here
# installs a pre-built nginx.
#
set -euo pipefail

NGINX_VERSION="${NGINX_VERSION:-1.25.5}"
OPENSSL_VERSION="${OPENSSL_VERSION:-3.0.21}"
# Upstream version stays 1.25.5 so scanners still match it; that is what the VEX
# document exists to answer. The +echo1 suffix marks this as our rebuild.
PKG_RELEASE="${PKG_RELEASE:-1+echo1~bookworm}"

NGINX_SHA256="2fe2294f8af4144e7e842eaea884182a84ee7970e11046ba98194400902bbec0"
OPENSSL_SHA256="617e29af8e421f46649484a4937e48c685e47f46488167c982f88bc4ec1d522f"

REPO="${REPO:-/work}"
OUT="${OUT:-/out}"
SRC="/usr/src"
PKGROOT="/tmp/pkgroot"
SSL_PREFIX="/usr/lib/nginx/openssl"
ARCH="$(dpkg --print-architecture)"
DEB_VERSION="${NGINX_VERSION}-${PKG_RELEASE}"

# The private OpenSSL is a separate package, not files bundled inside the nginx
# one. Only dpkg-registered packages appear in /var/lib/dpkg/status, which is all
# Trivy and Grype read; bundling the libraries fixed 36 CVEs and removed the
# scanners' ability to see the library at all.
SSLPKGROOT="/tmp/pkgroot-openssl"
SSL_PKG_NAME="nginx-openssl"
SSL_DEB_VERSION="${OPENSSL_VERSION}-${PKG_RELEASE}"

# Keys are vendored in build/keys/ rather than fetched from a keyserver, so
# changing who we trust is a diff rather than a network call. Fingerprints are
# pinned here separately from the key files, so swapping a key file without
# updating this list fails the build.
GNUPGHOME="/tmp/gnupg"; export GNUPGHOME
KEYRINGS="/tmp/keyrings"
NGINX_KEY_FPR="43387825DDB1BB97EC36BA5D007C8D7C15D87369"   # Roman Arutyunyan, signed 1.25.5
OPENSSL_KEY_FPR="BA5473A2B0587B07FB27CF2D216094DFD0CB81EF" # OpenSSL release key

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

keyring() {
  local name="$1" asc="$2" fpr="$3"
  local src="${REPO}/build/keys/${asc}"
  local ring="${KEYRINGS}/${name}.gpg"

  gpg --batch --quiet --no-default-keyring \
      --keyring "${KEYRINGS}/${name}.import" --import "${src}"
  # Export only the pinned fingerprint: openssl.asc carries five keys, and
  # without this a signature from any of them would pass.
  gpg --batch --quiet --no-default-keyring \
      --keyring "${KEYRINGS}/${name}.import" --export "${fpr}" > "${ring}"

  # --export of an absent key exits 0 and writes nothing.
  if [ ! -s "${ring}" ]; then
    echo "FAIL: ${asc} does not contain the pinned key ${fpr}" >&2
    exit 1
  fi
  echo "trusting ${name}: ${fpr}"
}

import_keys() {
  log "build trusted keyrings from vendored keys"
  install -d -m 700 "${GNUPGHOME}" "${KEYRINGS}"
  keyring nginx   nginx-arut.asc "${NGINX_KEY_FPR}"
  keyring openssl openssl.asc    "${OPENSSL_KEY_FPR}"
}

# Two checks, two questions: sha256 asks whether these are the bytes this repo
# was written against, gpgv asks whether upstream ever released them. A pinned
# hash of a tampered tarball is still a matching hash.
fetch() {
  local url="$1" dest="$2" want="$3" keyring="$4"
  log "fetch $url"
  curl -fsSL --retry 3 -o "$dest" "$url"
  echo "${want}  ${dest}" | sha256sum -c -

  curl -fsSL --retry 3 -o "${dest}.asc" "${url}.asc"
  gpgv --keyring "${KEYRINGS}/${keyring}.gpg" "${dest}.asc" "${dest}"
}

# ---------------------------------------------------------------- OpenSSL bump
build_openssl() {
  fetch "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
        "${SRC}/openssl.tar.gz" "${OPENSSL_SHA256}" openssl
  tar -xzf "${SRC}/openssl.tar.gz" -C "${SRC}"
  cd "${SRC}/openssl-${OPENSSL_VERSION}"

  log "configure OpenSSL ${OPENSSL_VERSION} (shared, prefix ${SSL_PREFIX})"
  # The hardening flags are Debian's own, taken from upstream nginx's `nginx -V`
  # and reused verbatim, so both halves of the build are hardened to one standard
  # rather than two. An earlier version hardened nginx and left OpenSSL stock,
  # which is backwards: OpenSSL parses the attacker-controlled handshake.
  #
  # The no-* list is attack surface nginx cannot reach: TLS compression (CRIME),
  # SSLv3, legacy ciphers absent from the ssl_ciphers we ship, and OpenSSL's
  # async engine, which nginx never calls because it has its own event loop.
  #
  # no-cmp is the only flag chosen from our own scan output. CVE-2026-42767 is a
  # NULL deref in CRMF decryption reachable only by a CMP client; Debian marks it
  # won't-fix, so it is still open in 3.0.21 and reported against our package.
  # nginx has no CMP surface, so the code can be removed rather than declared
  # unreachable. There is no no-crmf -- 3.0.21 rejects it, because CMP is CRMF's
  # only consumer and no-cmp drops crypto/crmf too.
  #
  # We stopped there rather than also disabling cms/ts/ct, which nginx also never
  # calls: every disabled feature diverges from Debian's libcrypto, and
  # --with-compat lets third-party modules link this same library, so a module
  # using one of those APIs would fail to load. Those three close no finding.
  #
  # Deliberately still enabled: no-deprecated breaks the build (nginx 1.25 calls
  # deprecated APIs), no-engine would break the ssl_engine directive a consumer's
  # config may use, and no-dtls touches the area QUIC compatibility relies on.
  ./config shared \
      --prefix="${SSL_PREFIX}" \
      --openssldir="${SSL_PREFIX}/ssl" \
      --libdir=lib \
      enable-tls1_3 \
      no-comp no-zlib no-zlib-dynamic \
      no-weak-ssl-ciphers no-ssl3 no-ssl3-method \
      no-idea no-rc2 no-rc5 no-md2 no-mdc2 no-seed \
      no-async no-cmp \
      -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
      -Wl,-z,relro -Wl,-z,now

  make -j"$(nproc)"
  make install_sw          # _sw: skip manpages, which the package does not ship
  "${SSL_PREFIX}/bin/openssl" version

  # The VEX statement for CVE-2026-42767 claims this code is absent, so check it
  # instead of trusting that Configure accepted the flag.
  log "verify no-cmp removed the vulnerable CMP/CRMF code"
  local hits
  hits="$(grep -ac 'OSSL_CRMF\|OSSL_CMP' "${SSL_PREFIX}/lib/libcrypto.so.3" || true)"
  if [ "${hits}" != "0" ]; then
    echo "FAIL: CMP/CRMF symbols still present in libcrypto (${hits} match(es))" >&2
    echo "the VEX statement for CVE-2026-42767 would be unsubstantiated" >&2
    exit 1
  fi
  echo "OK: no CMP/CRMF symbols in libcrypto.so.3"
}

# ------------------------------------------------------- nginx source + patches
fetch_nginx() {
  fetch "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" \
        "${SRC}/nginx.tar.gz" "${NGINX_SHA256}" nginx
  tar -xzf "${SRC}/nginx.tar.gz" -C "${SRC}"
}

apply_patches() {
  cd "${SRC}/nginx-${NGINX_VERSION}"
  shopt -s nullglob
  local applied=0
  for p in "${REPO}"/build/patches/*.patch; do
    log "apply backport $(basename "$p")"
    patch -p1 --batch --forward < "$p"
    applied=$((applied + 1))
  done
  if [ "${applied}" -eq 0 ]; then
    echo "refusing to build: no patches found in ${REPO}/build/patches" >&2
    exit 1
  fi
  # patch(1) exiting 0 only means a diff was written. This string exists only in
  # the fixed code.
  log "verify patch landed in source"
  grep -n 'unordered mp4 stsc chunks' src/http/modules/ngx_http_mp4_module.c
}

# --------------------------------------------------------------- compile nginx
build_nginx() {
  cd "${SRC}/nginx-${NGINX_VERSION}"
  log "configure nginx ${NGINX_VERSION}"
  # Mirrors `nginx -V` from nginx:1.25-bookworm, keeping Debian's hardening flags,
  # with our private OpenSSL substituted for libssl3. Note there is no
  # --with-openssl: that flag statically links OpenSSL and would make the shared
  # build above dead weight.
  ./configure \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --modules-path=/usr/lib/nginx/modules \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid \
    --lock-path=/var/run/nginx.lock \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
    --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
    --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
    --user=nginx \
    --group=nginx \
    --with-compat \
    --with-file-aio \
    --with-threads \
    --with-http_addition_module \
    --with-http_auth_request_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_mp4_module \
    --with-http_random_index_module \
    --with-http_realip_module \
    --with-http_secure_link_module \
    --with-http_slice_module \
    --with-http_ssl_module \
    --with-http_stub_status_module \
    --with-http_sub_module \
    --with-http_v2_module \
    --with-http_v3_module \
    --with-mail \
    --with-mail_ssl_module \
    --with-stream \
    --with-stream_realip_module \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-cc-opt="-g -O2 -fstack-protector-strong -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2 -I${SSL_PREFIX}/include" \
    --with-ld-opt="-Wl,-z,relro -Wl,-z,now -L${SSL_PREFIX}/lib -Wl,-rpath,${SSL_PREFIX}/lib"

  make -j"$(nproc)"
}

# ------------------------------------------------------------ stage filesystem
stage() {
  log "stage package filesystem"
  rm -rf "${PKGROOT}"
  cd "${SRC}/nginx-${NGINX_VERSION}"
  make install DESTDIR="${PKGROOT}"

  # `make install` ships upstream's sample configs; the Debian package does not,
  # and /etc/nginx has to match it exactly.
  rm -f "${PKGROOT}"/etc/nginx/*.default \
        "${PKGROOT}"/etc/nginx/koi-utf \
        "${PKGROOT}"/etc/nginx/koi-win \
        "${PKGROOT}"/etc/nginx/win-utf \
        "${PKGROOT}"/etc/nginx/fastcgi.conf
  rm -rf "${PKGROOT}"/etc/nginx/html

  install -d "${PKGROOT}/etc/nginx/conf.d" \
             "${PKGROOT}/usr/lib/nginx/modules" \
             "${PKGROOT}/usr/share/nginx" \
             "${PKGROOT}/usr/share/nginx/html" \
             "${PKGROOT}/var/log/nginx" \
             "${PKGROOT}/var/cache/nginx"

  ln -sfn /usr/lib/nginx/modules "${PKGROOT}/etc/nginx/modules"

  install -m 0644 "${REPO}/packaging/conf/nginx.conf"          "${PKGROOT}/etc/nginx/nginx.conf"
  install -m 0644 "${REPO}/packaging/conf/mime.types"          "${PKGROOT}/etc/nginx/mime.types"
  install -m 0644 "${REPO}/packaging/conf/fastcgi_params"      "${PKGROOT}/etc/nginx/fastcgi_params"
  install -m 0644 "${REPO}/packaging/conf/scgi_params"         "${PKGROOT}/etc/nginx/scgi_params"
  install -m 0644 "${REPO}/packaging/conf/uwsgi_params"        "${PKGROOT}/etc/nginx/uwsgi_params"
  install -m 0644 "${REPO}/packaging/conf/conf.d/default.conf" "${PKGROOT}/etc/nginx/conf.d/default.conf"
  install -m 0644 "${REPO}/packaging/html/index.html"          "${PKGROOT}/usr/share/nginx/html/index.html"
  install -m 0644 "${REPO}/packaging/html/50x.html"            "${PKGROOT}/usr/share/nginx/html/50x.html"

  strip --strip-unneeded "${PKGROOT}/usr/sbin/nginx"
}

# Runtime bits only: no headers, no static archives, and no openssl(1), which
# would be a confusing duplicate of Debian's.
stage_openssl() {
  log "stage ${SSL_PKG_NAME} package filesystem"
  rm -rf "${SSLPKGROOT}"
  install -d "${SSLPKGROOT}${SSL_PREFIX}/lib"
  cp -a "${SSL_PREFIX}/lib/libssl.so"*    "${SSLPKGROOT}${SSL_PREFIX}/lib/"
  cp -a "${SSL_PREFIX}/lib/libcrypto.so"* "${SSLPKGROOT}${SSL_PREFIX}/lib/"
  cp -a "${SSL_PREFIX}/lib/engines-3"     "${SSLPKGROOT}${SSL_PREFIX}/lib/" 2>/dev/null || true
  install -d "${SSLPKGROOT}${SSL_PREFIX}/ssl"
  cp -a "${SSL_PREFIX}/ssl/openssl.cnf"   "${SSLPKGROOT}${SSL_PREFIX}/ssl/" 2>/dev/null || true
  rm -f "${SSLPKGROOT}${SSL_PREFIX}/lib"/*.a
  find "${SSLPKGROOT}${SSL_PREFIX}/lib" -name '*.so*' -type f -exec strip --strip-unneeded {} +

  # The soname symlinks have to survive into the package, or the loader finds
  # nothing at runtime despite the files being there.
  ls -l "${SSLPKGROOT}${SSL_PREFIX}/lib"
}

# ----------------------------------------------------------- package metadata
control() {
  log "write control metadata"
  local debian="${PKGROOT}/DEBIAN"
  install -d "${debian}"

  local size
  size="$(du -sk --exclude=DEBIAN "${PKGROOT}" | cut -f1)"

  cat > "${debian}/control" <<EOF
Package: nginx
Version: ${DEB_VERSION}
Architecture: ${ARCH}
Maintainer: Tal Mesilati <talmayam@gmail.com>
Installed-Size: ${size}
Section: httpd
Priority: optional
Depends: libc6 (>= 2.34), libcrypt1 (>= 1:4.1.0), libpcre2-8-0 (>= 10.22), zlib1g (>= 1:1.1.4), ${SSL_PKG_NAME} (= ${SSL_DEB_VERSION})
Provides: httpd, nginx-r${NGINX_VERSION}
Replaces: nginx-common, nginx-core
Conflicts: nginx-common, nginx-core
Homepage: https://nginx.org
Description: high performance web server (source rebuild, CVE-2024-7347 patched)
 nginx [engine x] is an HTTP and reverse proxy server, as well as
 a mail proxy server.
 .
 Rebuilt from upstream source with a backport of the ngx_http_mp4_module
 fix for CVE-2024-7347 and linked against OpenSSL ${OPENSSL_VERSION}
 instead of the distribution libssl3.
EOF

  # Listed as conffiles so dpkg preserves a user's edits across upgrade.
  cat > "${debian}/conffiles" <<'EOF'
/etc/nginx/nginx.conf
/etc/nginx/mime.types
/etc/nginx/fastcgi_params
/etc/nginx/scgi_params
/etc/nginx/uwsgi_params
/etc/nginx/conf.d/default.conf
EOF

  install -m 0755 "${REPO}/packaging/postinst" "${debian}/postinst"

  ( cd "${PKGROOT}" && find . -type f -not -path './DEBIAN/*' -printf '%P\0' \
      | xargs -0 md5sum > DEBIAN/md5sums )
}

control_openssl() {
  log "write ${SSL_PKG_NAME} control metadata"
  local debian="${SSLPKGROOT}/DEBIAN"
  install -d "${debian}"

  local size
  size="$(du -sk --exclude=DEBIAN "${SSLPKGROOT}" | cut -f1)"

  # `Source: openssl` is load-bearing: Debian-family scanners map a binary
  # package to advisories through its source package name, so this is what makes
  # our 3.0.21 comparable against the openssl feed instead of an unrecognised
  # package they skip.
  cat > "${debian}/control" <<EOF
Package: ${SSL_PKG_NAME}
Source: openssl
Version: ${SSL_DEB_VERSION}
Architecture: ${ARCH}
Maintainer: Tal Mesilati <talmayam@gmail.com>
Installed-Size: ${size}
Section: libs
Priority: optional
Depends: libc6 (>= 2.34)
Homepage: https://www.openssl.org/
Description: OpenSSL ${OPENSSL_VERSION} runtime libraries for nginx
 libssl and libcrypto built from upstream OpenSSL ${OPENSSL_VERSION} source and
 installed under ${SSL_PREFIX}, where the nginx package resolves them via an
 -rpath baked in at link time.
 .
 Deliberately a separate package rather than files inside the nginx package:
 only dpkg-registered packages appear in /var/lib/dpkg/status, which is the
 only thing vulnerability scanners read. Bundling the libraries hid them from
 Trivy and Grype entirely; this makes the version bump auditable.
 .
 Does not replace the distribution libssl3 and does not appear on the default
 library search path -- nothing outside nginx links against it.
EOF

  # No maintainer script: nginx resolves these through its compiled-in -rpath,
  # not the ld.so cache, so there is nothing for an ldconfig hook to do.
  ( cd "${SSLPKGROOT}" && find . -type f -not -path './DEBIAN/*' -printf '%P\0' \
      | xargs -0 md5sum > DEBIAN/md5sums )
}

build_deb() {
  local root="$1" name="$2" version="$3"
  local deb="${OUT}/${name}_${version}_${ARCH}.deb"
  dpkg-deb --root-owner-group --build "${root}" "${deb}"
  dpkg-deb --info "${deb}"
  echo "${deb}"
}

package() {
  log "build .debs"
  install -d "${OUT}"
  build_deb "${SSLPKGROOT}" "${SSL_PKG_NAME}" "${SSL_DEB_VERSION}"
  build_deb "${PKGROOT}"    "nginx"           "${DEB_VERSION}"
}

# ------------------------------------------------------------------- evidence
# Asserts the remediation is in the artifact, rather than trusting that patch(1)
# and configure exited 0.
evidence() {
  local nginx="$1"
  log "build evidence for ${nginx}"

  echo "--- nginx -V ---"
  "${nginx}" -V 2>&1 || true

  echo "--- CVE-2024-7347 backport present in compiled binary ---"
  if grep -aq 'unordered mp4 stsc chunks' "${nginx}"; then
    echo "OK: patched log string found in ${nginx}"
  else
    echo "FAIL: patched string missing from ${nginx}" >&2
    echo "diagnostics:" >&2
    grep -ac 'mp4 stsc' "${nginx}" >&2 || true
    grep -ao 'stsc[ -~]\{0,40\}' "${nginx}" | sort -u | head >&2 || true
    exit 1
  fi

  echo "--- OpenSSL linkage (version bump) ---"
  ldd "${nginx}" | grep -E 'libssl|libcrypto' || true
}

main() {
  import_keys
  build_openssl
  fetch_nginx
  apply_patches
  build_nginx
  evidence "${SRC}/nginx-${NGINX_VERSION}/objs/nginx"   # before staging strips it
  stage
  stage_openssl
  evidence "${PKGROOT}/usr/sbin/nginx"
  control
  control_openssl
  package
  log "done: nginx ${DEB_VERSION} + ${SSL_PKG_NAME} ${SSL_DEB_VERSION} (${ARCH})"
}

main "$@"
