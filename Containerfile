# Final image: installs the .debs built by build/ into a minimal Debian base.
#
# Everything below exists to match nginx:1.25-bookworm's runtime contract --
# same layout, user, ports, entrypoint, log destinations. `make test` checks that
# claim rather than trusting it.
#
# Digest-pinned because a mutable base tag would let the contents of a
# "hardened" image change with no commit in this repo. The Makefile overrides it
# so this file and build/Dockerfile track one value.
ARG DEBIAN_BASE=debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
FROM ${DEBIAN_BASE}

LABEL maintainer="NGINX Docker Maintainers <docker-maint@nginx.com>"

ENV NGINX_VERSION=1.25.5
ENV NJS_VERSION=0.8.4
ENV NJS_RELEASE=3~bookworm
# Differs from upstream's 1~bookworm on purpose: this is our rebuild.
ENV PKG_RELEASE=1+echo1~bookworm

COPY dist/*.deb /tmp/

# Asserted below, because a glob install takes whatever happens to be in dist/:
# without this, a stale .deb from an earlier build lands in the image and its
# contents depend on uncleaned state rather than on this file.
ARG EXPECTED_DEBS=2

RUN set -eux; \
    found="$(ls -1 /tmp/*.deb | wc -l)"; \
    if [ "$found" -ne "$EXPECTED_DEBS" ]; then \
      echo "expected $EXPECTED_DEBS .deb(s) in dist/, found $found:" >&2; \
      ls -l /tmp/*.deb >&2; \
      echo "run 'make clean' and rebuild -- refusing to install an unknown package set" >&2; \
      exit 1; \
    fi; \
    apt-get update; \
# envsubst, required by /docker-entrypoint.d/20-envsubst-on-templates.sh
    apt-get install -y --no-install-recommends gettext-base; \
# both .debs on one command line, so apt resolves nginx's dependency on
# nginx-openssl locally instead of looking for it in a repository
    apt-get install -y --no-install-recommends /tmp/*.deb; \
    rm -rf /var/lib/apt/lists/* /tmp/*.deb; \
    dpkg -s nginx | head -4; \
    dpkg -s nginx-openssl | head -4; \
# forward request and error logs to the container log collector
    ln -sf /dev/stdout /var/log/nginx/access.log; \
    ln -sf /dev/stderr /var/log/nginx/error.log

COPY image/docker-entrypoint.sh   /docker-entrypoint.sh
COPY image/docker-entrypoint.d    /docker-entrypoint.d

RUN chmod +x /docker-entrypoint.sh /docker-entrypoint.d/*.sh

EXPOSE 80

STOPSIGNAL SIGQUIT

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["nginx", "-g", "daemon off;"]
