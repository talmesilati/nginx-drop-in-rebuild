# Build environment for the .debs. The only nginx in here is the one build.sh
# compiles from the upstream tarball; no nginx package is ever installed.
#
# Build context is the repo root:  docker build -f build/Dockerfile .
#
# Pinned by digest, because pinning the nginx and OpenSSL tarballs by SHA256 two
# files away while leaving the base on a mutable tag fixes some inputs and not
# others -- and a base image contributing ~88 packages is an input. The default
# below keeps a bare `docker build` working; the Makefile overrides it.
ARG DEBIAN_BASE=debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
FROM ${DEBIAN_BASE}

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        dpkg-dev \
        gnupg \
        libpcre2-dev \
        patch \
        perl \
        zlib1g-dev; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY build/build.sh   /work/build/build.sh
COPY build/keys       /work/build/keys
COPY build/patches    /work/build/patches
COPY packaging        /work/packaging

ARG NGINX_VERSION=1.25.5
ARG OPENSSL_VERSION=3.0.21
ARG PKG_RELEASE=1+echo1~bookworm

RUN chmod +x /work/build/build.sh \
 && REPO=/work OUT=/out /work/build/build.sh
