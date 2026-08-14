# nginx:1.25-bookworm drop-in replacement -- build, test, scan.
#
#   make            build the .deb and the image
#   make test       differential compatibility test vs the upstream image
#   make scan       trivy + grype on the new image, diffed against the baseline
#   make vex        re-scan with the VEX document applied
#
SHELL           := /bin/bash
NGINX_VERSION   ?= 1.25.5
OPENSSL_VERSION ?= 3.0.21
PKG_RELEASE     ?= 1+echo1~bookworm
ARCH            ?= $(shell docker version --format '{{.Server.Arch}}')

BASE_IMAGE      ?= nginx:1.25-bookworm
IMAGE           ?= nginx-hardened:$(NGINX_VERSION)
BUILDER_IMAGE   ?= nginx-deb-builder:$(NGINX_VERSION)
DEB             := dist/nginx_$(NGINX_VERSION)-$(PKG_RELEASE)_$(ARCH).deb
SSL_DEB         := dist/nginx-openssl_$(OPENSSL_VERSION)-$(PKG_RELEASE)_$(ARCH).deb

# Pinned by digest rather than the mutable tag, and defined once here so the
# builder and the runtime image cannot drift apart. This is the multi-arch index
# digest, so amd64 and arm64 both still resolve. Refresh deliberately with
# `docker buildx imagetools inspect debian:bookworm-slim`.
DEBIAN_BASE     ?= debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

.PHONY: all deb image test scan vex baseline clean sizes

all: image

# ---------------------------------------------------------------- .deb from source
deb: $(DEB)

$(DEB): build/build.sh build/Dockerfile $(wildcard build/patches/*.patch) \
        $(wildcard build/keys/*.asc) $(shell find packaging -type f)
	docker build \
	  --build-arg DEBIAN_BASE=$(DEBIAN_BASE) \
	  --build-arg NGINX_VERSION=$(NGINX_VERSION) \
	  --build-arg OPENSSL_VERSION=$(OPENSSL_VERSION) \
	  --build-arg PKG_RELEASE=$(PKG_RELEASE) \
	  -f build/Dockerfile -t $(BUILDER_IMAGE) .
	rm -rf dist && mkdir -p dist
	cid=$$(docker create $(BUILDER_IMAGE)); \
	  docker cp $$cid:/out/. dist/; \
	  docker rm $$cid >/dev/null
	@ls -l dist/*.deb

# --------------------------------------------------------------------- final image
# Containerfile asserts the .deb count, so a stale artifact fails the build
# rather than being installed silently; the `rm -rf dist` above keeps that honest.
image: $(DEB)
	docker build \
	  --build-arg DEBIAN_BASE=$(DEBIAN_BASE) \
	  -f Containerfile -t $(IMAGE) .
	@$(MAKE) --no-print-directory sizes

# Per-platform, because `docker images` sums every platform in a manifest list
# and makes the upstream image look ~8x bigger than it is.
sizes:
	@echo; echo "image size (uncompressed, this platform):"
	@for i in $(BASE_IMAGE) $(IMAGE); do \
	  printf '  %-26s %6.1f MB\n' "$$i" \
	    "$$(docker image inspect "$$i" --format '{{.Size}}' | awk '{print $$1/1048576}')"; \
	done

# ------------------------------------------------------------------------- tests
test: image
	docker pull -q $(BASE_IMAGE)
	BASE_IMAGE=$(BASE_IMAGE) TEST_IMAGE=$(IMAGE) python3 test/compat_test.py

# ------------------------------------------------------------------------- scans
baseline:
	trivy image --quiet $(BASE_IMAGE) > baseline-trivy.txt
	grype $(BASE_IMAGE) > baseline-grype.txt

scan: image
	mkdir -p scan
	trivy image --quiet $(IMAGE) > scan/hardened-trivy.txt || true
	grype $(IMAGE)                > scan/hardened-grype.txt || true
	@echo; echo "=== findings, as each tool counts them ==="
	@printf 'trivy  baseline %-28s hardened %s\n' \
	  "$$(grep -m1 -oE 'Total: .*' baseline-trivy.txt)" \
	  "$$(grep -m1 -oE 'Total: .*' scan/hardened-trivy.txt)"
	@printf 'grype  baseline %-28s hardened %s\n' \
	  "$$(($$(grep -cE '^[a-zA-Z0-9]' baseline-grype.txt) - 1)) rows" \
	  "$$(($$(grep -cE '^[a-zA-Z0-9]' scan/hardened-grype.txt) - 1)) rows"
	@echo; echo "=== unique CVE IDs (one CVE is often reported against several packages) ==="
	@printf 'trivy  baseline %-4s hardened %s\n' \
	  "$$(grep -oE 'CVE-[0-9]{4}-[0-9]+' baseline-trivy.txt | sort -u | wc -l | tr -d ' ')" \
	  "$$(grep -oE 'CVE-[0-9]{4}-[0-9]+' scan/hardened-trivy.txt | sort -u | wc -l | tr -d ' ')"
	@printf 'grype  baseline %-4s hardened %s\n' \
	  "$$(grep -oE 'CVE-[0-9]{4}-[0-9]+' baseline-grype.txt | sort -u | wc -l | tr -d ' ')" \
	  "$$(grep -oE 'CVE-[0-9]{4}-[0-9]+' scan/hardened-grype.txt | sort -u | wc -l | tr -d ' ')"
	@echo; echo "=== nginx package in grype, both images -- identical set proves ours is registered ==="
	@printf '  baseline  %s\n' "$$(awk '$$1=="nginx"' baseline-grype.txt | grep -oE 'CVE-[0-9]{4}-[0-9]+' | sort -u | tr '\n' ' ')"
	@printf '  hardened  %s\n' "$$(awk '$$1=="nginx"' scan/hardened-grype.txt | grep -oE 'CVE-[0-9]{4}-[0-9]+' | sort -u | tr '\n' ' ')"
	@echo; echo "=== CVEs NEW in our report (trivy attributes nginx here but not upstream) ==="
	@comm -13 \
	  <(grep -oE 'CVE-[0-9]{4}-[0-9]+' baseline-trivy.txt | sort -u) \
	  <(grep -oE 'CVE-[0-9]{4}-[0-9]+' scan/hardened-trivy.txt | sort -u) | sed 's/^/  /'
	@echo; echo "=== CVEs gone (present in baseline, absent now) ==="
	@comm -23 \
	  <(grep -oE 'CVE-[0-9]{4}-[0-9]+' baseline-trivy.txt | sort -u) \
	  <(grep -oE 'CVE-[0-9]{4}-[0-9]+' scan/hardened-trivy.txt | sort -u) \
	  | tee scan/fixed-cves.txt | head -40
	@echo "($$(wc -l < scan/fixed-cves.txt) total, full list in scan/fixed-cves.txt)"

# ------------------------------------------------------------- VEX demonstration
VEX_FILE := vex/nginx-hardened.openvex.json
VEX_CVES := CVE-2024-7347 CVE-2026-42767 CVE-2025-27587

# Scanned twice, with and without the document, so the effect of each statement
# is visible per CVE rather than only in the total.
vex: image
	@mkdir -p scan
	@trivy image --quiet                    $(IMAGE) > scan/vex-without.txt 2>/dev/null || true
	@trivy image --quiet --vex $(VEX_FILE)  $(IMAGE) > scan/vex-with.txt    2>/dev/null || true
	@echo; printf '  %-16s %-9s %-6s %s\n' CVE without with why
	@printf '  %-16s %-9s %-6s %s\n' ---------------- --------- ------ ---
	@for c in $(VEX_CVES); do \
	  case $$c in \
	    CVE-2024-7347)  why="fixed: backport, invisible to version matching";; \
	    CVE-2026-42767) why="not_affected: CMP/CRMF compiled out (no-cmp)";; \
	    CVE-2025-27587) why="not_affected: PowerPC-only code, arm64 build";; \
	  esac; \
	  printf '  %-16s %-9s %-6s %s\n' "$$c" \
	    "$$(grep -c $$c scan/vex-without.txt)" \
	    "$$(grep -c $$c scan/vex-with.txt)" "$$why"; \
	done
	@echo
	@printf '  totals   without VEX %s   with VEX %s\n' \
	  "$$(grep -m1 -oE 'Total: [0-9]+' scan/vex-without.txt | grep -oE '[0-9]+')" \
	  "$$(grep -m1 -oE 'Total: [0-9]+' scan/vex-with.txt    | grep -oE '[0-9]+')"
	@echo
	@echo "  CVE-2024-7347 is 0 -> 0 on purpose: no scanner in this toolchain"
	@echo "  reports it against nginx 1.25.5 in the first place, so there is"
	@echo "  nothing to suppress. The statement is shipped anyway because the"
	@echo "  backport is real and a consumer's scanner may well flag it."

clean:
	rm -rf dist scan
	-docker rmi $(IMAGE) $(BUILDER_IMAGE)
