# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile for pe-parse — builds on the org C/C++ base image.
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile --build-arg COMMIT=$(git rev-parse HEAD) -t pe-parse .
FROM ghcr.io/mayhemheroes/base:20260621

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

# Extra build deps: ICU (pe-parse's to_string conversion) + git/CA for vendoring.
USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
    apt-get update && apt-get install -yq --no-install-recommends \
      libicu-dev git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Vendor Catch2 v2.13.6 (upstream tests/cmake/catch.cmake.in FetchContent pin) so the
# test-suite configure/build is offline: build.sh points FETCHCONTENT_SOURCE_DIR_CATCH2 here.
RUN git clone --depth 1 --branch v2.13.6 https://github.com/catchorg/Catch2.git /opt/vendor/Catch2 \
 && chown -R 2000:2000 /opt/vendor/Catch2

USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

# Bake the corkami PE poc dataset (upstream's tests/assets submodule, pinned to the
# gitlink commit) so corkami_test runs; sparse PE/bin only (~40 MB, not the full pocs repo).
RUN git clone --filter=blob:none --sparse https://github.com/corkami/pocs.git /tmp/corkami \
 && git -C /tmp/corkami sparse-checkout set PE/bin \
 && git -C /tmp/corkami checkout befb3632214640a4af20be3b463f41e4b82f04f6 \
 && mkdir -p /mayhem/tests/assets/corkami-poc-dataset \
 && cp -r /tmp/corkami/PE /mayhem/tests/assets/corkami-poc-dataset/ \
 && rm -rf /tmp/corkami

RUN bash mayhem/build.sh

RUN bash mayhem/test.sh

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
