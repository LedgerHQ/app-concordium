# Ledger builder tags stay on their documented trust policy and are deliberately not pinned.
FROM ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest AS LITE_BUILDER

# Base image with clang toolchain.
# Pinned by digest: `v1` is a mutable tag, so the fuzzing toolchain that compiles this app could
# change without any commit here. Bump the digest through a reviewed dependency update.
FROM gcr.io/oss-fuzz-base/base-builder:v1@sha256:8b4a73d83374b298a0a771eeec9a1d44ceff3416a678b7d7946303389d022aca

# Copy the project's source code.
COPY . $SRC/concordium-ledger-app
COPY --from=LITE_BUILDER /opt/ledger-secure-sdk $SRC/concordium-ledger-app/BOLOS_SDK

# Working directory for build.sh
WORKDIR $SRC/concordium-ledger-app

# Copy build.sh into $SRC dir.
COPY ./.clusterfuzzlite/build.sh $SRC/
