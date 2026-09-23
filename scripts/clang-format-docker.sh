#!/usr/bin/env bash
# Run clang-format on app C sources using the Ledger app-builder image (same family as README).
#
# Usage:
#   ./scripts_local/clang-format-docker.sh           # format in place
#   ./scripts_local/clang-format-docker.sh --check  # fail if any file would change
#
# Override image:
#   CLANG_FORMAT_IMAGE=ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest ./scripts_local/clang-format-docker.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${CLANG_FORMAT_IMAGE:-ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest}"

MODE="${1:-format}"
if [[ "$MODE" != "format" && "$MODE" != "--check" ]]; then
    echo "Usage: $0 [--check]" >&2
    exit 2
fi

docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "${ROOT}:/app" \
    -w /app \
    -e "FORMAT_MODE=${MODE}" \
    "${IMAGE}" \
    bash -c '
set -euo pipefail
run_fmt() {
    local dir="$1"
    [[ -d "$dir" ]] || return 0
    if [[ "${FORMAT_MODE}" == "--check" ]]; then
        find "$dir" -type f \( -name "*.c" -o -name "*.h" \) -exec clang-format --dry-run --Werror {} +
    else
        find "$dir" -type f \( -name "*.c" -o -name "*.h" \) -exec clang-format -i {} +
    fi
}
run_fmt /app/src
run_fmt /app/fuzzing/src
'
