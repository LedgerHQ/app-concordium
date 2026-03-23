#!/usr/bin/env bash
# Build the Concordium Ledger app (Makefile / BOLOS_SDK) for each target and run
# Ragger golden snapshot tests in parallel (one Docker container per target).
#
# Prerequisites: Docker, ledger-app-dev-tools image (or set REFERENCE_CONTAINER / IMAGE).
# From the repo root:  ./scripts/golden_tests_all_targets.sh
#
# Targets are Makefile TARGET names (see ledger-secure-sdk/Makefile.target).
# Optional alias: nanosplus -> nanos2 (Nano S+).

set -eu

# Default: all SDK targets (nanos2 = Nano S+)
TARGETS="${TARGETS:-apex_p nanox nanos2 flex stax}"

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REFERENCE_CONTAINER="${REFERENCE_CONTAINER:-app-concordium-container}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
log_target() { echo "[$(date '+%H:%M:%S')] [$1] $2"; }

log "Project root: $PROJECT_ROOT"

if docker inspect "$REFERENCE_CONTAINER" &>/dev/null; then
    IMAGE=$(docker inspect "$REFERENCE_CONTAINER" --format '{{.Config.Image}}')
    log "Using image from $REFERENCE_CONTAINER: $IMAGE"
else
    IMAGE="${IMAGE:-ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest}"
    log "Using default image: $IMAGE"
fi

# Makefile TARGET -> pytest --device name (ragger / speculos).
# Nano S+ is built as TARGET=nanos2 but Ragger/Speculos use the product name "nanosp".
device_for_pytest() {
    case "$1" in
        nanos2) echo nanosp ;;
        *) echo "$1" ;;
    esac
}

# Makefile TARGET -> env var holding BOLOS_SDK path inside ledger-app-dev-tools
sdk_env_name_for_target() {
    case "$1" in
        nanox) echo NANOX_SDK ;;
        nanos2) echo NANOS2_SDK ;;
        stax) echo STAX_SDK ;;
        flex) echo FLEX_SDK ;;
        apex_p) echo APEX_P_SDK ;;
        apex_m) echo APEX_M_SDK ;;
        *)
            echo ""
            ;;
    esac
}

normalize_target() {
    case "$1" in
        nanosplus) echo nanos2 ;;
        *) echo "$1" ;;
    esac
}

container_name() { echo "app-concordium-golden-$1"; }

ensure_container() {
    local target=$1 name
    name=$(container_name "$target")
    if ! docker inspect "$name" &>/dev/null; then
        log_target "$target" "Creating container $name..."
        docker create --name "$name" \
            --user 1000:1000 \
            -v "$PROJECT_ROOT:/app" \
            -w /app \
            -e PYTHONUNBUFFERED=1 \
            "$IMAGE" \
            sleep infinity >/dev/null
    fi
    if [ "$(docker inspect -f '{{.State.Running}}' "$name")" != "true" ]; then
        docker start "$name" >/dev/null
    fi
}

# --- Ensure all containers exist and are running ---
for TARGET in $TARGETS; do
    T=$(normalize_target "$TARGET")
    ensure_container "$T"
done

# --- Install deps in first container, copy venv to the rest ---
FIRST_RAW=$(echo "$TARGETS" | awk '{print $1}')
FIRST_TARGET=$(normalize_target "$FIRST_RAW")
FIRST_CNAME=$(container_name "$FIRST_TARGET")

if ! docker exec "$FIRST_CNAME" test -f /tmp/.deps-installed; then
    log "Installing deps in $FIRST_CNAME..."
    docker exec "$FIRST_CNAME" bash -c '
        set -e
        source /opt/venv/bin/activate
        pip install -q --extra-index-url https://test.pypi.org/simple/ -r tests/requirements.txt
        touch /tmp/.deps-installed
    '
    log "Copying venv to other containers..."
    for TARGET in $TARGETS; do
        T=$(normalize_target "$TARGET")
        [ "$T" = "$FIRST_TARGET" ] && continue
        CNAME=$(container_name "$T")
        docker cp "$FIRST_CNAME:/opt/venv" - | docker cp - "$CNAME:/opt/"
        docker exec "$CNAME" touch /tmp/.deps-installed
        log_target "$T" "venv copied"
    done
    log "All containers ready"
else
    log "Deps already installed, skipping"
fi

# --- Build & test each target in parallel ---
for TARGET in $TARGETS; do
    (
        T=$(normalize_target "$TARGET")
        DEVICE=$(device_for_pytest "$T")
        CNAME=$(container_name "$T")
        SDK_VAR=$(sdk_env_name_for_target "$T")
        log_target "$T" "Using container $CNAME"

        # bash -lc: login shell loads NANOX_SDK, NANOS2_SDK, etc. from image profile
        docker exec "$CNAME" bash -lc '
                set -e
                TAG="'"$T"'"
                log() { echo "[$(date +%H:%M:%S)] [$TAG] $*"; }

                DEVICE="'"$DEVICE"'"
                SDK_VAR="'"$SDK_VAR"'"
                if [ -z "$SDK_VAR" ]; then
                    log "No BOLOS_SDK mapping for target $TAG"
                    exit 1
                fi
                BOLOS_SDK="${!SDK_VAR:-}"
                if [ -z "$BOLOS_SDK" ]; then
                    log "Environment variable $SDK_VAR is not set (is this ledger-app-dev-tools?)"
                    exit 1
                fi
                export BOLOS_SDK

                log "Building (TARGET='"$T"', BOLOS_SDK=$BOLOS_SDK)..."
                cd /app
                # Per-target clean only (parallel-safe; "make clean" would delete all build/*)
                make BOLOS_SDK="$BOLOS_SDK" TARGET='"$T"' clean_target
                make BOLOS_SDK="$BOLOS_SDK" TARGET='"$T"'

                # Ragger looks for build/<pytest --device>/bin/app.elf; Makefile uses TARGET=nanos2 for S+.
                if [ "$TAG" = nanos2 ] && [ -d /app/build/nanos2 ]; then
                    ln -sfn nanos2 /app/build/nanosp
                    log "Linked build/nanosp -> nanos2 for --device nanosp"
                fi

                log "Running Ragger tests (device=$DEVICE)..."
                cd /app
                /opt/venv/bin/pytest tests/ --tb=short -v --device "$DEVICE" --golden_run -s

                log "All tests passed"
            ' 2>&1 && log_target "$T" "Done" || { log_target "$T" "FAILED"; exit 1; }
    ) &
done

log "Waiting for all targets..."
wait

log "=== All targets completed ==="
