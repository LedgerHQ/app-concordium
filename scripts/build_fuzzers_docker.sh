#!/usr/bin/env bash
# Build (and briefly run) the libFuzzer targets the way ClusterFuzzLite CI does, using the
# OSS-Fuzz base image.
#
# Why this exists: the device build globs `src/` (APP_SOURCE_PATH), but the fuzz build enumerates
# its sources in fuzzing/CMakeLists.txt and stubs out the APDU response layer in
# fuzzing/stubs/stubs.c. So a new file under src/helpers/, or a new send_* function, breaks the
# fuzzers while the app still builds and every Ragger test passes. CI is the only thing that
# notices, and it fails fast on the first target — reporting one missing symbol per run. Run this
# before pushing a commit that adds either.
#
# Compiling and fuzzing both run several targets at once: the build hands make -j the whole
# machine, and the smoke run keeps -j targets fuzzing concurrently. Wall-clock for the run stage
# is therefore about (targets / jobs) x seconds rather than targets x seconds.
#
# Usage:
#   ./scripts_local/build_fuzzers_docker.sh                    # build + run each target 10s
#   ./scripts_local/build_fuzzers_docker.sh --no-run           # build only
#   ./scripts_local/build_fuzzers_docker.sh --seconds 60       # longer run per target
#   ./scripts_local/build_fuzzers_docker.sh -j 4               # cap concurrent fuzzers
#   ./scripts_local/build_fuzzers_docker.sh --build-jobs 8     # cap compiler processes
#   ./scripts_local/build_fuzzers_docker.sh --serial           # one target at a time
#   ./scripts_local/build_fuzzers_docker.sh --sanitizer memory # the other sanitizer CI uses
#   ./scripts_local/build_fuzzers_docker.sh -f standalone_cbor_data_blob_fuzzer
#
# Each concurrent fuzzer peaked at 89-164 MB RSS in the address-sanitizer smoke run, so the
# default of nproc/2 needs roughly nproc/2 x 0.2 GB. Lower -j if the box is already busy: a
# fuzzer killed by the OOM killer reports as a failure indistinguishable from a real one.
#
# Overrides:
#   SDK_PATH=...  host path to ledger-secure-sdk (default: sibling of the repo)
#   IMAGE=...     OSS-Fuzz builder image (default: the digest pinned in .clusterfuzzlite)
#
# Artifacts (all gitignored): fuzzing/out/ binaries, fuzzing/corpus/<target>/,
# fuzzing/crashes/<target>/. Prerequisites: Docker, a local ledger-secure-sdk checkout.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SANITIZER=address
RUN_SECONDS=10
DO_RUN=1
FILTER=""

# Concurrent fuzzers. Half the cores by default, matching fuzzing/run_local.sh: a libFuzzer
# process is single-threaded, so this leaves room for the other half of the machine.
HOST_CORES="$(nproc 2>/dev/null || echo 2)"
RUN_JOBS=$(( HOST_CORES / 2 ))
(( RUN_JOBS < 1 )) && RUN_JOBS=1
# Compiler processes. Building is the memory-cheaper stage of the two, so it gets everything.
BUILD_JOBS="$HOST_CORES"

usage() {
    # The whole comment header: line 2 through the last line before `set -euo pipefail`.
    sed -n "2,$(( $(grep -n '^set -euo pipefail' "${BASH_SOURCE[0]}" | cut -d: -f1) - 1 ))p" \
        "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-2}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sanitizer)  SANITIZER="${2:?--sanitizer needs a value}"; shift 2 ;;
        --seconds)    RUN_SECONDS="${2:?--seconds needs a value}"; shift 2 ;;
        -f|--fuzzer)  FILTER="${2:?--fuzzer needs a value}"; shift 2 ;;
        -j|--jobs)    RUN_JOBS="${2:?--jobs needs a value}"; shift 2 ;;
        --build-jobs) BUILD_JOBS="${2:?--build-jobs needs a value}"; shift 2 ;;
        --serial)     RUN_JOBS=1; shift ;;
        --no-run)     DO_RUN=0; shift ;;
        -h|--help)    usage 0 ;;
        *) echo "Unknown argument: $1" >&2; usage ;;
    esac
done

case "$SANITIZER" in
    address | memory | undefined | coverage) ;;
    *) echo "Unknown sanitizer '$SANITIZER' (address, memory, undefined, coverage)" >&2; exit 2 ;;
esac

for pair in "jobs:$RUN_JOBS" "build-jobs:$BUILD_JOBS"; do
    if ! [[ "${pair#*:}" =~ ^[1-9][0-9]*$ ]]; then
        echo "--${pair%%:*} needs a positive integer, got '${pair#*:}'" >&2
        exit 2
    fi
done

SDK_PATH="${SDK_PATH:-$(cd "${PROJECT_ROOT}/.." && pwd)/ledger-secure-sdk}"

# Default to the digest pinned in .clusterfuzzlite/Dockerfile so a local build uses the same
# toolchain as CI; fall back to the mutable tag only if the pin cannot be read.
IMAGE="${IMAGE:-$(sed -n 's|^FROM \(gcr\.io/oss-fuzz-base/base-builder.*\)$|\1|p' \
    "${PROJECT_ROOT}/.clusterfuzzlite/Dockerfile" | head -1)}"
IMAGE="${IMAGE:-gcr.io/oss-fuzz-base/base-builder:v1}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

if [[ ! -d "$SDK_PATH" ]]; then
    echo "ledger-secure-sdk not found at '$SDK_PATH'. Set SDK_PATH=/path/to/ledger-secure-sdk." >&2
    exit 1
fi

log "Project root: $PROJECT_ROOT"
log "SDK:          $SDK_PATH"
log "Image:        $IMAGE"
log "Sanitizer:    $SANITIZER"
log "Build:        make -j${BUILD_JOBS}"
if [[ "$DO_RUN" == 1 ]]; then
    if [[ -n "$FILTER" ]]; then
        # A filter names exactly one target, so the job cap is irrelevant.
        log "Run:          ${RUN_SECONDS}s, only ${FILTER}"
    else
        log "Run:          ${RUN_SECONDS}s per target, ${RUN_JOBS} at a time"
    fi
else
    log "Run:          skipped (--no-run)"
fi

mkdir -p "${PROJECT_ROOT}/fuzzing/out" "${PROJECT_ROOT}/fuzzing/corpus" \
         "${PROJECT_ROOT}/fuzzing/crashes"

# Without this, SIGINT terminates the host shell at once and can orphan the container. With it,
# bash defers to after `docker run` returns, giving the container time to stop cleanly.
trap 'printf "\n"; log "Interrupted."; exit 130' INT

# The container layout mirrors .clusterfuzzlite/Dockerfile: repo at $SRC/concordium-ledger-app
# with the SDK beside it as BOLOS_SDK, and build.sh at $SRC where `compile` looks for it.
#
# Everything below runs as root inside the container, which matters twice:
#  - `compile` writes /usr/lib/libFuzzingEngine.a, so it cannot run as the host user. It is also
#    what produces that archive, which is why build.sh must never be invoked directly.
#  - a previous run leaves root-owned fuzzing/build, so the stale-cache cleanup has to happen in
#    here too (a CMakeCache from another environment makes make die with a bare "Error 127").
# `compile` runs under `set -u`, hence the full env below. Ownership is handed back at the end.
docker run --rm \
    -v "${PROJECT_ROOT}:/src/concordium-ledger-app" \
    -v "${SDK_PATH}:/src/concordium-ledger-app/BOLOS_SDK:ro" \
    -e "SANITIZER=${SANITIZER}" \
    -e SRC=/src \
    -e OUT=/src/concordium-ledger-app/fuzzing/out \
    -e WORK=/work \
    -e FUZZING_LANGUAGE=c \
    -e FUZZING_ENGINE=libfuzzer \
    -e ARCHITECTURE=x86_64 \
    -e "DO_RUN=${DO_RUN}" \
    -e "RUN_SECONDS=${RUN_SECONDS}" \
    -e "RUN_JOBS=${RUN_JOBS}" \
    -e "FUZZ_BUILD_JOBS=${BUILD_JOBS}" \
    -e "FILTER=${FILTER}" \
    -e "HOST_UID=$(id -u)" \
    -e "HOST_GID=$(id -g)" \
    -w /src/concordium-ledger-app \
    "$IMAGE" \
    bash -c '
set -eu
FUZZ_DIR=/src/concordium-ledger-app/fuzzing
cleanup() { chown -R "${HOST_UID}:${HOST_GID}" "$FUZZ_DIR" 2>/dev/null || true; }
trap cleanup EXIT

rm -rf "${FUZZ_DIR}/build" "${OUT:?}"/standalone_*_fuzzer
mkdir -p /work "$OUT"
cp .clusterfuzzlite/build.sh /src/build.sh
compile

# build.sh moves each linked fuzzer into $OUT, so a target that failed to link is simply absent.
expected=$(grep -oE "standalone_[a-z_]+_fuzzer" .clusterfuzzlite/build.sh | sort -u | wc -l)
built=$(find "$OUT" -maxdepth 1 -type f -name "standalone_*_fuzzer" | wc -l)
echo "== fuzzers built: ${built}/${expected}"
if [ "$built" -ne "$expected" ]; then
    echo "!! not every fuzzer was produced - see the link errors above" >&2
    exit 1
fi

[ "$DO_RUN" = "1" ] || exit 0

# Short smoke run: enough to prove each target starts, initialises its handler state and
# survives its own seeds. Not a fuzzing campaign - use fuzzing/run_local.sh for that.
#
# Up to $RUN_JOBS targets fuzz at once. Each writes to its own log and, on exit, drops a marker
# file holding its status; the loop below polls for markers rather than using `wait -n`, which
# cannot say *which* job finished on the bash 5.0 in this image. The whole report for a
# finished target is printed in one go from the main loop, so concurrent runs never interleave.
names=()
for bin in "$OUT"/standalone_*_fuzzer; do
    name=$(basename "$bin")
    [ -z "$FILTER" ] || [ "$name" = "$FILTER" ] || continue
    names+=("$name")
done
total=${#names[@]}
if [ "$total" -eq 0 ]; then
    echo "!! no target matched FILTER=${FILTER}" >&2
    exit 1
fi
[ "$RUN_JOBS" -le "$total" ] || RUN_JOBS="$total"

STATE_DIR=/work/runstate
mkdir -p "$STATE_DIR"

# On Ctrl-C: kill every fuzzer still running, wipe the status line, exit 130. child_pids is
# expanded when the trap fires, not now, and defaults to empty so it is safe under `set -u`.
child_pids=""
trap "for p in \${child_pids:-}; do kill \$p 2>/dev/null || true; done; \
printf \"\r\033[K\n\033[1;33m!! Interrupted\033[0m\n\"; exit 130" INT

# Parse one finished log and print its block. Match the status word as a field, not with a
# whitespace regex: libFuzzer separates the run count from it with a TAB ("#69<TAB>INITED ...").
report_target() {
    r_name="$1"
    r_code="$2"
    # Never let a surprising status string abort the run before the other targets are reported.
    case "$r_code" in
        "" | *[!0-9]*) r_code=255 ;;
    esac
    r_short="${r_name#standalone_}"
    r_short="${r_short%_fuzzer}"
    r_crashes="${FUZZ_DIR}/crashes/${r_name}"

    printf "\r\033[K"
    printf "\033[1;36m┌── %-52s ──┐\033[0m\n" "$r_short"
    awk "
        \$1 ~ /^#[0-9]+\$/ {
            for (i=1; i<=NF; i++) {
                if (\$i == \"cov:\") cov=\$(i+1)
                if (\$i == \"ft:\")  ft=\$(i+1)
            }
            if (\$2 == \"INITED\")   { icov=cov; ift=ft }
            else if (\$2 == \"NEW\") { news++ }
            next
        }
        /^stat::number_of_executed_units:/ { execs=\$2; next }
        /^stat::average_exec_per_sec:/     { eps=\$2;   next }
        /^stat::new_units_added:/          { added=\$2; next }
        /^stat::peak_rss_mb:/              { rss=\$2;   next }
        /^stat::slowest_unit_time_sec:/    { slow=\$2;  next }
        /^Done /                           { done=\$0;  next }
        /ERROR:|^SUMMARY:|ABORTING|deadly signal|Test unit written to/ {
            printf \"  \033[31m%s\033[0m\n\", \$0; next
        }
        END {
            if (icov != \"\") printf \"  \033[2minit   cov %-6s ft %-6s\033[0m\n\", icov, ift
            if (cov != \"\")  printf \"  \033[33mfinal  cov %-6s ft %-6s  +%d new\033[0m\n\", cov, ft, news+0
            if (done != \"\") printf \"  \033[2m%s\033[0m\n\", done
            printf \"  \033[36mexec\033[0m %d  \033[36mexec/s\033[0m %d  \033[36mnew\033[0m %d  \033[36mpeak-rss\033[0m %dMb  \033[36mslowest\033[0m %ds\n\",
                execs+0, eps+0, added+0, rss+0, slow+0
        }
    " "${r_crashes}/last_run.log"

    if [ "$r_code" -eq 0 ]; then
        printf "\033[1;32m└── PASS\033[0m\n"
        pass_list="${pass_list} ${r_short}"
    else
        # 137 is SIGKILL, which on a loaded box is usually the OOM killer rather than a finding.
        r_note=""
        [ "$r_code" -eq 137 ] && r_note="  (killed - check memory, or lower -j)"
        printf "\033[1;31m└── FAIL rc=%s%s  →  %s/last_run.log\033[0m\n" \
            "$r_code" "$r_note" "${r_crashes#/src/concordium-ledger-app/}"
        fail_list="${fail_list} ${r_short}"
        rc=1
    fi
}

rc=0
pass_list=""
fail_list=""
launched=0
ndone=0
nrunning=0
running_names=""
spin=0
t_start=$(date +%s)

while [ "$ndone" -lt "$total" ]; do
    # Fill every free slot before polling, so a finished target is replaced immediately.
    while [ "$nrunning" -lt "$RUN_JOBS" ] && [ "$launched" -lt "$total" ]; do
        name="${names[$launched]}"
        launched=$((launched + 1))
        corpus="${FUZZ_DIR}/corpus/${name}"
        crashes="${FUZZ_DIR}/crashes/${name}"
        mkdir -p "$corpus" "$crashes"

        # -print_funcs=0: on a cold corpus the first new-function discovery makes libFuzzer
        # symbolize a PC, and the symbolizer subprocess the sanitizer spawns deadlocks in this
        # image - the run then sits at NEW_FUNC with exec/s 0 until it is killed. Reproduced on
        # every target at HEAD, and cleared by either this flag or ASAN_OPTIONS=symbolize=0, so
        # it is the toolchain and not the app. Suppressing the function names costs nothing.
        # (No apostrophes in this block: it lives inside a single-quoted docker script.)
        #
        # `set +e` inside the subshell so a failing target still records its status: the
        # inherited `set -e` would otherwise abort the subshell before the marker was written.
        # The marker is written to a temporary name and moved into place, so the poll below can
        # never read a half-written one.
        (
            set +e
            "$OUT/$name" "$corpus" \
                -max_total_time="$RUN_SECONDS" \
                -artifact_prefix="${crashes}/" \
                -print_funcs=0 \
                -print_final_stats=1 >"${crashes}/last_run.log" 2>&1
            code=$?
            echo "$code" >"${STATE_DIR}/${name}.tmp"
            mv "${STATE_DIR}/${name}.tmp" "${STATE_DIR}/${name}.rc"
        ) &
        child_pids="${child_pids} $!"
        running_names="${running_names} ${name}"
        nrunning=$((nrunning + 1))
    done

    for name in $running_names; do
        marker="${STATE_DIR}/${name}.rc"
        [ -s "$marker" ] || continue
        code=$(cat "$marker")
        mv "$marker" "${marker}.seen"
        still=""
        for m in $running_names; do
            [ "$m" = "$name" ] || still="${still} ${m}"
        done
        running_names="$still"
        nrunning=$((nrunning - 1))
        ndone=$((ndone + 1))
        report_target "$name" "$code"
    done

    [ "$ndone" -lt "$total" ] || break

    # libFuzzer prints a pulse line only when the run counter hits a power of two, so polling
    # the logs on a timer is the only way a slow target does not look hung. exec/s is summed
    # across everything currently running, as a single number for the whole machine.
    case $((spin % 4)) in
        0) frame="|" ;; 1) frame="/" ;; 2) frame="-" ;; *) frame="\\" ;;
    esac
    spin=$((spin + 1))
    # The log is read while the fuzzer is still writing it, so a line can be caught before its
    # newline and appear spliced onto the next one - which made `grep -o` yield two numbers and
    # the arithmetic below abort the whole run under `set -e`. Take the first match only, and
    # treat anything that is not a plain integer as zero.
    agg=0
    for name in $running_names; do
        last=$(grep -a "^#[0-9]" "${FUZZ_DIR}/crashes/${name}/last_run.log" 2>/dev/null | tail -1)
        eps=$(printf "%s" "$last" | sed -n "s/.*exec\/s: \([0-9][0-9]*\).*/\1/p" | head -1)
        case "$eps" in
            "" | *[!0-9]*) eps=0 ;;
        esac
        agg=$((agg + eps))
    done
    printf "\r\033[K  \033[1m%s\033[0m  running \033[1m%d\033[0m  queued %-3d done \033[1m%d/%d\033[0m  agg exec/s %-9d \033[36m%ss\033[0m" \
        "$frame" "$nrunning" "$((total - launched))" "$ndone" "$total" "$agg" \
        "$(( $(date +%s) - t_start ))"
    sleep 0.4
done

printf "\r\033[K"
wait 2>/dev/null || true

printf "\n\033[1m══════════════════════════════ Summary ══════════════════════════════\033[0m\n"
# Sorted, not in completion order: with several running at once, targets finish in whatever
# order their -max_total_time expires, which makes an unsorted list hard to scan.
for t in $(printf "%s\n" $pass_list | sort); do printf "  \033[32m✓\033[0m  %s\n" "$t"; done
for t in $(printf "%s\n" $fail_list | sort); do printf "  \033[31m✗\033[0m  %s\n" "$t"; done
printf "  \033[2m%d target(s), %ds each, %d at a time, %ds wall-clock\033[0m\n" \
    "$total" "$RUN_SECONDS" "$RUN_JOBS" "$(( $(date +%s) - t_start ))"
printf "\033[1m═════════════════════════════════════════════════════════════════════\033[0m\n"

exit $rc
'
log "Done. Binaries: fuzzing/out/  Corpus: fuzzing/corpus/  Crashes: fuzzing/crashes/"
