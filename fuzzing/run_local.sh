#!/usr/bin/env bash
#
# Local fuzzing runner.  Always rebuilds, then runs all 19 targets in parallel
# for a configurable duration, saving findings to fuzzing/corpus/ and crashes to
# fuzzing/crashes/.
#
# Each target starts from the seed corpus in fuzzing/seeds/<target>/ and uses
# fuzzing/dictionaries/<target>.dict, so a local run begins at the same deep, valid protocol
# states as a CI campaign.  Both are generated here, exactly as .clusterfuzzlite/build.sh
# generates them, so neither tree needs tracking.
#
# Usage:
#   ./run_local.sh                        # run for 60 s per target (default)
#   ./run_local.sh -t 300                 # run for 5 minutes per target
#   ./run_local.sh -t 300 -j 4           # cap to 4 parallel jobs
#   ./run_local.sh -f standalone_sign_transfer_fuzzer   # single target

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
CORPUS_DIR="$SCRIPT_DIR/corpus"
CRASH_DIR="$SCRIPT_DIR/crashes"
# Generated starting corpus and dictionaries (see fuzzing/tools/generate_seed_corpus.py).
SEEDS_DIR="$SCRIPT_DIR/seeds"
DICTS_DIR="$SCRIPT_DIR/dictionaries"

# ── defaults ─────────────────────────────────────────────────────────────────
FUZZ_SECONDS=60
MAX_JOBS=$(( $(nproc) / 2 ))
MAX_JOBS=$(( MAX_JOBS < 1 ? 1 : MAX_JOBS ))
FILTER=""

# ── argument parsing ──────────────────────────────────────────────────────────
usage() {
    echo "Usage: $0 [-t seconds] [-j jobs] [-f fuzzer_name]"
    echo "  -t  seconds per target (default: $FUZZ_SECONDS)"
    echo "  -j  max parallel jobs  (default: $MAX_JOBS)"
    echo "  -f  run only this one target (basename, no path)"
    exit 1
}

while getopts "t:j:f:h" opt; do
    case $opt in
        t) FUZZ_SECONDS="$OPTARG" ;;
        j) MAX_JOBS="$OPTARG" ;;
        f) FILTER="$OPTARG" ;;
        h|*) usage ;;
    esac
done

# ── build ─────────────────────────────────────────────────────────────────────
# Always configure and build before collecting targets.
#
# This used to run the build system only when $BUILD_DIR was missing, or when CMakeLists.txt
# was newer than the generated Makefile. Editing a production handler, a shared helper, a
# harness, a stub or the SDK therefore rebuilt nothing: the run below picked up whatever
# standalone_* binaries happened to be lying in $BUILD_DIR and reported coverage and crashes
# for a previous revision (finding V-113). CMake and Make already track dependencies
# precisely, so letting them run every time costs a no-op build when nothing changed, and is
# the only thing that guarantees the binaries match the working tree.
echo "[build] Configuring and incrementally rebuilding fuzz targets …"
cmake -S "$SCRIPT_DIR" -B "$BUILD_DIR" -DCMAKE_C_COMPILER=clang
cmake --build "$BUILD_DIR" --parallel "$(nproc)"

# Regenerate the seeds and dictionaries for the same reason the build always runs: they are
# derived from the harness input layouts, so an edited harness must not be fuzzed with the
# seeds of the previous one.
echo "[build] Generating seed corpus and dictionaries …"
python3 "$SCRIPT_DIR/tools/generate_seed_corpus.py"

# Record what was fuzzed next to the logs, so a stale-looking result can be tied to an exact
# revision rather than guessed at.
mkdir -p "$CRASH_DIR"
{
    echo "date:      $(date -Is)"
    echo "commit:    $(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "dirty:     $(git -C "$SCRIPT_DIR" status --porcelain 2>/dev/null | wc -l) modified path(s)"
    echo "compiler:  $(clang --version 2>/dev/null | head -1)"
    echo "seconds:   $FUZZ_SECONDS"
} >"$CRASH_DIR/build_info.txt"

# ── collect targets ───────────────────────────────────────────────────────────
if [[ -n "$FILTER" ]]; then
    TARGETS=("$BUILD_DIR/$FILTER")
    if [[ ! -x "${TARGETS[0]}" ]]; then
        echo "error: '$FILTER' not found in $BUILD_DIR" >&2
        exit 1
    fi
else
    mapfile -t TARGETS < <(find "$BUILD_DIR" -maxdepth 1 -name "standalone_*" -perm /111 | sort)
fi

echo "[run] ${#TARGETS[@]} target(s), ${FUZZ_SECONDS}s each, up to ${MAX_JOBS} parallel jobs"
echo "[run] corpus → $CORPUS_DIR   crashes → $CRASH_DIR   seeds → $SEEDS_DIR"
echo

# ── run loop ──────────────────────────────────────────────────────────────────
running=0
pids=()
names=()

run_one() {
    local bin="$1"
    local name
    name="$(basename "$bin")"
    local corpus="$CORPUS_DIR/$name"
    local logfile="$CRASH_DIR/${name}.log"

    mkdir -p "$corpus"

    # libFuzzer takes any number of corpus directories and only writes new units into the
    # first, so passing the tracked seeds second gives every run the same deep starting
    # states without the campaign ever modifying them.
    local corpora=("$corpus")
    [[ -d "$SEEDS_DIR/$name" ]] && corpora+=("$SEEDS_DIR/$name")

    local dict_args=()
    [[ -f "$DICTS_DIR/${name}.dict" ]] && dict_args+=("-dict=$DICTS_DIR/${name}.dict")

    # libFuzzer: positional args = corpus dirs; artifact_prefix = crash output dir
    "$bin" \
        -max_total_time="$FUZZ_SECONDS" \
        -artifact_prefix="$CRASH_DIR/${name}-" \
        -print_final_stats=1 \
        ${dict_args[@]+"${dict_args[@]}"} \
        "${corpora[@]}" \
        >"$logfile" 2>&1

    local rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "[CRASH] $name — see $logfile"
    else
        # pull the final stats line for a one-line summary
        local cov execs
        cov=$(grep "cov:" "$logfile" | tail -1 | grep -oP "cov: \K[0-9]+") || cov="?"
        execs=$(grep "stat::number_of_executed_units:" "$logfile" | grep -oP ": \K[0-9]+") || execs="?"
        printf "[done] %-55s  cov: %s  execs: %s\n" "$name" "$cov" "$execs"
    fi
}

export -f run_one
export CRASH_DIR CORPUS_DIR SEEDS_DIR DICTS_DIR FUZZ_SECONDS

for bin in "${TARGETS[@]}"; do
    run_one "$bin" &
    pids+=($!)
    names+=("$(basename "$bin")")
    running=$(( running + 1 ))

    if (( running >= MAX_JOBS )); then
        wait "${pids[0]}"
        pids=("${pids[@]:1}")
        names=("${names[@]:1}")
        running=$(( running - 1 ))
    fi
done

wait

# ── crash summary ─────────────────────────────────────────────────────────────
crash_files=()
mapfile -t crash_files < <(find "$CRASH_DIR" -maxdepth 1 -name "standalone_*-crash-*" -o -name "standalone_*-timeout-*" 2>/dev/null | sort)

if (( ${#crash_files[@]} > 0 )); then
    echo
    echo "══ ${#crash_files[@]} crash(es) found ══"
    for f in "${crash_files[@]}"; do
        echo "  $f"
    done
    echo
    echo "Reproduce a crash:"
    echo "  $BUILD_DIR/<fuzzer> <crash-file>"
    exit 1
else
    echo
    echo "No crashes found."
fi
