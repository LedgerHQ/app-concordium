#!/bin/bash -eu

# build fuzzers
#
# Besides linking each target, this publishes the two artefacts ClusterFuzzLite/libFuzzer pick
# up automatically from $OUT:
#
#   $OUT/<target>_seed_corpus.zip   unpacked into the target's starting corpus
#   $OUT/<target>.dict              passed to the target as -dict=
#
# Without them every campaign starts cold, and these parsers need a long structured prefix - a
# packed derivation path, the 60-byte account-transaction header, an exact transaction-kind
# byte, then per-kind length fields - before any of the interesting code is reachable, so a
# cold run spends its whole budget failing the first length checks (finding V-108).
#
# Both are derived from the functional APDU fixtures in tests/standalone/ by
# fuzzing/tools/generate_seed_corpus.py, which runs here rather than committing ~300 binary
# blobs: the generator is the tracked source of truth, so a seed can never drift out of step
# with the fixture or the harness layout it was built from. A target left without seeds or a
# dictionary fails the build rather than silently reverting to a cold start.

pushd fuzzing
cmake -DBOLOS_SDK=../BOLOS_SDK -Bbuild -H.
make -C build

python3 tools/generate_seed_corpus.py

SEEDS_DIR="$(pwd)/seeds"
DICTS_DIR="$(pwd)/dictionaries"

# `zip` is present in the OSS-Fuzz base builder, but fall back to Python so the script also
# works in a leaner image.
package_seed_corpus() {
    local seed_dir="$1" archive="$2"
    if command -v zip >/dev/null 2>&1; then
        (cd "${seed_dir}" && zip -q -r -X "${archive}" .)
    else
        python3 - "${seed_dir}" "${archive}" <<'PY'
import pathlib, sys, zipfile
seed_dir, archive = pathlib.Path(sys.argv[1]), sys.argv[2]
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
    for entry in sorted(seed_dir.rglob("*")):
        if entry.is_file():
            zf.write(entry, entry.relative_to(seed_dir).as_posix())
PY
    fi
}

for fuzzer in \
    standalone_apdu_dispatch_fuzzer \
    standalone_set_trusted_name_fuzzer \
    standalone_export_pk_new_path_fuzzer \
    standalone_export_pk_legacy_path_fuzzer \
    standalone_cbor_data_blob_fuzzer \
    standalone_sign_transfer_fuzzer \
    standalone_sign_transfer_to_public_fuzzer \
    standalone_sign_configure_delegation_fuzzer \
    standalone_sign_configure_baker_fuzzer \
    standalone_sign_update_credential_fuzzer \
    standalone_init_contract_fuzzer \
    standalone_update_contract_fuzzer \
    standalone_deploy_module_fuzzer \
    standalone_sign_register_data_fuzzer \
    standalone_sign_transfer_with_memo_fuzzer \
    standalone_sign_transfer_with_schedule_fuzzer \
    standalone_sign_transfer_with_schedule_and_memo_fuzzer \
    standalone_sign_public_information_for_ip_fuzzer \
    standalone_sign_credential_deployment_fuzzer \
    standalone_get_public_key_fuzzer \
    standalone_verify_address_fuzzer; do
    mv "./build/${fuzzer}" "${OUT}"

    seed_dir="${SEEDS_DIR}/${fuzzer}"
    if [[ ! -d "${seed_dir}" ]] || [[ -z "$(ls -A "${seed_dir}")" ]]; then
        echo "no seed corpus for ${fuzzer}: expected files under fuzzing/seeds/${fuzzer}/." >&2
        echo "Run fuzzing/tools/generate_seed_corpus.py." >&2
        exit 1
    fi
    # ClusterFuzzLite and OSS-Fuzz both look for exactly this name beside the binary.
    package_seed_corpus "${seed_dir}" "${OUT}/${fuzzer}_seed_corpus.zip"

    dict_file="${DICTS_DIR}/${fuzzer}.dict"
    if [[ ! -f "${dict_file}" ]]; then
        echo "no dictionary for ${fuzzer}: expected fuzzing/dictionaries/${fuzzer}.dict." >&2
        echo "Run fuzzing/tools/generate_seed_corpus.py." >&2
        exit 1
    fi
    cp "${dict_file}" "${OUT}/${fuzzer}.dict"
done
popd
