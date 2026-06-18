#!/bin/bash -eu

# build fuzzers

pushd fuzzing
cmake -DBOLOS_SDK=../BOLOS_SDK -Bbuild -H.
make -C build
for fuzzer in \
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
done
popd
