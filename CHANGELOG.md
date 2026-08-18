# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.6.3] - 2026-08-13

### Changed
- CBOR parsing (memo, register data) now uses the tinycbor library instead of a hand-rolled streaming parser. Raw CBOR bytes are accumulated per-APDU and decoded once complete.
- Renamed `MAX_MEMO_STRING_SIZE` / `MAX_MEMO_CBOR_SIZE` to `MAX_CBOR_STRING_SIZE` / `MAX_CBOR_BLOB_SIZE` to reflect that CBOR decoding is not memo-specific.

### Fixed
- CBOR payloads requiring more than two APDU packets (e.g. a memo or registered-data blob split across three or more packets) are now processed correctly instead of returning an error.
- Stored challenge is erased on any `set_trusted_name` failure, preventing a rejected command from being retried with the same nonce.

## [5.6.2] - 2026-05-19

### Fixed
- PKI certificate verification: random challenge was silently dropped; certificate guards were incorrect, causing spurious failures or bypasses.

## [5.6.1] - 2026-05-19

### Fixed
- Security-audit findings (QB items): buffer overflow in several handlers, state not cleared after `get_app_name`/`get_app_version`, instruction context not reset on guard hit, empty public key accepted on Nano devices.

## [5.6.0] - 2026-04-21

### Added
- "Max fees" field shown on all sign-transfer confirmation screens.

### Fixed
- Replaced residual GTU copy with CCD in scheduled-transfer screens.

## [5.5.1] - 2026-04-15

### Added
- `set_trusted_name` instruction for PKI-signed name binding.
- `get_random_challenge` APDU for device-side randomness.
- `verify_address` command updated and re-tested.
- PKI `bind_descriptor` verification implemented.

### Changed
- `derivation_path_t` promoted to a global; removed per-instruction copies, reducing stack usage.
- Removed `LEDGER_ASSERT` calls from handlers in favour of explicit error returns.
- Removed magic constants from common and UI layers.

### Fixed
- Invalid CLA value now rejected at the dispatcher level.

## [5.5.0] - 2026-02-25

### Added
- Testnet derivation paths (`44'/1'`) supported in verify-address flow (INS 0x37).
- Export private key via new-style derivation path (separate handler from legacy path).

### Changed
- Merged upstream blooo-io v5.5.x line: PLT-token code removed; added standalone fuzzers.

### Fixed
- Memo blobs split across more than two APDUs now accumulate correctly instead of failing.
- Null-termination bug in CBOR string decoding (upstream audit fix).

## [5.4.1] - 2026-02-04

### Added
- Transaction fees read from the transaction header and shown on sign-transfer confirmation screens for all BAGL and NBGL devices.

### Fixed
- Removed undefined behaviour when displaying amounts too large for the temporary buffer.

## [5.4.0] - 2026-01-28

### Added
- `get_app_version` APDU: device now responds with the running app version bytes.

## [5.3.4] - 2026-01-21

### Changed
- Wording on private-key export screens updated for clarity.
- Added '?' prompt to the verify-address sign screen.

### Fixed
- CLA byte is now validated at the start of every instruction handler.

## [5.3.2] - 2025-10-23

### Added
- Apex Plus (apex_p) device support; golden snapshots updated for all targets.

### Changed
- Replaced deprecated `firmware` fixture with `backend` in all Ragger tests.
- Nano S snapshots removed (device no longer supported).

## [5.3.1] - 2025-06-17

### Changed
- Nano S removed from the device manifest (`ledger_app.toml`).
- Removed default `DEBUG=1` flag from Makefile.

## [5.3.0] - 2025-03-20

### Added
- Initial Ledger fork base derived from blooo-io/concordium-ledger-app; tests adapted for Stax and Flex.
- Nano S test snapshots added; CI adapted for multi-device matrix.

---
*Entries below are upstream blooo-io releases that form the base of this fork.*

## [5.2.0] - 2025-03-17

### Added
- QR code display in verify-address flow.

### Changed
- `exportPrivateKey` split into two separate instructions (legacy path vs. new derivation path).

## [5.1.3] - 2025-03-12

### Changed
- Merged LedgerHQ/app-concordium develop branch (blooo-io versions kept); CI now triggers on develop branch.

## [5.1.2] - 2025-03-06

### Fixed
- Additional buffer overflow and length checks in `signCredentialDeployment`, `signConfigureBaker`, `exportPrivateKey`, and `sign.c` (audit, round 2).

## [5.1.1] - 2025-03-05

### Fixed
- Recipient address now base58-encoded for transfer-to-public display.

## [5.1.0] - 2025-03-04

### Added
- Recipient address display for transfer-to-public transactions.
- Four additional context fields shown in credential deployment and public-info-for-IP signing flows.

### Fixed
- Comprehensive buffer overflow checks across multiple transaction handlers and time/amount display functions.

## [5.0.2] - 2025-01-31

### Fixed
- Warnings and bugs raised by security audit; magic numbers removed from CBOR reader.

## [5.0.1] - 2025-01-24

### Added
- `suspended` boolean flag added to the `configureBaker` instruction.

## [5.0.0] - 2024-12-17

### Added
- Full NBGL display support (Stax, Flex) for all instruction types: transfer, transfer with memo, scheduled transfers, register data, credential deployment, configure baker/delegation, public info for IP, init/update contract, deploy module, export private key, verify address, get public key.
- New derivation path formats supported in get-public-key and verify-address flows.

### Changed
- Handler logic split from display layer across all instructions (BAGL and NBGL).
- Deprecated SDK methods removed; replaced with current equivalents.
