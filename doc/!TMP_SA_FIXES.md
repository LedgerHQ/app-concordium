# Security Audit Fixes

## QB-2 — Early signing trigger in configure-baker display flow

Added `|| ctx->hasSuspended` to the "continue vs. sign" condition in
`startConfigureBakerDisplay` and `startConfigureBakerUrlDisplay` in both
`display_nbgl.c` and `display_bagl.c`.

When none of the three commission flags is set but `hasSuspended` is true, both
functions fell into the `else` branch and presented the sign screen directly,
skipping the `BAKER_SUSPENDED` display step entirely.

**Root cause:** `a6c8be40` (**GuilaneDen**, 2025-01-24,
*"fix(LDG-677): added suspended boolean to the configureBaker method"*) correctly
wired `CONFIGURE_BAKER_SUSPENDED` into the handler state machine but did not update
the display functions, leaving their "is this the last step?" guard stale.

## QB-1 — Out-of-order command execution in update-credential flow

Moved `ctx->state = TX_CREDENTIAL_DEPLOYMENT_VERIFICATION_KEYS_LENGTH` from the
`isInitialCall` block to the `P2_CREDENTIAL_CREDENTIAL_INDEX` branch in
`sign_update_credential.c`. Previously the deployment sub-state was set at flow start,
so a client could call the credential deployment handler directly without first going
through credential-index processing.

**Root cause:** The `P2_CREDENTIAL_CREDENTIAL_INDEX` → `TX_UPDATE_CREDENTIAL_CREDENTIAL`
transition was introduced by **Jakob Ørhøj** (`5d7543f2`, 2021-03-16) without ever
setting `ctx->state` at that point. The 2026 reorganization (`9477d6de`,
**dbaranov-hoodies**) added the eager `ctx->state` init at `isInitialCall`, which
widened the window to any point after flow start rather than after credential-index.

## QB-12 — Write out of bounds in `path_display_new` / `path_display_legacy`

Added `offset >= dstLength` guards before each `"/"` separator write in both functions
in `derivation_path.c`. Also changed `int offset` to `size_t` to match the return type
of `number_to_text`.

`number_to_text` validates that the digit string fits in the remaining buffer, but the
subsequent `memmove(dst + offset, "/", 1)` had no such check. If `offset == dstLength`
after the digit write the `"/"` lands out of bounds, and the following `dstLength - offset`
subtraction underflows (both are `size_t`), passing a huge length to the next call.

**Root cause:** `getIdentityAccountDisplayNewPath` was written from scratch by **keiff3r**
(`13c8d745`, 2024-12-04, *"feat(pubkey): support new derivation path format"*) with
`int offset` and no separator guard. Carried forward unchanged through the Apr 2026
reorganization (`93d496a`, **dbaranov-hoodies**) and renamed to `path_display_new` /
`path_display_legacy` (`43d78be`, **dbaranov-hodies**, 2026-04-09).

## QB-16 — Buffer overflow in `timeToDisplayText`

Added `time.tm_year <= 0` guard at function entry in `time.c`, `size_t offset` replacing
`int offset`, and `offset >= dstLength` checks before each separator write.

A negative `tm_year` (possible when `secondsToTm` receives a value near `INT_MAX *
31622400LL`) is silently cast to a huge `uint64_t` by `number_to_text`, producing a
20-digit string that overflows the 20-byte timestamp buffer before any separator is
written. The same unchecked separator offset pattern as QB-12 then causes further
underflow of `dstLength - offset`.

**Root cause:** `timeToDisplayText` was written from scratch by **Jakob Ørhøj**
(`f03824ba`, 2021-06-23, *"Refactor epoch to date conversion"*) with `int offset`, no
`tm_year` sign check, and no separator bounds guards. Carried through the replatform
(`f1c5511`, n4l5u0r, 2024-12-03) and reorganization (`93d496a`, dbaranov-hoodies,
2026-04-08) unchanged.

## QB-17 — Instruction-switching guard in dispatcher.c

Added a guard in `apdu_dispatcher()` rejecting any APDU whose `ins` differs from
`global_tx_state.currentInstruction` while a multi-step flow is active.

The guard was missing since `handler.c` was first created by **keiff3r** (`ae19e3395b`,
2024-12-04) — `currentInstruction` was already in `globals.h` (added by **n4l5u0r** in
the replatform `f1c5511`, 2024-12-03) but no check was ever wired into the dispatcher.
The April 2026 reorganization (`93d496a`, **dbaranov-hoodies**) rewrote `handler.c` into
`dispatcher.c` and carried the omission forward.

## QB-15 — Buffer overflow guard in `readCborContent`

Added a bounds check before `memmove` into `ctx->display` in `cbor_data_blob.c`.
A multi-chunk CBOR string could otherwise overflow the 255-byte display buffer.

**Root cause:** The `memoDisplayUsed` accumulator and the unbounded `memmove` were
introduced by **Hjort** (`524137ab`, 2021-09-07, *"fixes to memo based on feedback"*) in
the original `memo.c`. The code was carried forward without a fix through three
refactors: rename to `displayCbor.c` (Hjort, 2021-12-15), port to `sign.c` (n4l5u0r,
2024-12-03), and move to `cbor_data_blob.c` (dbaranov-hoodies, 2026-04-08).

## QB-3 — Unguarded P1_INITIAL in deploy-module / init-contract / update-contract handlers

Added `isInitialCall` parameter to `handle_deploy_module`, `handle_init_contract`, and
`handle_update_contract`, threaded it through the dispatcher, and changed `if (p1 == P1_INITIAL)`
to `if (p1 == P1_INITIAL && isInitialCall)` in each handler. A client could previously
send `P1_INITIAL` again mid-flow, silently resetting the SHA-256 hash and all parsed state
while the device remained in an active signing session.

**Root cause:** All three handlers were written from scratch by **keiff3r** without an
`isInitialCall` guard — `deploy_module` (`04c3d10`, 2024-12-10), `init_contract`
(`8acba8c`, 2024-12-11), `update_contract` (`c7fc099`, 2024-12-11). The April 2026
reorganisation (`93d496a`, **dbaranov-hoodies**) carried the omission forward unchanged.

## QB-4 — Unguarded initial call in configure-delegation handler

Added `isInitialCall` parameter to `handle_sign_configure_delegation` and threaded it through
the dispatcher. A guard at the top of the handler throws `ERROR_INVALID_STATE` on any
non-initial call. Because the handler has no sub-command state machine, a host could previously
replay the APDU while the device was waiting for user approval, swapping the displayed
delegation parameters (e.g. target baker ID or capital amount) before the user pressed
confirm.

**Root cause:** `handle_sign_configure_delegation` was written from scratch by **Jakob Ørhøj**
(`cfcbb47`, 2022-01-17, *"Add support for configure delegation transaction"*) without an
`isInitialCall` parameter or any state guard. Unlike other transaction handlers added at the
same time, the delegation handler was never updated to accept the parameter as the codebase
evolved.

## QB-5 / QB-6 — Missing bounds check in `*_FIRST` state of `handle_init_contract`

Added `if (remainingNameLength < lc) THROW(ERROR_INVALID_NAME_LENGTH)` immediately after
computing `remainingNameLength` in the `INIT_CONTRACT_NAME_FIRST` branch, and the equivalent
check for `remainingParamsLength` in the `INIT_CONTRACT_PARAMS_FIRST` branch of
`init_contract.c`. The identical guard already existed in each `else` branch (continuation
chunks) but was absent for the first chunk, so a client could send an `lc` larger than the
declared length, causing an unsigned underflow on `remaining -= lc` with a corrupted counter.

**Root cause:** `init_contract.c` was written from scratch by **keiff3r** (`8acba8c`,
2024-12-11). The `else if (remaining < lc)` guard was added for continuation chunks but the
first-chunk path was left unchecked. Carried forward by the April 2026 reorganisation
(`93d496a`, **dbaranov-hoodies**).

## QB-7 — Unguarded P1_INITIAL in `handle_sign_configure_baker`

Added `if (isInitialCall) { ctx_conf_baker->state = CONFIGURE_BAKER_INITIAL; }` before the
dispatch block in `sign_configure_baker.c`, and changed the first branch guard from
`P1_INITIAL == p1 && isInitialCall` to `P1_INITIAL == p1 && ctx_conf_baker->state ==
CONFIGURE_BAKER_INITIAL`. A client could previously call the initial sub-command at any
point in an active signing session because `ctx_conf_baker->state` was never checked in the
`P1_INITIAL` branch — only `isInitialCall` was tested. With QB-17's dispatcher guard in
place, `isInitialCall` is always false mid-flow, so the window is narrow; the fix makes the
guard consistent with every other multi-step handler in the codebase and uses the existing
`CONFIGURE_BAKER_INITIAL` state that was defined but never consumed.

**Root cause:** `handleSignConfigureBaker` was written from scratch by **jo** (`024cd076`,
2022-01-20, *"Initial configure baker"*) with `if (P1_INITIAL == p1)` and no guard at all.
Commit `db4a1cc` (**jo**, 2022-04-12, *"Add state checking to configure baker"*) added state
checks to all subsequent sub-commands and introduced the `CONFIGURE_BAKER_INITIAL` enum value,
but added only `&& isInitialCall` to the `P1_INITIAL` branch — leaving `CONFIGURE_BAKER_INITIAL`
defined but never used as a state guard. The December 2024 replatform (`313463a`, **n4l5u0r**)
and the April 2026 reorganisation (`93d496a`, **dbaranov-hoodies**) carried the incomplete guard
forward unchanged.

## QB-13 — Read out of bounds in `hashAccountTransactionHeaderAndKind`

Added `if (dataLength < ADDRESS_LENGTH) THROW(ERROR_INVALID_TRANSACTION)` at the top of
`hashAccountTransactionHeaderAndKind` in `tx_hash.c`, before the `base58check_encode` call.
`base58check_encode` reads exactly `ADDRESS_LENGTH` (32) bytes from `cdata`, but `dataLength`
was never checked first. `handleHeaderAndToAddress` correctly computes `remainingDataLength`
after stripping the derivation path and passes it in, but that value was ignored.
`hashHeaderAndType` (called afterward) does check `dataLength < ACCOUNT_TRANSACTION_HEADER_LENGTH + 1`,
but that check arrives too late — the 32-byte read has already happened.

**Root cause:** `f1f8f0be` (**jo**, 2021-05-28, *"Show sender address for all account
transactions"*) added `base58check_encode(cdata, 32, ...)` to a function that had no
`dataLength` parameter at all at the time — so a bounds check was not possible. The
`dataLength` parameter was added later as part of the `hashHeaderAndType` refactor but
no one added a guard for the preceding `base58check_encode` call. The omission was carried
through the December 2024 replatform (`f1c5511`, **n4l5u0r**) and the April 2026
reorganisation (`93d496a`, **dbaranov-hoodies**) unchanged.

## QB-10 / QB-11 — Read out of bounds in `parse_derivation_path_legacy` / `parse_derivation_path_new`

Added `if (lc < 8) THROW(SWO_INCORRECT_DATA)` at entry to `parse_derivation_path_legacy`
and `if (lc < 12) THROW(SWO_INCORRECT_DATA)` at entry to `parse_derivation_path_new` in
`derivation_path.c`. Both functions called `read_u32_be` (which performs no bounds check)
before any length validation; `check_lc` at the end verified the exact length only after
the out-of-bounds reads had already occurred.

**Root cause:** Both functions were introduced in the April 2026 reorganisation (`93d496a`,
**dbaranov-hoodies**) by extracting repeated derivation-path parsing from the individual
handlers. The original `handleExportPrivateKeyNewPath` and `handleExportPrivateKeyLegacyPath`
had explicit `if (remainingDataLength < 4) THROW(ERROR_INVALID_PATH)` guards before each
`U4BE` read. The extracted helpers replaced those per-field guards with a single
post-read `check_lc`, introducing the window.

## QB-8 / QB-9 — Same underflow in `handle_update_contract`

Identical fix applied to `update_contract.c`: bounds checks added in both
`UPDATE_CONTRACT_NAME_FIRST` and `UPDATE_CONTRACT_PARAMS_FIRST` branches.

**Root cause:** `update_contract.c` was written from scratch by **keiff3r** (`c7fc099`,
2024-12-11) with the same omission as `init_contract.c` above.
