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
