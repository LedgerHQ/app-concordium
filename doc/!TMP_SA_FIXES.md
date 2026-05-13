# Security Audit Fixes

This document tracks every finding addressed on branch `1360-sa-fixes`. For each issue it records the fix applied, the commit that originally introduced the bug, and the author responsible. Severities follow the audit's §8.2 table (QB-N and severity-N share the same numbering).

| QB# | Severity | Name | Introduced |
|-----|----------|------|------------|
| [QB-1](#qb-1)   | <span style="color:darkorange">Medium</span>   | Out-of-order command execution in update-credential flow                | 2021-03-16 · jo · `5d7543f2`                       |
| [QB-2](#qb-2)   | <span style="color:forestgreen">Low</span>     | Early signing trigger in configure-baker display flow                   | 2025-01-24 · GuilaneDen · `a6c8be40`               |
| [QB-3](#qb-3)   | <span style="color:forestgreen">Low</span>     | Unguarded P1_INITIAL in deploy-module / init-contract / update-contract | 2024-12-10/11 · keiff3r · `04c3d10` / `8acba8c` / `c7fc099` |
| [QB-4](#qb-4)   | <span style="color:forestgreen">Low</span>     | Unguarded initial call in configure-delegation handler                  | 2022-01-17 · jo · `cfcbb47`                        |
| [QB-5](#qb-5)   | <span style="color:forestgreen">Low</span>     | Missing bounds check in `NAME_FIRST` state of `handle_init_contract`    | 2024-12-11 · keiff3r · `8acba8c`                   |
| [QB-6](#qb-5)   | <span style="color:forestgreen">Low</span>     | Missing bounds check in `PARAMS_FIRST` state of `handle_init_contract`  | 2024-12-11 · keiff3r · `8acba8c`                   |
| [QB-7](#qb-7)   | <span style="color:forestgreen">Low</span>     | Unguarded P1_INITIAL in `handle_sign_configure_baker`                   | 2022-01-20 · jo · `024cd076`                       |
| [QB-8](#qb-8)   | <span style="color:forestgreen">Low</span>     | Missing bounds check in `NAME_FIRST` state of `handle_update_contract`  | 2024-12-11 · keiff3r · `c7fc099`                   |
| [QB-9](#qb-8)   | <span style="color:forestgreen">Low</span>     | Missing bounds check in `PARAMS_FIRST` state of `handle_update_contract`| 2024-12-11 · keiff3r · `c7fc099`                   |
| [QB-10](#qb-10) | <span style="color:forestgreen">Low</span>     | Read out of bounds in `parse_derivation_path_legacy`                    | 2026-04-08 · dbaranov-hoodies · `93d496a`          |
| [QB-11](#qb-10) | <span style="color:forestgreen">Low</span>     | Read out of bounds in `parse_derivation_path_new`                       | 2026-04-08 · dbaranov-hoodies · `93d496a`          |
| [QB-12](#qb-12) | <span style="color:darkorange">Medium</span>   | Write out of bounds in `path_display_new` / `path_display_legacy`       | 2024-12-04 · keiff3r · `13c8d745`                  |
| [QB-13](#qb-13) | <span style="color:forestgreen">Low</span>     | Read out of bounds in `hashAccountTransactionHeaderAndKind`             | 2021-05-28 · jo · `f1f8f0be`                       |
| [QB-14](#qb-14) | <span style="color:forestgreen">Low</span>     | Integer underflow in `readCborInitial`                                  | 2021-09-07 · Hjort · `5b108ea6`                    |
| [QB-15](#qb-15) | <span style="color:orangered">High</span>      | Buffer overflow in `readCborContent`                                    | 2021-09-07 · Hjort · `524137ab`                    |
| [QB-16](#qb-16) | <span style="color:darkorange">Medium</span>   | Buffer overflow in `timeToDisplayText`                                  | 2021-06-23 · Jakob Ørhøj · `f03824ba`              |
| [QB-17](#qb-17) | <span style="color:crimson">Critical</span>    | Instruction-switching guard missing in `dispatcher.c`                   | 2024-12-04 · keiff3r · `ae19e339`                  |
| [QB-18/1](#qb-18-1) | <span style="color:forestgreen">Low</span>     | Insufficient fuzzing coverage across APDU handlers                      | 2026-04-08 · dbaranov-hoodies · `93d496a`           |
| [QB-18/2](#qb-18-2) | <span style="color:forestgreen">Low</span>     | Global-buffer-overflow in export-private-key display (memmove overread) | 2026-04-08 · dbaranov-hoodies · `93d496a`           |
| [QB-18/3](#qb-18-3) | <span style="color:darkorange">Medium</span>   | Heap-buffer-overflow in `sign_configure_delegation` via stale dataLength| 2022-01-17 · Jakob Ørhøj · `cfcbb47`               |

---

<a id="qb-1"></a>
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

<a id="qb-2"></a>
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

<a id="qb-3"></a>
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

<a id="qb-4"></a>
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

<a id="qb-5"></a><a id="qb-6"></a>
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

<a id="qb-7"></a>
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

<a id="qb-8"></a><a id="qb-9"></a>
## QB-8 / QB-9 — Same underflow in `handle_update_contract`

Identical fix applied to `update_contract.c`: bounds checks added in both
`UPDATE_CONTRACT_NAME_FIRST` and `UPDATE_CONTRACT_PARAMS_FIRST` branches.

**Root cause:** `update_contract.c` was written from scratch by **keiff3r** (`c7fc099`,
2024-12-11) with the same omission as `init_contract.c` above.

<a id="qb-10"></a><a id="qb-11"></a>
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

<a id="qb-12"></a>
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

<a id="qb-13"></a>
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

<a id="qb-14"></a>
## QB-14 — Integer underflow in `readCborInitial`

Added `if (ctx->cborLength < 1) THROW(SWO_INCORRECT_DATA)` before the first decrement
(`ctx->cborLength -= 1` for the header byte) and `if (ctx->cborLength < sizeLength)
THROW(SWO_INCORRECT_DATA)` before the second decrement (`ctx->cborLength -= sizeLength`
for the length-of-length bytes) in `cbor_data_blob.c`. `ctx->cborLength` is `uint32_t`
and is set from a user-supplied 2-byte field (0–256); decrementing it past zero wraps to
~4 GiB and corrupts all subsequent length accounting. The worst case is a header byte
(`-= 1`) followed by an 8-byte length prefix (`-= 8`) against a `cborLength` of 0,
giving the nine-unit underflow the audit describes.

**Root cause:** `readMemoInitial` was written from scratch by **Hjort** (`5b108ea6`,
2021-09-07, *"split memo transactions from their non-memo counterparts"*) with no pre-decrement
guard. The same file included `if (ctx->memoLength < 0) THROW(ERROR_INVALID_STATE)` in the
unrelated `handleMemoStep()` callback, but `memoLength` was declared `uint32_t`, making the
check always false and leaving the actual decrements in `readMemoInitial` unprotected. The code
was carried forward through the rename to `displayCbor.c` (Hjort, 2021-12-15), the replatform
(`f1c5511`, **n4l5u0r**, 2024-12-03), and the move to `cbor_data_blob.c` (`93d496a`,
**dbaranov-hoodies**, 2026-04-08) without ever adding the missing guards.

<a id="qb-15"></a>
## QB-15 — Buffer overflow guard in `readCborContent`

Added a bounds check before `memmove` into `ctx->display` in `cbor_data_blob.c`.
A multi-chunk CBOR string could otherwise overflow the 255-byte display buffer.

**Root cause:** The `memoDisplayUsed` accumulator and the unbounded `memmove` were
introduced by **Hjort** (`524137ab`, 2021-09-07, *"fixes to memo based on feedback"*) in
the original `memo.c`. The code was carried forward without a fix through three
refactors: rename to `displayCbor.c` (Hjort, 2021-12-15), port to `sign.c` (n4l5u0r,
2024-12-03), and move to `cbor_data_blob.c` (dbaranov-hoodies, 2026-04-08).

<a id="qb-16"></a>
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

<a id="qb-17"></a>
## QB-17 — Instruction-switching guard in dispatcher.c

Added a guard in `apdu_dispatcher()` rejecting any APDU whose `ins` differs from
`global_tx_state.currentInstruction` while a multi-step flow is active.

The guard was missing since `handler.c` was first created by **keiff3r** (`ae19e3395b`,
2024-12-04) — `currentInstruction` was already in `globals.h` (added by **n4l5u0r** in
the replatform `f1c5511`, 2024-12-03) but no check was ever wired into the dispatcher.
The April 2026 reorganization (`93d496a`, **dbaranov-hoodies**) rewrote `handler.c` into
`dispatcher.c` and carried the omission forward.

<a id="qb-18-1"></a>
## QB-18/1 — Insufficient fuzzing coverage across APDU handlers

Rewrote the fuzzing infrastructure so all 19 APDU handler fuzz targets compile the real
handler source files rather than re-implementing simplified logic inline. Changes:

- Rewrote `fuzzing/CMakeLists.txt` with a `SHARED_SOURCES` list (all helpers) and an
  `add_fuzz_target()` function that links each target against its real handler `.c` file.
- Created `fuzzing/stubs/` — a thin Ledger SDK stub layer (`cx_sha256_init`,
  `os_perso_derive_node_bip32`, `get_private_key`, etc. as no-ops) so harnesses compile
  without the full Ledger SDK toolchain.
- Rewrote all 19 fuzzer `.c` files as thin harnesses: input bytes are unpacked into a
  `command_t` and the real handler is called; `setjmp`/`longjmp` intercepts `THROW`
  exceptions so the harness terminates cleanly instead of crashing the process.
- Added `fuzzing/run_local.sh`: builds the suite, runs each target for a configurable
  duration, accumulates corpus in `fuzzing/corpus/`, and reports any crashes.

Running the harnesses for one minute each immediately found two previously unknown
memory-safety bugs in production handler code (QB-18/2, QB-18/3) that the old stub-based
fuzzers could not have detected.

**Root cause:** The `fuzzing/` directory (last restructured `93d496a`, **dbaranov-hoodies**,
2026-04-08) contained 19 targets, but each re-implemented a simplified copy of its handler's
logic rather than calling the real handler. Any memory-safety violation in the actual source
was invisible to the fuzzer.

<a id="qb-18-2"></a>
## QB-18/2 — Global-buffer-overflow in export-private-key display (memmove overread)

Changed all `memmove(ctx->display_sign_verb, "...", EXPORT_PRIVATE_KEY_SIGN_VERB_LEN)` and
`memmove(ctx->display_review_verb, "...", EXPORT_PRIVATE_KEY_REVIEW_VERB_LEN)` calls in
`export_private_key_legacy_path.c` (3 switch cases) and `export_private_key_new_path.c`
(5 switch cases) to use `sizeof("literal")` as the copy length.

`EXPORT_PRIVATE_KEY_SIGN_VERB_LEN` is defined as 25 — the buffer capacity of
`display_sign_verb`, sized for the longest string `"to discover credentials?"` (24 bytes
+ NUL). When a shorter string such as `"to create credentials?"` (23 bytes) is copied with
count 25, `memmove` reads one byte past the end of that string literal in the rodata
section, triggering a global-buffer-overflow. The same applies to
`EXPORT_PRIVATE_KEY_REVIEW_VERB_LEN` (24) against shorter review-verb strings. On the
device the overread byte is adjacent rodata (typically the NUL of the next literal) and
the display field appears correct, hiding the defect entirely.

**Root cause:** Both handler files were restructured by **dbaranov-hoodies** (`93d496a`,
2026-04-08). The `EXPORT_PRIVATE_KEY_SIGN_VERB_LEN` / `EXPORT_PRIVATE_KEY_REVIEW_VERB_LEN`
constants were introduced as buffer-size annotations on the destination array, but were
accidentally reused as the `memmove` byte-count argument for every string regardless of
its actual length.

<a id="qb-18-3"></a>
## QB-18/3 — Heap-buffer-overflow in `sign_configure_delegation` via stale dataLength

Introduced `uint8_t remaining = dataLength - keyDerivationPathLength` immediately after
advancing `cdata` past the derivation path in `handle_sign_configure_delegation`, and
passed `remaining` (not the original `dataLength`) to `hashAccountTransactionHeaderAndKind`
and its subsequent length checks.

`hashAccountTransactionHeaderAndKind` calls `base58check_encode(cdata, ADDRESS_LENGTH, …)`
which reads exactly 32 bytes. The function checks `if (dataLength < ADDRESS_LENGTH)` before
that call (QB-13 fix), but `dataLength` had not been reduced by `keyDerivationPathLength`,
so the guard passed even when only a few bytes of actual payload remained after the path,
and `base58check_encode` read past the end of the heap-allocated input buffer:

```
ERROR: AddressSanitizer: heap-buffer-overflow … READ of size 32
    #0 __asan_memmove … base58check.c:43
    #1 hashAccountTransactionHeaderAndKind … tx_hash.c:53
    #2 handle_sign_configure_delegation … sign_configure_delegation.c:42
```

Every other handler calling `hashAccountTransactionHeaderAndKind` (`sign_transfer.c`,
`sign_configure_baker.c`, etc.) first subtracts the path length and passes the reduced
value; only `sign_configure_delegation` passed the original `dataLength`.

**Root cause:** `handle_sign_configure_delegation` was written from scratch by **Jakob Ørhøj**
(`cfcbb47`, 2022-01-17, *"Add support for configure delegation transaction"*). The
remaining-data pattern used in every other handler was simply not applied — `dataLength`
was passed to `hashAccountTransactionHeaderAndKind` without accounting for the bytes
already consumed by the derivation path. The omission was carried forward through the
April 2026 reorganisation (`93d496a`, **dbaranov-hoodies**) unchanged.
