# Protocol proposal: display fee separate from energy (host extension)

This document proposes a **backward-compatible** extension to the Ledger ↔ host APDU contract so the device can show an **estimated or maximum fee in micro-CCD (µCCD)** that is **not** conflated with the chain’s **`energy_amount`** field in the signed transaction header.

**Status:** **Implemented** in app **5.5.2+** (UI labels **5.5.3** — **Max fees**, no energy line; **GET_APP_VERSION** without capabilities byte from **5.5.4**). Hosts infer fee-display support from **semantic version** + docs — see `src/helpers/fee_display.h` and the `P2=0x01` rows in [ins_transfer.md](ins_transfer.md) / [ins_transfer_with_schedule.md](ins_transfer_with_schedule.md).

---

## 1. Problem

- In the **canonical Concordium account transaction**, the header contains **`energy_amount`**: a limit on **execution energy**, in **chain energy units**. It is **not** an amount of CCD.
- Actual **fees** charged on-chain depend on **energy used**, **energy price**, and protocol rules. Wallets typically compute a **fee estimate in µCCD** off-device.
- Today the app may present the energy field using **amount-style formatting** intended for µCCD, which is **misleading** (“max fees” vs energy).

**Requirement:** Let the host send a **separate, explicit fee value for display**, without changing what the node verifies (the **hash must remain over the canonical serialization only**).

---

## 2. Design constraints

| Constraint | Implication |
| ---------- | ----------- |
| **Signing / hashing** | Every byte included in the **Ed25519 hash** must stay **bit-for-bit** the same as today’s Concordium serialization. No extra fields inside the signed blob. |
| **Trust model** | A display-only fee is **asserted by the host** (wallet). The device **does not** recompute it from chain state. The user should treat it as **wallet-provided** (on-device label: **“Max fees”**). |
| **Compatibility** | **P2 = `0x00`** (or absence of extension) keeps **current** CDATA layout and behavior. |
| **APDU size** | `Lc ≤ 255`; any extension must fit in **one APDU** per step or use an agreed multi-frame rule consistent with existing chunked flows. |

---

## 3. Proposed extension (summary)

Use **`P2`** on affected **INS** values to mean:

| `P2` | Meaning |
| ---- | ------- |
| `0x00` | **Legacy:** CDATA is exactly as documented today. No fee display field. |
| `0x01` | **Fee display present:** after the **same** CDATA as legacy (path + canonical payload for that command/step), CDATA **ends with** an extra **`uint64`** big-endian: **`display_fee_microccd`**. |

**Hashing rule:** The firmware feeds **only** the legacy CDATA prefix into the transaction hash (same bytes as today). The **trailing 8 bytes** are parsed **only** for UI (and possibly a sanity check on `Lc`), **never** passed to `update_hash`.

**Semantics of `display_fee_microccd`:**

- **Units:** µCCD (same as transfer amounts in existing docs).
- **Meaning (on-device label):** **“Max fees”** for the wallet-provided µCCD value.
- **Optional sentinel:** reserve **`0xFFFFFFFFFFFFFFFF`** to mean **“do not show a separate fee line”** (legacy UI), if implementers want an explicit “omit” without switching `P2`.

---

## 4. CDATA layout (per command family)

The **legacy prefix** is whatever is specified today for that **INS / P1** step (derivation path + transaction bytes, or chunked memo payload, etc.). The **extension** is always:

```text
… (legacy prefix as today) … || display_fee_microccd [uint64, big-endian]
```

when **`P2 == 0x01`**.

### 4.1 Simple transfer (`INS_SIGN_TRANSFER`, `0x02`)

- **Legacy:** `path` + full serialized simple transfer (header + kind + recipient + amount).
- **Extended (`P2=0x01`):** same, then **8 bytes** `display_fee_microccd`.
- **Firmware:** hash **only** the legacy portion; **do not** show header **`energy_amount`** on the device; if `P2=0x01` and sentinel not used, show **`display_fee_microccd`** as **“Max fees”**.

### 4.2 Transfer with memo (`INS_SIGN_TRANSFER_WITH_MEMO`, `0x32`)

- **Recommended:** carry **`display_fee_microccd` only on the first APDU** (`P1` initial), after `memo_length`, so the user sees fee before memo chunks. **Later** `P1` steps unchanged; **`P2`** must be consistent with the first packet (or `P2=0x00` on follow-ups if fee was already stored in flow state — implementer choice; simplest rule: **same `P2` on all steps of one flow**, fee bytes **only** on initial).
- **Hashing:** unchanged from today; trailing 8 bytes on the **initial** command are not hashed.

*(Exact P1 numbering should match `doc/ins_transfer.md` / firmware once aligned.)*

### 4.3 Other account-transaction instructions

Any handler that parses **`ACCOUNT_TRANSACTION_HEADER_LENGTH`** and hashes the same bytes as today can adopt the **same `P2` convention** on its **first** (or single) command that carries the header, with a short addition to that instruction’s doc:

- Transfer with schedule / with memo variants  
- Deploy module, init/update contract, register data, configure baker/delegation, etc.

Each needs a one-line note: **legacy CDATA length** vs **extended = legacy + 8** when `P2=0x01`.

---

## 5. Validation rules (firmware)

1. If **`P2 == 0x01`**, require **`Lc == legacy_length + 8`** (for that command/step); else **`SWO_WRONG_DATA_LENGTH`** (or existing invalid-param SW).
2. If **`P2 == 0x00`**, require **`Lc == legacy_length`**; reject extra bytes if strict (recommended) to avoid ambiguous clients.
3. **Never** include the trailing 8 bytes in **`cx_sha256` / transaction hash** input.
4. **Display:** do not show **`energy_amount`**; show **`display_fee_microccd`** as **“Max fees”** only when `P2=0x01` and value is not the optional omit sentinel.

---

## 6. Host (wallet) responsibilities

1. Compute **`display_fee_microccd`** with the **same** model the wallet shows pre-sign (max fee / estimate).
2. Send **`P2=0x01`** only when using a firmware build that advertises support (see §7).
3. Keep **canonical transaction bytes** identical to what is submitted to the network.

---

## 7. Capability / versioning

To avoid sending **`P2=0x01`** to old firmware:

- **Option A (not used here):** Extend **GET_APP_VERSION** or add **GET_CAPABILITIES** with a **bit** for “fee display extension”. This firmware keeps **GET_APP_VERSION** to **major/minor/patch** only.
- **Option B:** Document a **minimum app version** in the wallet that enables the new `P2` path.

Until then, hosts **must** use **`P2=0x00`**.

---

## 8. Documentation and tests

- Update the relevant **`doc/ins_*.md`** files with a **“Fee display (`P2=0x01`)”** subsection and exact **Lc** formulas.
- Add **standalone tests** that send **`P2=0x01`** and assert the correct string appears in snapshots / golden runs.

---

## 9. Rationale for trailing bytes + `P2` (vs alternatives)

| Alternative | Drawback |
| ----------- | -------- |
| Encode fee inside the signed transaction | **Breaks** Concordium serialization and verification. |
| Replace energy display with fee only | Hides **energy limit** on the device (accepted here: host/wallet can show energy elsewhere). |
| New INS only for “set fee string” | Extra round-trips and session state; easier to get out of sync with the sign flow. |
| **Trailing unhashed `uint64` + `P2`** | One flag, minimal change, clear hash boundary, easy to document per command. |

---

## 10. Open points

- Whether **`P2=0x01`** on memo follow-up APDUs is **ignored** or **must match** initial (recommended: **match initial `P2`**, fee only on first CDATA).
- Interaction with **multi-signature or future** chunked headers (if any).

---

## See also

- [ins_transfer.md](ins_transfer.md) — current transfer CDATA layout  
- [APDU.md](APDU.md) — global APDU limits  
