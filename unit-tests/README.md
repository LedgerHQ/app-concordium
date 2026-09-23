# Host unit tests

Host-compiled tests for the parsing and display helpers, run by
[`.github/workflows/unit_tests.yml`](../.github/workflows/unit_tests.yml) on every push and
pull request.

They exist because that workflow had its `push` and `pull_request` triggers commented out and
pointed at a `unit-tests/` directory that did not exist on this branch, so nothing gated a
change to security-sensitive parsing code (finding V-116).

## Running them

```sh
cd unit-tests
export BOLOS_SDK=/path/to/ledger-secure-sdk
cmake -Bbuild -H. && make -C build && make -C build test
```

Or in the CI image, from the repository root:

```sh
docker run --rm -v "$PWD":/app -v /path/to/ledger-secure-sdk:/sdk:ro -w /app \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest \
  bash -lc 'cd unit-tests && BOLOS_SDK=/sdk cmake -Bbuild -H. && make -C build && make -C build test'
```

A single suite can be run directly for verbose output: `./build/test_time`.

## What is covered

| File | Finding | What it pins down |
| --- | --- | --- |
| `test_display_text.c` | V-004, V-025 | An embedded NUL or C0 control in host text is refused, so signed bytes cannot be hidden past the end of a displayed string |
| `test_cbor_data_blob.c` | V-077, V-100, V-104 | Non-canonical CBOR arguments and trailing bytes after an integer are refused **by status word**, and a number and a text value do not review identically |
| `test_time.c` | V-070 | A scheduled release time shows milliseconds, always three digits, so 1 ms and 100 ms are distinguishable |
| `test_derivation_path.c` | V-057, V-029 | Mainnet and testnet never review identically, an unknown coin type is not assumed to be mainnet, and every path node is shown hardened |

## How it is wired

- **The host stubs are [`../fuzzing/stubs/`](../fuzzing/stubs/), not a second copy.** Those
  already shadow every SDK header these helpers include and define the app globals, and they
  are exercised on every CI fuzz build, so a divergence from the app surfaces quickly. A
  private set here would be a second thing to keep in step with the SDK — and the one built
  only by a workflow nobody watches is the one that rots.
- **`-funsigned-char -fshort-enums`** match what the SDK applies to the device build. Without
  them a state enum is four bytes here and one on device, and the tests would be checking a
  struct layout the device never runs. The `_Static_assert`s in `src/instruction_context.h`
  (finding V-103) fail the build outright if the flags are ever dropped.
- **`throw_harness.h`** puts a `setjmp` in place before code that can `THROW`. `THROW` is
  `os_longjmp`; without a landing pad it would jump through an uninitialised buffer. The
  macros also let a test state *how* an input is refused — by status word, or by an exception
  that on device would have ended the session — which is the distinction finding V-006 was
  about.

## Adding a test

Add `test_<name>.c` with a `main()` that calls `cmocka_run_group_tests`, then one line in
[`CMakeLists.txt`](CMakeLists.txt):

```cmake
add_unit_test(test_<name>)
```

Prefer the pure helpers under `src/helpers/`. A handler pulls in the UI and APDU layers, which
are stubbed to no-ops; the fuzz harness covers those paths with the real dispatcher instead
(see [`../fuzzing/`](../fuzzing/)).
