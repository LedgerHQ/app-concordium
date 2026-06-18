# Functional tests (Ragger)

Tests use [Ragger](https://github.com/LedgerHQ/ragger) with Speculos. Shared setup is in **[`tests/conftest.py`](../conftest.py)** (parent of `standalone/`), which extends `ragger.conftest.base_conftest` so `pytest tests/` still registers `--device`.

## Prerequisites

1. **Python dependencies** (from the repository root):

   ```shell
   pip install -r tests/requirements.txt
   ```

   (Equivalent: `pip install -r tests/standalone/requirements.txt`.)

2. **Built application ELF** for the device you will emulate. Example for Nano S+:

   ```shell
   export BOLOS_SDK=/path/to/ledger-secure-sdk
   make DEBUG=1 COIN=CCD
   ```

   Use the same `TARGET` (or `$BOLOS_SDK/.target`) as when you run pytest so Speculos loads the matching binary under `build/<target>/bin/app.elf`.

## Choosing the device (`--device`)

Ragger selects the Speculos model with **`--device`**. Common values include:

| Flag example   | Typical use        |
|----------------|--------------------|
| `--device nanosp` | Nano S+ (`nanos2` build output) |
| `--device nanox`  | Nano X             |
| `--device stax`   | Stax               |

Run the full suite:

```shell
pytest tests/standalone/ --tb=short -v --device nanosp
```

Run a single file:

```shell
pytest tests/standalone/test_verify_address.py --tb=short -v --device nanosp
```

Exact device names follow your **Ragger version**; see `pytest --help` and [Ragger documentation](https://ledgerhq.github.io/ragger/) if a name is rejected.

## Screen snapshots (golden run)

UI tests compare screenshots to committed reference images. When intentional UI changes require **updating** those references, use Ragger’s golden run flow (see also the root [README](../README.md) “Useful commands”):

```shell
pytest tests/standalone/test_verify_address.py --tb=short -v --device nanosp --golden_run -s
```

Use this only when the new screenshots are correct; then commit the updated snapshot artifacts as usual for your team’s workflow.

## Trusted Name (PKI) tests

Tests that exercise **SET_TRUSTED_NAME** with the Speculos **test** PKI signer need the app built with **`TRUSTED_NAME_TEST_KEY`**:

- **`make DEBUG=1 COIN=CCD`**, or
- **`make ENABLE_TRUSTED_NAME_TEST_KEY=1 COIN=CCD`** (e.g. CI without full `DEBUG`).

**Note:** `export DEBUG=1` alone is **not** enough: the SDK Makefile sets `DEBUG` in a way that overrides the environment; pass **`DEBUG=1` on the `make` command line**.

If the app is built without that key (release-style), PKI-related tests **skip** automatically.

## Further reading

- Main repository instructions: [README.md](../../README.md) (Test section, Docker, Ledger VS Code extension).
- Application specification: [APP_SPECIFICATION.md](../../APP_SPECIFICATION.md).
