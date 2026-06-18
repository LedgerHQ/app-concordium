# Tests

Functional (Ragger) tests live under **`tests/standalone/`**, matching the layout used by [Ledger’s C app-boilerplate](https://github.com/LedgerHQ/app-boilerplate).

- **Install:** `pip install -r tests/requirements.txt` (includes [`standalone/requirements.txt`](standalone/requirements.txt)).
- **Run:** `pytest tests/standalone/ --tb=short -v --device nanosp`
- **Details:** [tests/standalone/README.md](standalone/README.md)

Pytest config (`setup.cfg`) and Ragger hook (`conftest.py`) live under **`tests/`**, not only under `standalone/`, so `rootdir` stays `tests/` and `--device` is always registered when you pass `tests/` or `tests/standalone/` on the command line.
