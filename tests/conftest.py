"""
Pytest configuration for the whole ``tests/`` tree.

Must live here (not only under ``standalone/``) so ``pytest tests/`` registers
Ragger's ``--device`` (and other) options. The Ledger VS Code extension often
invokes that path; without this file, ``--device`` is unrecognized.
"""
import os

import pytest
from ragger.conftest import configuration

###########################
### CONFIGURATION START ###
###########################


# Define pytest markers
def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "active_test_scope: marks tests related to application name functionality",
    )
    # Add more markers here as needed


#########################
### CONFIGURATION END ###
#########################


def pytest_runtest_logreport(report):
    if report.skipped and os.getenv("CI"):
        skip_reason = report.longrepr[2] if isinstance(report.longrepr, tuple) else str(report.longrepr)
        report.outcome = "failed"
        report.longrepr = f"Unexpected skip in CI: {skip_reason}"

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest",)
