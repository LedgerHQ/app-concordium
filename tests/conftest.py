"""
Pytest configuration for the whole ``tests/`` tree.

Must live here (not only under ``standalone/``) so ``pytest tests/`` registers
Ragger's ``--device`` (and other) options. The Ledger VS Code extension often
invokes that path; without this file, ``--device`` is unrecognized.
"""
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

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest",)
