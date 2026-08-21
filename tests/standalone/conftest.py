from ragger.conftest import configuration

###########################
### CONFIGURATION START ###
###########################

# One fresh speculos instance per test function — prevents screen state
# from a previous test (e.g. a PLT review screen) from leaking into the
# first snapshot of the next test.
configuration.OPTIONAL.BACKEND_SCOPE = "function"

#########################
### CONFIGURATION END ###
#########################

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest",)
