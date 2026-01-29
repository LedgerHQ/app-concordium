import pytest
from application_client.boilerplate_command_sender import BoilerplateCommandSender
from application_client.boilerplate_response_unpacker import (
    unpack_get_app_name_response,
)
from utils import verify_version


# In this test we check that the GET_APP_NAME replies the application name
@pytest.mark.active_test_scope
def test_app_version(backend):
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)
    # Send the GET_APP_NAME instruction to the app
    response = client.get_app_version()
    # Assert that we have received the correct appname

    verify_version(response)
