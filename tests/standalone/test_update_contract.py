import pytest

from application_client.command_sender import CommandSender

from application_client.response_unpacker import (
    unpack_get_public_key_response,
)
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.error import ExceptionRAPDU, StatusWords
from ragger.navigator import NavInsID, NavIns
from utils import navigate_until_text_and_compare, instructions_builder


@pytest.mark.active_test_scope
def test_update_contract(
    backend, navigator, test_name, default_screenshot_path
):
    client = CommandSender(backend)
    path = "m/1105/0/0/0/0/2/0/0"
    header_and_type = bytes.fromhex(
        "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7000000000000000a0000000000000064000000290000000063de5da702"
    )
    amount = 0xFFFFFFFFFFFFFFFF
    index = bytes.fromhex("00000000000004d2")
    sub_index = bytes.fromhex("000000000000162e")
    name = bytes.fromhex("696e69745f5465737420436f6e7472616374")
    params = bytes.fromhex("0102030405060708090a")

    with client.update_contract(
        path=path,
        header_and_type=header_and_type,
        amount=amount,
        index=index,
        sub_index=sub_index,
        name=name,
        params=params,
    ):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    response = client.get_async_response()
    print(response.data.hex())
    assert response.status == StatusWords.SWO_SUCCESS
    assert response.data == bytes.fromhex(
        "3c3d5a49e157b35b64f78677622f8c0a6bbe1a1864668006c8d432471e3d9e5df73e478e005db93c3986d6805b7d498f52b400099cc9034041d799f237703402"
    )


@pytest.mark.active_test_scope
def test_update_contract(
    backend, navigator, test_name, default_screenshot_path
):
    client = CommandSender(backend)
    path = "m/1105/0/0/0/0/2/0/0"
    header_and_type = bytes.fromhex(
        "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7000000000000000a0000000000000064000000290000000063de5da702"
    )
    amount = 0xFFFFFFFFFFFFFFFF
    index = bytes.fromhex("00000000000004d2")
    sub_index = bytes.fromhex("000000000000162e")
    name = "This is the name of the smart contract i am making it way longer than it was before for testing purposes of course".encode(
        "utf-8"
    )
    name = bytes.fromhex(name.hex())
    params = bytes.fromhex(
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    )

    with client.update_contract(
        path=path,
        header_and_type=header_and_type,
        amount=amount,
        index=index,
        sub_index=sub_index,
        name=name,
        params=params,
    ):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    response = client.get_async_response()
    print(response.data.hex())
    assert response.status == StatusWords.SWO_SUCCESS
    assert response.data == bytes.fromhex(
        "79fc02f2d8afcb292bbcc3516db304b7ac628fe9b16379d75a0287eed7dc6909602782f25b02d4be44165bb2ea00ab5f4473b10847469f04ec9867f4e421b00a"
    )


# The entrypoint name is hashed into the signed transaction but rendered as a C string. Same
# gate as init_contract and the baker metadata URL; see test_init_contract.py for the reasoning.
SW_INVALID_TRANSACTION = 0x6B04

_NAME_TEST_PATH = "m/1105/0/0/0/0/2/0/0"
_NAME_TEST_HEADER = bytes.fromhex(
    "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7"
    "000000000000000a0000000000000064000000290000000063de5da702"
)


def _expect_update_contract_refused(client: CommandSender, name: bytes) -> None:
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.update_contract(
            path=_NAME_TEST_PATH,
            header_and_type=_NAME_TEST_HEADER,
            amount=1,
            index=bytes.fromhex("00000000000004d2"),
            sub_index=bytes.fromhex("000000000000162e"),
            name=name,
            params=bytes.fromhex("0102"),
        ):
            pass
    assert exc.value.status == SW_INVALID_TRANSACTION


@pytest.mark.active_test_scope
def test_update_contract_rejects_name_with_embedded_nul(backend):
    """``transfer\\0<more>`` would review as ``transfer`` while the signature covered the rest.

    This is the entrypoint being invoked, so a disguised name is a disguised method call.
    """
    client = CommandSender(backend)
    _expect_update_contract_refused(client, b"transfer\x00_drain_wallet")


@pytest.mark.active_test_scope
def test_update_contract_rejects_name_with_control_character(backend):
    """C0 controls have no faithful rendering either, so they are refused, not drawn."""
    client = CommandSender(backend)
    _expect_update_contract_refused(client, b"transfer\x0b_drain_wallet")


@pytest.mark.active_test_scope
def test_update_contract_rejects_nul_in_a_later_name_chunk(backend):
    """The multi-packet case a strlen() write cursor got wrong; see test_init_contract.py."""
    client = CommandSender(backend)
    name = b"transfer_" + b"a" * 250 + b"\x00" + b"b" * 50
    _expect_update_contract_refused(client, name)
