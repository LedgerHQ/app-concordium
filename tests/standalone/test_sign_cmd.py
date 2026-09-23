import pytest

from application_client.command_sender import CommandSender
from application_client.response_unpacker import (
    unpack_get_public_key_response,
    unpack_sign_tx_response,
)
from ragger.error import ExceptionRAPDU, StatusWords
from ragger.navigator import NavInsID
from utils import (
    navigate_until_text_and_compare,
    instructions_builder,
    screenshots_taken_so_far,
    split_message,
)

MAX_SCHEDULE_PAIRS_IN_ONE_APDU: int = (250 // 16) * 16
MAX_APDU_LEN: int = 255

# µCCD value appended when P2=0x01 (display-only; not hashed). Signature must match the
# corresponding test without a fee for the same transaction payload.
TEST_DISPLAY_FEE_MICROCCD = 123_456_798

# Concordium-specific status word: the app refuses a transaction it cannot display faithfully.
SW_INVALID_TRANSACTION = 0x6B04


# In this test we send to the device a transaction to sign and validate it on screen
# The transaction is short and will be sent in one chunk
# We will ensure that the displayed information is correct by using screenshots comparison
@pytest.mark.active_test_scope
def test_sign_tx_simple_transfer_legacy_path(
    backend, navigator, default_screenshot_path, test_name
):
    # Use the app interface instead of raw interface
    client = CommandSender(backend)
    # The path used for this entire test
    path: str = "m/1105/0/0/0/0/2/0/0"

    # Create the transaction that will be sent to the device for signing
    transaction = "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7000000000000000a0000000000000064000000290000000063de5da70320a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7ffffffffffffffff"
    transaction = bytes.fromhex(transaction)

    # Send the sign device instruction.
    # As it requires on-screen validation, the function is asynchronous.
    # It will yield the result when the navigation is done
    with client.sign_simple_transfer(path=path, transaction=transaction):
        # Validate the on-screen request by performing the navigation appropriate for this device
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )

    # The device as yielded the result, parse it and ensure that the signature is correct
    response = client.get_async_response().data
    response_hex = response.hex()
    print("response", response_hex)
    assert (
        response_hex
        == "d1617ee706805c0bc6a43260ece93a7ceba37aaefa303251cf19bdcbbe88c0a3d3878dcb965cdb88ff380fdb1aa4b321671f365d7258e878d18fa1b398a1a10f"
    )
    # assert check_signature_validity(public_key, der_sig, transaction)


@pytest.mark.active_test_scope
def test_sign_tx_simple_transfer_legacy_path_with_display_fee(
    backend, navigator, default_screenshot_path, test_name
):
    """P2=0x01 + trailing display fee (µCCD); fee is not hashed — same signature as without fee."""
    client = CommandSender(backend)
    path: str = "m/1105/0/0/0/0/2/0/0"
    transaction = "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7000000000000000a0000000000000064000000290000000063de5da70320a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7ffffffffffffffff"
    transaction = bytes.fromhex(transaction)

    with client.sign_simple_transfer(
        path=path,
        transaction=transaction,
        display_fee_microccd=TEST_DISPLAY_FEE_MICROCCD,
    ):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )

    response = client.get_async_response().data
    assert (
        response.hex()
        == "d1617ee706805c0bc6a43260ece93a7ceba37aaefa303251cf19bdcbbe88c0a3d3878dcb965cdb88ff380fdb1aa4b321671f365d7258e878d18fa1b398a1a10f"
    )


# In this test we send to the device a transaction to sign and validate it on screen
# The transaction is short and will be sent in one chunk
# We will ensure that the displayed information is correct by using screenshots comparison
@pytest.mark.active_test_scope
def test_sign_tx_simple_transfer_new_path(
    backend, navigator, default_screenshot_path, test_name
):
    # Use the app interface instead of raw interface
    client = CommandSender(backend)
    # The path used for this entire test
    path: str = "m/44/919/0/0/0/0"

    # Create the transaction that will be sent to the device for signing
    transaction = "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7000000000000000a0000000000000064000000290000000063de5da70320a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7ffffffffffffffff"
    transaction = bytes.fromhex(transaction)

    # Send the sign device instruction.
    # As it requires on-screen validation, the function is asynchronous.
    # It will yield the result when the navigation is done
    with client.sign_simple_transfer(path=path, transaction=transaction):
        # Validate the on-screen request by performing the navigation appropriate for this device
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )

    # The device as yielded the result, parse it and ensure that the signature is correct
    response = client.get_async_response().data
    response_hex = response.hex()
    print("response", response_hex)
    assert (
        response_hex
        == "e5f112237d58f908c44385827e71048869db7e8f513e2ceb5da6a6370e2088f4371f93d6e08f9f6c1dd92c74fe565727b8f81600541e817d35cfeec4cc3bc408"
    )


# Same transaction as above on the testnet coin type (44'/1'). Mainnet and testnet account
# addresses are encoded identically, so the "Network" review row is the only thing that
# distinguishes the two flows on screen; the snapshots assert it says Testnet here and Mainnet
# in the test above.
@pytest.mark.active_test_scope
def test_sign_tx_simple_transfer_new_path_testnet(
    backend, navigator, default_screenshot_path, test_name
):
    client = CommandSender(backend)
    path: str = "m/44/1/0/0/0/0"

    transaction = "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7000000000000000a0000000000000064000000290000000063de5da70320a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7ffffffffffffffff"
    transaction = bytes.fromhex(transaction)

    with client.sign_simple_transfer(path=path, transaction=transaction):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )

    response = client.get_async_response()
    assert response.status == StatusWords.SWO_SUCCESS
    # A testnet path must not produce the mainnet signature for the same payload.
    assert (
        response.data.hex()
        != "e5f112237d58f908c44385827e71048869db7e8f513e2ceb5da6a6370e2088f4371f93d6e08f9f6c1dd92c74fe565727b8f81600541e817d35cfeec4cc3bc408"
    )


# In this test we send to the device a transaction to sign and validate it on screen
# The transaction is short and will be sent in one chunk
# We will ensure that the displayed information is correct by using screenshots comparison
@pytest.mark.active_test_scope
def test_sign_tx_simple_transfer_with_memo_legacy_path(
    backend, navigator, default_screenshot_path, test_name
):
    # Use the app interface instead of raw interface
    client = CommandSender(backend)
    # The path used for this entire test
    path: str = "m/1105/0/0/0/0/2/0/0"

    # Create the transaction that will be sent to the device for signing
    header_and_to_address = "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7000000000000000a0000000000000064000000290000000063de5da71620a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7"
    header_and_to_address = bytes.fromhex(header_and_to_address)

    memo_payload = (
        "The quick brown fox jumps over the lazy dog. Pack my box with five dozen "
        "liquor jugs. Jackdaws love my big sphinx of quartz. Quick zephyrs blow, "
        "vexing daft Jim. Sphinx of black quartz, judge my vow. How quickly daft "
        "jumping zebras vex!"
    )

    payload_bytes = memo_payload.encode("utf-8")
    memo = bytes([0x78, len(memo_payload)]) + payload_bytes
    # memo = bytes.fromhex(memo)
    amount = "ffffffffffffffff"
    amount = bytes.fromhex(amount)

    # Send the sign device instruction.
    # As it requires on-screen validation, the function is asynchronous.
    # It will yield the result when the navigation is done
    with client.sign_simple_transfer_with_memo(
        path=path,
        header_and_to_address=header_and_to_address,
        memo=memo,
        amount=amount,
    ):
        # Validate the on-screen request by performing the navigation appropriate for this device
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )

    # The device as yielded the result, parse it and ensure that the signature is correct
    response = client.get_async_response().data
    response_hex = response.hex()
    print("response", response_hex)
    assert (
        response_hex
        == "6c0b0ada297d35d79a76df87b30c4ae3c9b29fdfe5647e56ea3f9c1334366bfb942716dc4d236395ffaee5a4671b90118c28295cc12094cb7188a8354e92f600"
    )
    # assert check_signature_validity(public_key, der_sig, transaction)


@pytest.mark.active_test_scope
def test_sign_tx_simple_transfer_with_memo_legacy_path_with_display_fee(
    backend, navigator, default_screenshot_path, test_name
):
    """P2=0x01 on first memo packet; display fee bytes are not hashed."""
    client = CommandSender(backend)
    path: str = "m/1105/0/0/0/0/2/0/0"

    header_and_to_address = "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7000000000000000a0000000000000064000000290000000063de5da71620a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7"
    header_and_to_address = bytes.fromhex(header_and_to_address)

    memo_payload = (
        "The quick brown fox jumps over the lazy dog. Pack my box with five dozen "
        "liquor jugs. Jackdaws love my big sphinx of quartz. Quick zephyrs blow, "
        "vexing daft Jim. Sphinx of black quartz, judge my vow. How quickly daft "
        "jumping zebras vex!"
    )

    payload_bytes = memo_payload.encode("utf-8")
    memo = bytes([0x78, len(memo_payload)]) + payload_bytes
    amount = bytes.fromhex("ffffffffffffffff")

    with client.sign_simple_transfer_with_memo(
        path=path,
        header_and_to_address=header_and_to_address,
        memo=memo,
        amount=amount,
        display_fee_microccd=TEST_DISPLAY_FEE_MICROCCD,
    ):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )

    response = client.get_async_response().data
    assert (
        response.hex()
        == "6c0b0ada297d35d79a76df87b30c4ae3c9b29fdfe5647e56ea3f9c1334366bfb942716dc4d236395ffaee5a4671b90118c28295cc12094cb7188a8354e92f600"
    )


@pytest.mark.active_test_scope
def test_sign_tx_transfer_with_schedule_legacy_path(
    backend, navigator, default_screenshot_path, test_name
):
    # Initialize the command sender client
    client = CommandSender(backend)
    # Define the path for the transaction
    path = "m/1105/0/0/0/0/2/0/0"

    # Create the transaction that will be sent to the device for signing
    header_and_to_address = "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7000000000000000a0000000000000064000000290000000063de5da71320a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7"
    header_and_to_address = bytes.fromhex(header_and_to_address)

    # Define the schedule pairs
    pairs = [
        "0000017a396883d90000000005f5e100",
        "0000017a396883d90000000005f5e100",
        "0000017a396883d90000000005f5e100",
        "0000017a396883d90000000005f5e100",
        "0000017a396883d90000000005f5e100",
    ]
    joined_pairs = bytes.fromhex("".join(pairs))

    # Ensure pairs are a multiple of 16 bytes
    if len(joined_pairs) % 16 != 0:
        raise ValueError("Pairs must be a multiple of 16 bytes")

    # Split the pairs into chunks for APDU transmission
    pairs_chunk = split_message(joined_pairs, MAX_SCHEDULE_PAIRS_IN_ONE_APDU)

    # Send the first part of the transaction signing request

    with client.sign_tx_with_schedule_part_1(
        path=path,
        header_and_to_address=header_and_to_address,
        num_pairs=len(pairs),
    ):
        # Navigate and compare screenshots for validation
        navigate_until_text_and_compare(
            backend,
            navigator,
            "Continue",
            default_screenshot_path,
            test_name,
            True,
            False,
            NavInsID.USE_CASE_CHOICE_CONFIRM,
        )

    # Process each chunk of pairs
    # Resume snapshot numbering where the review above left off. Deriving this rather
    # than hardcoding it per device keeps the pair screens from overwriting the tail of
    # the review whenever a screen is added to or removed from that review.
    screenshots_so_far = screenshots_taken_so_far(
        backend, default_screenshot_path, test_name
    )

    for chunk in pairs_chunk:
        nbgl_confirm_instruction = NavInsID.USE_CASE_CHOICE_CONFIRM
        number_of_pairs_in_chunk = len(chunk) // 16
        # Create the instructions to validate each pair
        instructions = []
        for _ in range(number_of_pairs_in_chunk):
            if _ == number_of_pairs_in_chunk - 1:
                nbgl_confirm_instruction = NavInsID.USE_CASE_REVIEW_CONFIRM
            instructions.extend(
                instructions_builder(2, backend, nbgl_confirm_instruction)
            )

        # Send the second part of the transaction signing request
        with client.sign_tx_with_schedule_part_2(data=chunk):
            # Navigate and compare screenshots for validation
            navigator.navigate_and_compare(
                default_screenshot_path,
                test_name,
                instructions,
                10,
                True,
                True,
                screenshots_so_far,
            )
        screenshots_so_far += number_of_pairs_in_chunk * 3

    # The device as yielded the result, parse it and ensure that the signature is correct
    response = client.get_async_response().data
    response_hex = response.hex()
    assert (
        response_hex
        == "e22fa38f78a79db71e84376c4eec2382166cdc412994207e7631b0ba3828f069b17b6f30351a64c50e5efacec3fe25161e9f7131e0235cd740739b24e0b06308"
    )


@pytest.mark.active_test_scope
def test_sign_tx_transfer_with_schedule_legacy_path_with_display_fee(
    backend, navigator, default_screenshot_path, test_name
):
    """P2=0x01 on schedule part 1; display fee not hashed."""
    client = CommandSender(backend)
    path = "m/1105/0/0/0/0/2/0/0"

    header_and_to_address = "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7000000000000000a0000000000000064000000290000000063de5da71320a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7"
    header_and_to_address = bytes.fromhex(header_and_to_address)

    pairs = [
        "0000017a396883d90000000005f5e100",
        "0000017a396883d90000000005f5e100",
        "0000017a396883d90000000005f5e100",
        "0000017a396883d90000000005f5e100",
        "0000017a396883d90000000005f5e100",
    ]
    joined_pairs = bytes.fromhex("".join(pairs))

    if len(joined_pairs) % 16 != 0:
        raise ValueError("Pairs must be a multiple of 16 bytes")

    pairs_chunk = split_message(joined_pairs, MAX_SCHEDULE_PAIRS_IN_ONE_APDU)

    with client.sign_tx_with_schedule_part_1(
        path=path,
        header_and_to_address=header_and_to_address,
        num_pairs=len(pairs),
        display_fee_microccd=TEST_DISPLAY_FEE_MICROCCD,
    ):
        navigate_until_text_and_compare(
            backend,
            navigator,
            "Continue",
            default_screenshot_path,
            test_name,
            True,
            False,
            NavInsID.USE_CASE_CHOICE_CONFIRM,
        )

    # Resume snapshot numbering where the review above left off. Deriving this rather
    # than hardcoding it per device keeps the pair screens from overwriting the tail of
    # the review whenever a screen is added to or removed from that review.
    screenshots_so_far = screenshots_taken_so_far(
        backend, default_screenshot_path, test_name
    )

    for chunk in pairs_chunk:
        nbgl_confirm_instruction = NavInsID.USE_CASE_CHOICE_CONFIRM
        number_of_pairs_in_chunk = len(chunk) // 16
        instructions = []
        for _ in range(number_of_pairs_in_chunk):
            if _ == number_of_pairs_in_chunk - 1:
                nbgl_confirm_instruction = NavInsID.USE_CASE_REVIEW_CONFIRM
            instructions.extend(
                instructions_builder(2, backend, nbgl_confirm_instruction)
            )

        with client.sign_tx_with_schedule_part_2(data=chunk):
            navigator.navigate_and_compare(
                default_screenshot_path,
                test_name,
                instructions,
                10,
                True,
                True,
                screenshots_so_far,
            )
        screenshots_so_far += number_of_pairs_in_chunk * 3

    response = client.get_async_response().data
    assert (
        response.hex()
        == "e22fa38f78a79db71e84376c4eec2382166cdc412994207e7631b0ba3828f069b17b6f30351a64c50e5efacec3fe25161e9f7131e0235cd740739b24e0b06308"
    )


@pytest.mark.active_test_scope
def test_sign_tx_transfer_with_schedule_and_memo_legacy_path(
    backend, navigator, default_screenshot_path, test_name
):
    # Initialize the command sender client
    client = CommandSender(backend)
    # Define the path for the transaction
    path = "m/1105/0/0/0/0/2/0/0"

    # Create the transaction that will be sent to the device for signing
    header_and_to_address = "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7000000000000000a0000000000000064000000290000000063de5da71820a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7"
    header_and_to_address = bytes.fromhex(header_and_to_address)

    # Define the memo
    memo = "6474657374"  # "test" in hex
    memo = bytes.fromhex(memo)

    memo_chunks = split_message(memo, MAX_APDU_LEN)

    # Define the schedule pairs
    pairs = [
        "0000017a396883d90000000005f5e100",
        "0000017a396883d90000000005f5e100",
        "0000017a396883d90000000005f5e100",
        "0000017a396883d90000000005f5e100",
        "0000017a396883d90000000005f5e100",
    ]
    joined_pairs = bytes.fromhex("".join(pairs))

    # Ensure pairs are a multiple of 16 bytes
    if len(joined_pairs) % 16 != 0:
        raise ValueError("Pairs must be a multiple of 16 bytes")

    # Split the pairs into chunks for APDU transmission
    pairs_chunk = split_message(joined_pairs, MAX_SCHEDULE_PAIRS_IN_ONE_APDU)

    # Send the first part of the transaction signing request
    response = client.sign_tx_with_schedule_and_memo_part_1(
        path=path,
        header_and_to_address=header_and_to_address,
        num_pairs=len(pairs),
        memo_length=len(memo),
    )
    assert response.status == StatusWords.SWO_SUCCESS
    # Send the part with the memo
    for chunk in memo_chunks:
        with client.sign_tx_with_schedule_and_memo_part_2(memo_chunk=chunk):
            navigate_until_text_and_compare(
                backend,
                navigator,
                "Continue",
                default_screenshot_path,
                test_name,
                True,
                False,
                NavInsID.USE_CASE_CHOICE_CONFIRM,
            )

    # Process each chunk of pairs
    # Resume snapshot numbering where the review above left off. Deriving this rather
    # than hardcoding it per device keeps the pair screens from overwriting the tail of
    # the review whenever a screen is added to or removed from that review.
    screenshots_so_far = screenshots_taken_so_far(
        backend, default_screenshot_path, test_name
    )

    for chunk in pairs_chunk:
        nbgl_confirm_instruction = NavInsID.USE_CASE_CHOICE_CONFIRM
        number_of_pairs_in_chunk = len(chunk) // 16
        # Create the instructions to validate each pair
        instructions = []
        for _ in range(number_of_pairs_in_chunk):
            if _ == number_of_pairs_in_chunk - 1:
                nbgl_confirm_instruction = NavInsID.USE_CASE_REVIEW_CONFIRM
            instructions.extend(
                instructions_builder(2, backend, nbgl_confirm_instruction)
            )

        with client.sign_tx_with_schedule_and_memo_part_3(data=chunk):
            navigator.navigate_and_compare(
                default_screenshot_path,
                test_name,
                instructions,
                10,
                True,
                True,
                screenshots_so_far,
            )
        screenshots_so_far += number_of_pairs_in_chunk * 3

    # The device as yielded the result, parse it and ensure that the signature is correct
    response = client.get_async_response().data
    response_hex = response.hex()
    assert (
        response_hex
        == "9056db36dfa7b0ba722660b2becb227ed490dcaff9e332a7fba4c6d534ff0ff3368b21da8e7ebb62891be561261abd7c0435dfb46e596b1116c9996269d2a70b"
    )


@pytest.mark.active_test_scope
def test_sign_tx_transfer_with_schedule_and_memo_legacy_path_with_display_fee(
    backend, navigator, default_screenshot_path, test_name
):
    """P2=0x01 on schedule+memo part 1; display fee not hashed."""
    client = CommandSender(backend)
    path = "m/1105/0/0/0/0/2/0/0"

    header_and_to_address = "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7000000000000000a0000000000000064000000290000000063de5da71820a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7"
    header_and_to_address = bytes.fromhex(header_and_to_address)

    memo = bytes.fromhex("6474657374")

    memo_chunks = split_message(memo, MAX_APDU_LEN)

    pairs = [
        "0000017a396883d90000000005f5e100",
        "0000017a396883d90000000005f5e100",
        "0000017a396883d90000000005f5e100",
        "0000017a396883d90000000005f5e100",
        "0000017a396883d90000000005f5e100",
    ]
    joined_pairs = bytes.fromhex("".join(pairs))

    if len(joined_pairs) % 16 != 0:
        raise ValueError("Pairs must be a multiple of 16 bytes")

    pairs_chunk = split_message(joined_pairs, MAX_SCHEDULE_PAIRS_IN_ONE_APDU)

    response = client.sign_tx_with_schedule_and_memo_part_1(
        path=path,
        header_and_to_address=header_and_to_address,
        num_pairs=len(pairs),
        memo_length=len(memo),
        display_fee_microccd=TEST_DISPLAY_FEE_MICROCCD,
    )
    assert response.status == StatusWords.SWO_SUCCESS

    for chunk in memo_chunks:
        with client.sign_tx_with_schedule_and_memo_part_2(memo_chunk=chunk):
            navigate_until_text_and_compare(
                backend,
                navigator,
                "Continue",
                default_screenshot_path,
                test_name,
                True,
                False,
                NavInsID.USE_CASE_CHOICE_CONFIRM,
            )

    # Resume snapshot numbering where the review above left off. Deriving this rather
    # than hardcoding it per device keeps the pair screens from overwriting the tail of
    # the review whenever a screen is added to or removed from that review.
    screenshots_so_far = screenshots_taken_so_far(
        backend, default_screenshot_path, test_name
    )

    for chunk in pairs_chunk:
        nbgl_confirm_instruction = NavInsID.USE_CASE_CHOICE_CONFIRM
        number_of_pairs_in_chunk = len(chunk) // 16
        instructions = []
        for _ in range(number_of_pairs_in_chunk):
            if _ == number_of_pairs_in_chunk - 1:
                nbgl_confirm_instruction = NavInsID.USE_CASE_REVIEW_CONFIRM
            instructions.extend(
                instructions_builder(2, backend, nbgl_confirm_instruction)
            )

        with client.sign_tx_with_schedule_and_memo_part_3(data=chunk):
            navigator.navigate_and_compare(
                default_screenshot_path,
                test_name,
                instructions,
                10,
                True,
                True,
                screenshots_so_far,
            )
        screenshots_so_far += number_of_pairs_in_chunk * 3

    response = client.get_async_response().data
    assert (
        response.hex()
        == "9056db36dfa7b0ba722660b2becb227ed490dcaff9e332a7fba4c6d534ff0ff3368b21da8e7ebb62891be561261abd7c0435dfb46e596b1116c9996269d2a70b"
    )


@pytest.mark.active_test_scope
def test_sign_tx_memo_rejects_embedded_nul(backend):
    """A memo is hashed in full but rendered as a C string.

    An embedded NUL would end the review at that byte while the signature still covered the
    bytes after it, so the user would approve a memo they never saw. The app must refuse the
    transaction rather than sign data it did not display.
    """
    client = CommandSender(backend)
    path: str = "m/1105/0/0/0/0/2/0/0"
    header_and_to_address = bytes.fromhex(
        "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7000000000000000a00000000000000640000002900000000"
        "63de5da71620a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7"
    )
    # CBOR text string hiding a suffix behind a NUL. The header must be the CANONICAL inline
    # form (0x60 | len) for a length below 24: the one-byte-length form 0x78 is non-canonical
    # and would be refused by the deterministic-encoding check first, which returns the same
    # status word and would make this test pass without ever reaching the NUL check.
    hidden = b"visible\x00hidden"
    memo = bytes([0x60 | len(hidden)]) + hidden

    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_simple_transfer_with_memo(
            path=path,
            header_and_to_address=header_and_to_address,
            memo=memo,
            amount=bytes.fromhex("ffffffffffffffff"),
        ):
            pass
    assert exc.value.status == SW_INVALID_TRANSACTION


@pytest.mark.active_test_scope
def test_sign_tx_memo_rejects_trailing_bytes_after_integer(backend):
    """An integer memo is complete once its argument is read, so no APDU byte may follow it.

    The device previously tracked only the protocol-declared CBOR length, so a host could
    declare a 3-byte memo and send {0x05, 0xAA, 0xBB}: the review showed integer 5 while
    0xAA 0xBB stayed in the signed transaction hash.
    """
    client = CommandSender(backend)
    path: str = "m/1105/0/0/0/0/2/0/0"
    header_and_to_address = bytes.fromhex(
        "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7000000000000000a00000000000000640000002900000000"
        "63de5da71620a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7"
    )
    # 0x05 is the whole CBOR item (unsigned integer 5); 0xAA 0xBB are trailing bytes.
    memo = bytes([0x05, 0xAA, 0xBB])

    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_simple_transfer_with_memo(
            path=path,
            header_and_to_address=header_and_to_address,
            memo=memo,
            amount=bytes.fromhex("ffffffffffffffff"),
        ):
            pass
    assert exc.value.status == SW_INVALID_TRANSACTION


@pytest.mark.active_test_scope
def test_sign_tx_memo_rejects_non_canonical_integer(backend):
    """Deterministic CBOR requires the shortest encoding of an argument.

    Integer 1 encodes canonically as 0x01. Accepting 0x1801, 0x190001, 0x1a00000001 and
    0x1b0000000000000001 as well meant five distinct signed byte strings reviewed identically.
    """
    client = CommandSender(backend)
    path: str = "m/1105/0/0/0/0/2/0/0"
    header_and_to_address = bytes.fromhex(
        "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7000000000000000a00000000000000640000002900000000"
        "63de5da71620a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7"
    )
    # 0x18 0x01 is integer 1 in the one-byte-length form; canonical is the inline 0x01.
    memo = bytes([0x18, 0x01])

    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_simple_transfer_with_memo(
            path=path,
            header_and_to_address=header_and_to_address,
            memo=memo,
            amount=bytes.fromhex("ffffffffffffffff"),
        ):
            pass
    assert exc.value.status == SW_INVALID_TRANSACTION


# ------------------------------------------------------------------ #
# Multi-packet memo: intermediate CONT frames                         #
# ------------------------------------------------------------------ #
#
# This PR changed the intermediate memo frame in both memo handlers from
# THROW(ERROR_INVALID_STATE) to send_success_no_idle(), and nothing covered it: every other
# memo case in this file fits a single APDU, so the `cborLength != 0` branch never ran.
#
# The largest memo the protocol allows is MAX_CBOR_BLOB_SIZE = 257 bytes (a 2-byte CBOR
# header plus 255 text bytes), which splits into 255 + 2 -- two frames, so exactly one
# intermediate. Three frames are not reachable: 257 is the cap.
#
# These are deliberately synchronous and take no screenshots. The frame under test answers
# 0x9000 without showing anything, so asserting it needs no navigation and adds no goldens.

_MEMO_PATH = "m/1105/0/0/0/0/2/0/0"
_MEMO_HEADER_TO_ADDRESS = bytes.fromhex(
    "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7"
    "000000000000000a0000000000000064000000290000000063de5da716"
    "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7"
)
# Same 60-byte header, but transaction kind 0x18 (transfer with schedule and memo).
_SCHEDULE_MEMO_HEADER_TO_ADDRESS = bytes.fromhex(
    "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7"
    "000000000000000a0000000000000064000000290000000063de5da718"
    "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7"
)

# CBOR text string of 255 displayable bytes: 0x78 0xFF + payload. 257 bytes total, the
# protocol maximum, so split_message yields 255 + 2.
_MAX_MEMO = bytes([0x78, 0xFF]) + b"A" * 255
assert len(_MAX_MEMO) == 257


@pytest.mark.active_test_scope
def test_sign_tx_memo_intermediate_frame_returns_success(backend):
    """INS 0x32: a memo split across two frames must answer 0x9000 on the first.

    Before this PR the intermediate frame threw ERROR_INVALID_STATE, so any memo over
    255 bytes was unsignable.
    """
    from application_client.command_sender import CLA, InsType, P2, pack_derivation_path

    chunks = split_message(_MAX_MEMO, MAX_APDU_LEN)
    assert len(chunks) == 2, f"expected 255+2, got {[len(c) for c in chunks]}"

    init = (
        pack_derivation_path(_MEMO_PATH)
        + _MEMO_HEADER_TO_ADDRESS
        + len(_MAX_MEMO).to_bytes(2, "big")
    )
    resp = backend.exchange(
        cla=CLA, ins=InsType.SIGN_TRANSFER_WITH_MEMO, p1=0x01, p2=P2.P2_NONE, data=init
    )
    assert resp.status == StatusWords.SWO_SUCCESS

    # The frame under test: memo incomplete, so the handler answers and waits for more.
    resp = backend.exchange(
        cla=CLA, ins=InsType.SIGN_TRANSFER_WITH_MEMO, p1=0x02, p2=P2.P2_NONE, data=chunks[0]
    )
    assert resp.status == StatusWords.SWO_SUCCESS
    assert resp.data == b""

    # Final memo frame. For INS 0x32 the review is on the amount packet, not here, so this
    # still answers synchronously and the flow is left waiting for the amount.
    resp = backend.exchange(
        cla=CLA, ins=InsType.SIGN_TRANSFER_WITH_MEMO, p1=0x02, p2=P2.P2_NONE, data=chunks[1]
    )
    assert resp.status == StatusWords.SWO_SUCCESS


@pytest.mark.active_test_scope
def test_sign_tx_schedule_memo_intermediate_frame_returns_success(backend):
    """INS 0x34: same intermediate memo frame, same regression, separate handler.

    Only the intermediate frame is sent. The final one calls finish_memo_scheduled(), which
    opens the memo review, so completing the flow here would need navigation and goldens for
    no extra coverage of the line under test.
    """
    from application_client.command_sender import CLA, InsType, P1, P2, pack_derivation_path

    chunks = split_message(_MAX_MEMO, MAX_APDU_LEN)

    init = (
        pack_derivation_path(_MEMO_PATH)
        + _SCHEDULE_MEMO_HEADER_TO_ADDRESS
        + bytes([1])                               # one schedule pair
        + len(_MAX_MEMO).to_bytes(2, "big")
    )
    resp = backend.exchange(
        cla=CLA,
        ins=InsType.SIGN_TRANSFER_WITH_SCHEDULE_AND_MEMO,
        p1=P1.P1_INITIAL_SCHEDULED_TRANSFER_WITH_MEMO,
        p2=P2.P2_NONE,
        data=init,
    )
    assert resp.status == StatusWords.SWO_SUCCESS

    resp = backend.exchange(
        cla=CLA,
        ins=InsType.SIGN_TRANSFER_WITH_SCHEDULE_AND_MEMO,
        p1=P1.P1_MEMO_SCHEDULED_TRANSFER,
        p2=P2.P2_NONE,
        data=chunks[0],
    )
    assert resp.status == StatusWords.SWO_SUCCESS
    assert resp.data == b""


@pytest.mark.active_test_scope
def test_sign_tx_memo_multi_packet_review(
    backend, navigator, default_screenshot_path, test_name
):
    """INS 0x32: a two-frame memo reviews and signs like a single-frame one.

    The synchronous test above pins the intermediate frame's status word; this one proves
    the whole flow still reaches a review and a signature once the memo spans two APDUs.
    The review shows all 255 memo characters, so the goldens also cover the paging.
    """
    client = CommandSender(backend)

    with client.sign_simple_transfer_with_memo(
        path=_MEMO_PATH,
        header_and_to_address=_MEMO_HEADER_TO_ADDRESS,
        memo=_MAX_MEMO,
        amount=bytes.fromhex("ffffffffffffffff"),
    ):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )

    response = client.get_async_response().data
    assert len(response) == 64, f"expected a 64-byte signature, got {len(response)}"


@pytest.mark.active_test_scope
def test_sign_tx_schedule_memo_multi_packet_review(
    backend, navigator, default_screenshot_path, test_name
):
    """INS 0x34: same, for the scheduled-transfer memo handler.

    Unlike INS 0x32 the memo review opens on the frame that completes the memo, so the
    earlier frames go out synchronously and only the last one is navigated.
    """
    client = CommandSender(backend)

    memo_chunks = split_message(_MAX_MEMO, MAX_APDU_LEN)
    assert len(memo_chunks) == 2, f"expected 255+2, got {[len(c) for c in memo_chunks]}"

    pairs = bytes.fromhex("0000017a396883d90000000005f5e100")  # one 16-byte pair

    response = client.sign_tx_with_schedule_and_memo_part_1(
        path=_MEMO_PATH,
        header_and_to_address=_SCHEDULE_MEMO_HEADER_TO_ADDRESS,
        num_pairs=1,
        memo_length=len(_MAX_MEMO),
    )
    assert response.status == StatusWords.SWO_SUCCESS

    # Memo incomplete: answers immediately, nothing on screen.
    for chunk in memo_chunks[:-1]:
        response = client.sign_tx_with_schedule_and_memo_memo_chunk(chunk)
        assert response.status == StatusWords.SWO_SUCCESS

    # Completing frame: opens the memo review.
    with client.sign_tx_with_schedule_and_memo_part_2(memo_chunk=memo_chunks[-1]):
        navigate_until_text_and_compare(
            backend,
            navigator,
            "Continue",
            default_screenshot_path,
            test_name,
            True,
            False,
            NavInsID.USE_CASE_CHOICE_CONFIRM,
        )

    # Resume numbering where the memo review left off, as the single-packet test does.
    screenshots_so_far = screenshots_taken_so_far(
        backend, default_screenshot_path, test_name
    )
    instructions = instructions_builder(2, backend, NavInsID.USE_CASE_REVIEW_CONFIRM)

    with client.sign_tx_with_schedule_and_memo_part_3(data=pairs):
        navigator.navigate_and_compare(
            default_screenshot_path,
            test_name,
            instructions,
            10,
            True,
            True,
            screenshots_so_far,
        )

    response = client.get_async_response().data
    assert len(response) == 64, f"expected a 64-byte signature, got {len(response)}"
