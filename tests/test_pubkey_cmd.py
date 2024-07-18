from application_client.boilerplate_command_sender import (
    BoilerplateCommandSender,
    Errors,
)
from application_client.boilerplate_response_unpacker import (
    unpack_get_public_key_response,
)
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.backend import RaisePolicy
from ragger.navigator import NavInsID, NavIns
from utils import ROOT_SCREENSHOT_PATH

# Test will ask to generate a public key that will be accepted on screen
def test_get_public_key_confirm_accepted(firmware, backend, navigator, test_name):
    client = BoilerplateCommandSender(backend)
    index = 5

    with client.get_public_key_with_confirmation(index=index):
        if firmware.device.startswith("nano"):
            navigator.navigate_until_text_and_compare(
                NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                "Approve",
                ROOT_SCREENSHOT_PATH,
                test_name,
            )
        else:
            instructions = [
                NavInsID.USE_CASE_VIEW_DETAILS_NEXT,
                NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM,
            ]
            navigator.navigate_and_compare(
                ROOT_SCREENSHOT_PATH, test_name, instructions
            )

    response = client.get_async_response()
    ref_public_key, _ = calculate_public_key_and_chaincode(
        CurveChoice.Ed25519Slip, path="44'/93'/%d'/0'/0'" % (index)
    )
    assert response.status == Errors.SW_OK
    assert response.data[:32].hex() == ref_public_key[2:]


# Test will ask to generate a public key that will be rejected on screen
def test_get_public_key_confirm_refused(firmware, backend, navigator, test_name):
    client = BoilerplateCommandSender(backend)
    index = 5

    with client.get_public_key_with_confirmation(index=index):
        # Disable raising when trying to unpack an error APDU
        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        if firmware.device.startswith("nano"):
            navigator.navigate_until_text_and_compare(
                NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                "Reject",
                ROOT_SCREENSHOT_PATH,
                test_name,
            )
        else:
            navigator.navigate_and_compare(
                ROOT_SCREENSHOT_PATH, test_name, [NavInsID.USE_CASE_VIEW_DETAILS_EXIT]
            )

    response = client.get_async_response()
    # Assert that we have received a refusal
    assert response.status == Errors.SW_DENY
    assert len(response.data) == 0


# Test will ask to generate an address that will be accepted on screen
def test_get_address_confirm_accepted(firmware, backend, navigator, test_name):
    client = BoilerplateCommandSender(backend)
    index = 5

    with client.get_address_with_confirmation(index=index):
        if firmware.device.startswith("nano"):
            navigator.navigate_until_text_and_compare(
                NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                "Approve",
                ROOT_SCREENSHOT_PATH,
                test_name,
            )
        else:
            instructions = [
                NavInsID.USE_CASE_VIEW_DETAILS_NEXT,
                NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM,
            ]
            navigator.navigate_and_compare(
                ROOT_SCREENSHOT_PATH, test_name, instructions
            )

    response = client.get_async_response()
    ref_public_key, _ = calculate_public_key_and_chaincode(
        CurveChoice.Ed25519Slip, path="44'/93'/%d'/0'/0'" % (index)
    )
    assert response.status == Errors.SW_OK
    assert response.data[:32].hex() == ref_public_key[2:]


# Test will ask to generate an address that will be rejected on screen
def test_get_address_confirm_refused(firmware, backend, navigator, test_name):
    client = BoilerplateCommandSender(backend)
    index = 5

    with client.get_address_with_confirmation(index=index):
        # Disable raising when trying to unpack an error APDU
        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        if firmware.device.startswith("nano"):
            navigator.navigate_until_text_and_compare(
                NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                "Reject",
                ROOT_SCREENSHOT_PATH,
                test_name,
            )
        else:
            navigator.navigate_and_compare(
                ROOT_SCREENSHOT_PATH, test_name, [NavInsID.USE_CASE_VIEW_DETAILS_EXIT]
            )

    response = client.get_async_response()
    # Assert that we have received a refusal
    assert response.status == Errors.SW_DENY
    assert len(response.data) == 0
