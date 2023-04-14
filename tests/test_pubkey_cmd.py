from application_client.boilerplate_command_sender import BoilerplateCommandSender, Errors
from application_client.boilerplate_response_unpacker import unpack_get_public_key_response
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.backend import RaisePolicy
from ragger.navigator import NavInsID, NavIns
from utils import ROOT_SCREENSHOT_PATH


def test_get_public_key_confirm_accepted(firmware, backend, navigator, test_name):
    client = BoilerplateCommandSender(backend)
    index = 5

    with client.get_public_key_with_confirmation(index=index):
        if firmware.device.startswith("nano"):
            navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                      [NavInsID.BOTH_CLICK],
                                                      "Approve",
                                                      ROOT_SCREENSHOT_PATH,
                                                      test_name)
        else:
            instructions = [
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM,
            ]
            navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                           test_name,
                                           instructions)

    response = client.get_async_response().data
    ref_public_key, _ = calculate_public_key_and_chaincode(CurveChoice.Ed25519Slip, path="44'/93'/%d'/0'/0'" % (index))
    assert(response[:32].hex() == ref_public_key[2:])

def test_get_public_key_confirm_refused(firmware, backend, navigator, test_name):
    client = BoilerplateCommandSender(backend)
    index = 5

    if firmware.device.startswith("nano"):
        with client.get_public_key_with_confirmation(index=index):
            # Disable raising when trying to unpack an error APDU
            backend.raise_policy = RaisePolicy.RAISE_NOTHING
            navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                      [NavInsID.BOTH_CLICK],
                                                      "Reject",
                                                      ROOT_SCREENSHOT_PATH,
                                                      test_name)

        response = client.get_async_response()

        # Assert that we have received a refusal
        assert response.status == Errors.SW_DENY
        assert len(response.data) == 0
    else:
        with client.get_public_key_with_confirmation(index=index):
            backend.raise_policy = RaisePolicy.RAISE_NOTHING
            navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                           test_name,
                                           [NavInsID.USE_CASE_REVIEW_REJECT])
        response = client.get_async_response()

        # Assert that we have received a refusal
        assert response.status == Errors.SW_DENY
        assert len(response.data) == 0

def test_get_address_confirm_accepted(firmware, backend, navigator, test_name):
    client = BoilerplateCommandSender(backend)
    index = 5

    with client.get_address_with_confirmation(index=index):
        if firmware.device.startswith("nano"):
            navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                      [NavInsID.BOTH_CLICK],
                                                      "Approve",
                                                      ROOT_SCREENSHOT_PATH,
                                                      test_name)
        else:
            instructions = [
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM,
            ]
            navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                           test_name,
                                           instructions)

    response = client.get_async_response().data
    ref_public_key, _ = calculate_public_key_and_chaincode(CurveChoice.Ed25519Slip, path="44'/93'/%d'/0'/0'" % (index))
    assert(response.hex()[:64] == ref_public_key[2:])

def test_get_address_confirm_refused(firmware, backend, navigator, test_name):
    client = BoilerplateCommandSender(backend)
    index = 5

    if firmware.device.startswith("nano"):
        with client.get_address_with_confirmation(index=index):
            # Disable raising when trying to unpack an error APDU
            backend.raise_policy = RaisePolicy.RAISE_NOTHING
            navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                      [NavInsID.BOTH_CLICK],
                                                      "Reject",
                                                      ROOT_SCREENSHOT_PATH,
                                                      test_name)

        response = client.get_async_response()

        # Assert that we have received a refusal
        assert response.status == Errors.SW_DENY
        assert len(response.data) == 0
    else:
        with client.get_public_key_with_confirmation(index=index):
            backend.raise_policy = RaisePolicy.RAISE_NOTHING
            navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                           test_name,
                                           [NavInsID.USE_CASE_REVIEW_REJECT])
        response = client.get_async_response()

        # Assert that we have received a refusal
        assert response.status == Errors.SW_DENY
        assert len(response.data) == 0
