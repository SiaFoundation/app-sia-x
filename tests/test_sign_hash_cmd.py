from application_client.boilerplate_transaction import Transaction
from application_client.boilerplate_command_sender import BoilerplateCommandSender, Errors
from application_client.boilerplate_response_unpacker import unpack_get_public_key_response, unpack_sign_tx_response
from ragger.backend import RaisePolicy
from ragger.navigator import NavInsID
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from utils import ROOT_SCREENSHOT_PATH, check_signature_validity

def test_sign_hash_accept(firmware, backend, navigator, test_name):
    client = BoilerplateCommandSender(backend)
    index = 5
    to_sign = bytes.fromhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

    if firmware.device.startswith("nano"):
        with client.sign_hash_with_confirmation(index=index, to_sign=to_sign):
            # Disable raising when trying to unpack an error APDU
            backend.raise_policy = RaisePolicy.RAISE_NOTHING
            navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                      [NavInsID.BOTH_CLICK],
                                                      "Approve",
                                                      ROOT_SCREENSHOT_PATH,
                                                      test_name)
    else:
        with client.sign_hash_with_confirmation(index=index, to_sign=to_sign):
            # Disable raising when trying to unpack an error APDU
            backend.raise_policy = RaisePolicy.RAISE_NOTHING
            navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                           test_name,
                                           [NavInsID.USE_CASE_REVIEW_TAP])


    response = client.get_async_response()
    assert response.status == Errors.SW_OK
    assert(response.data == bytes.fromhex("abd9187ca30200709137fa76dee32d58700f05c2debef62fb9b36af663498657384772ea437c886e07be20ddc60aaf04bb54736ab5dbaed4c00a6bdffcf7750f"))


def test_sign_hash_reject(firmware, backend, navigator, test_name):
    client = BoilerplateCommandSender(backend)
    index = 5
    to_sign = bytes.fromhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

    if firmware.device.startswith("nano"):
        with client.sign_hash_with_confirmation(index=index, to_sign=to_sign):
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
        with client.sign_hash_with_confirmation(index=index, to_sign=to_sign):
            # Disable raising when trying to unpack an error APDU
            backend.raise_policy = RaisePolicy.RAISE_NOTHING
            navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                           test_name,
                                           [NavInsID.USE_CASE_REVIEW_REJECT])
        response = client.get_async_response()

        # Assert that we have received a refusal
        assert response.status == Errors.SW_DENY
        assert len(response.data) == 0
