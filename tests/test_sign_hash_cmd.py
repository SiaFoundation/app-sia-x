from application_client.boilerplate_command_sender import (
    BoilerplateCommandSender,
    Errors,
)
from application_client.boilerplate_response_unpacker import (
    unpack_get_public_key_response,
    unpack_sign_tx_response,
)
from ragger.backend import RaisePolicy
from ragger.navigator import NavIns, NavInsID
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from utils import ROOT_SCREENSHOT_PATH

test_to_sign = bytes.fromhex(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

# Test will ask to sign a hash that will be accepted on screen
def test_sign_hash_accept(firmware, backend, navigator, test_name):
    client = BoilerplateCommandSender(backend)
    index = 5

    if firmware.device.startswith("nano"):
        navigator.navigate([
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
        ], screen_change_before_first_instruction=False)
    else:
        navigator.navigate([
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavIns(NavInsID.TOUCH, (350,115)),
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
        ], screen_change_before_first_instruction=False)

    with client.sign_hash_with_confirmation(index=index, to_sign=test_to_sign):
        # Disable raising when trying to unpack an error APDU
        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        if firmware.device.startswith("nano"):
            # enable blind signing
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
                NavInsID.USE_CASE_VIEW_DETAILS_NEXT,
                NavInsID.USE_CASE_REVIEW_CONFIRM,
            ]
            navigator.navigate_and_compare(
                ROOT_SCREENSHOT_PATH, test_name, instructions,
            )

    response = client.get_async_response()
    assert response.status == Errors.SW_OK
    assert response.data == bytes.fromhex(
        "abd9187ca30200709137fa76dee32d58700f05c2debef62fb9b36af663498657384772ea437c886e07be20ddc60aaf04bb54736ab5dbaed4c00a6bdffcf7750f"
    )


# Test will ask to sign a hash that will be rejected on screen
def test_sign_hash_reject(firmware, backend, navigator, test_name):
    client = BoilerplateCommandSender(backend)
    index = 5

    if firmware.device.startswith("nano"):
        navigator.navigate([
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
        ], screen_change_before_first_instruction=False)
    else:
        navigator.navigate([
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavIns(NavInsID.TOUCH, (350,115)),
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
        ], screen_change_before_first_instruction=False)

    with client.sign_hash_with_confirmation(index=index, to_sign=test_to_sign):
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
                ROOT_SCREENSHOT_PATH, test_name, [
                    NavInsID.USE_CASE_VIEW_DETAILS_EXIT,
                    NavInsID.USE_CASE_CHOICE_CONFIRM,
                ]
            )

    # Assert that we have received a refusal
    response = client.get_async_response()
    assert response.status == Errors.SW_DENY
    assert len(response.data) == 0
