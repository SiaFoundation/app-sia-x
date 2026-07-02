from ragger.backend import BackendInterface, RaisePolicy
from ragger.navigator import Navigator, NavIns, NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.firmware.touch.positions import POSITIONS

from ledgered.devices import Device
from application_client.boilerplate_command_sender import (
    BoilerplateCommandSender,
    Errors,
)


test_to_sign = bytes.fromhex(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)


def __toggle_setting(device: Device, navigator: Navigator) -> None:
    if device.is_nano:
        navigator.navigate(
            [
                NavInsID.RIGHT_CLICK,
                NavInsID.BOTH_CLICK,
                NavInsID.BOTH_CLICK,
                NavInsID.RIGHT_CLICK,
                NavInsID.BOTH_CLICK,
                NavInsID.BOTH_CLICK,
            ],
            screen_change_before_first_instruction=False,
        )
    else:
        navigator.navigate(
            [
                NavInsID.USE_CASE_HOME_SETTINGS,
                NavIns(NavInsID.TOUCH, POSITIONS["ChoiceList"][device.type][1]),
                NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
            ],
            screen_change_before_first_instruction=False,
        )


# Test will ask to sign a hash that will be accepted on screen
def test_sign_hash_accept(
    device: Device,
    backend: BackendInterface,
    navigator: Navigator,
    scenario_navigator: NavigateWithScenario,
):
    client = BoilerplateCommandSender(backend)
    index = 5

    __toggle_setting(device, navigator)

    with client.sign_hash_with_confirmation(index, test_to_sign):
        # Disable raising when trying to unpack an error APDU
        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        scenario_navigator.review_approve(custom_screen_text="Sign hash")

    response = client.get_async_response()
    assert response.status == Errors.SW_OK
    # pylint: disable=line-too-long
    assert response.data == bytes.fromhex(
        "abd9187ca30200709137fa76dee32d58700f05c2debef62fb9b36af663498657384772ea437c886e07be20ddc60aaf04bb54736ab5dbaed4c00a6bdffcf7750f"
    )
    # pylint: enable=line-too-long


# Test will ask to sign a hash that will be rejected on screen
def test_sign_hash_reject(
    device: Device,
    backend: BackendInterface,
    navigator: Navigator,
    scenario_navigator: NavigateWithScenario,
):
    client = BoilerplateCommandSender(backend)
    index = 5

    __toggle_setting(device, navigator)

    with client.sign_hash_with_confirmation(index, test_to_sign):
        # Disable raising when trying to unpack an error APDU
        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        scenario_navigator.review_reject()

    # Assert that we have received a refusal
    response = client.get_async_response()
    assert response.status == Errors.SW_DENY
    assert len(response.data) == 0
