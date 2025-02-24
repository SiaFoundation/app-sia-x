import base64
from typing import List

from application_client.boilerplate_command_sender import (
    BoilerplateCommandSender,
    Errors,
)

from ragger.backend import BackendInterface, RaisePolicy
from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario

from utils import ROOT_SCREENSHOT_PATH

# In this tests we check the behavior of the device when asked to sign a transaction

# Encoded version of {"id":"33a00cab66a3082770d710a368983c1733e1b12925a31fdbcf9d5431cd18f87d","siacoinInputs":[{"parent":{"id":"e975d168a47835ec22d343646f6826c9721f00892ddbc4f38f5b579dfb509b4c","stateElement":{"leafIndex":0,"merkleProof":["021f8e53c4edb1108c2573cbe4cdd498af63d4fe0281564343a0f8a582ac71f2","93be04b12d4ee1f874a7a8669a85696048932890eadaa5e38027ab1ad54a5f44"]},"siacoinOutput":{"value":"100000000000000000000000000","address":"3178e2a50d69c3083c2304cfb4cf6356022b355f3a75c7813f6dd32d42c7c5280172cebc20b5"},"maturityHeight":0},"satisfiedPolicy":{"policy":{"type":"uc","policy":{"timelock":0,"publicKeys":["ed25519:45ce3b5d6fbd807101e1e257e7efb3343e2956ebfc18ea3271131c1a0d2894c1"],"signaturesRequired":1}},"signatures":["44d7466a5ae4359d08460261af44802db43649ea10ea8473f2db2be2d0126507d14b547b4ae4512c6a8164d7ccb9e6c08f43c4253febe89f6c211b1780f02f08"]}}],"siacoinOutputs":[{"value":"13100000000000000000000000","address":"3178e2a50d69c3083c2304cfb4cf6356022b355f3a75c7813f6dd32d42c7c5280172cebc20b5"},{"value":"26200000000000000000000000","address":"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"}],"siafundInputs":[{"parent":{"id":"48c650e3ba4a8f1720761459bcb0a92f099e660ee863cedc00663be52035dad7","stateElement":{"leafIndex":1,"merkleProof":["c7a2d6c7309c7631aedccf4d88da47eda92145fb6b8db61833a6f9be358b0ae1","93be04b12d4ee1f874a7a8669a85696048932890eadaa5e38027ab1ad54a5f44"]},"siafundOutput":{"value":100,"address":"3178e2a50d69c3083c2304cfb4cf6356022b355f3a75c7813f6dd32d42c7c5280172cebc20b5"},"claimStart":"0"},"claimAddress":"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69","satisfiedPolicy":{"policy":{"type":"uc","policy":{"timelock":0,"publicKeys":["ed25519:45ce3b5d6fbd807101e1e257e7efb3343e2956ebfc18ea3271131c1a0d2894c1"],"signaturesRequired":1}},"signatures":["44d7466a5ae4359d08460261af44802db43649ea10ea8473f2db2be2d0126507d14b547b4ae4512c6a8164d7ccb9e6c08f43c4253febe89f6c211b1780f02f08"]}}],"siafundOutputs":[{"value":25,"address":"3178e2a50d69c3083c2304cfb4cf6356022b355f3a75c7813f6dd32d42c7c5280172cebc20b5"},{"value":75,"address":"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"}],"minerFee":"123456789123456789"}
test_v2_transaction = bytes.fromhex(
    "0100000000000000e975d168a47835ec22d343646f6826c9721f00892ddbc4f38f5b579dfb509b4c0200000000000000000080235c49486c08d60a00000000003178e2a50d69c3083c2304cfb4cf6356022b355f3a75c7813f6dd32d42c7c52800000047b89290d810ac1500000000000000000000000000000000000000000000000000000000000000000000000000010000000000000048c650e3ba4a8f1720761459bcb0a92f099e660ee863cedc00663be52035dad7020000000000000019000000000000003178e2a50d69c3083c2304cfb4cf6356022b355f3a75c7813f6dd32d42c7c5284b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000155fd0ac4b9bb6010000000000000000"
)

def __get_instructions(firmware: Firmware, refused: bool) -> List[NavInsID]:
    instructions = []
    if firmware.is_nano:
        for _ in range(4):
            instructions.extend([NavInsID.RIGHT_CLICK])
            instructions.extend(2 * [NavInsID.BOTH_CLICK])
        instructions.append(NavInsID.BOTH_CLICK)

        if refused:
            instructions.extend([NavInsID.RIGHT_CLICK])
        instructions.extend([
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
        ])
    return instructions


# Transaction signature refused test
# The test will ask for a transaction signature that will be refused on screen
def test_v2_sign_tx_refused(firmware: Firmware,
                         backend: BackendInterface,
                         navigator: Navigator,
                         scenario_navigator: NavigateWithScenario,
                         test_name: str):
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)
    # Disable raising when trying to unpack an error APDU
    backend.raise_policy = RaisePolicy.RAISE_NOTHING

    with client.sign_v2_tx(0, 0, 4294967295, test_v2_transaction):
        if firmware.is_nano:
            instructions = __get_instructions(firmware, True)
            navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions)
        else:
            scenario_navigator.review_reject()

    response = client.get_async_response()
    assert response.status == Errors.SW_DENY
    assert len(response.data) == 0


# Transaction signature accepted test
# The test will ask for a transaction signature that will be accepted on screen
def test_v2_sign_tx_accept(firmware: Firmware,
                        backend: BackendInterface,
                        navigator: Navigator,
                        scenario_navigator: NavigateWithScenario,
                        test_name: str):
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)
    # Disable raising when trying to unpack an error APDU
    backend.raise_policy = RaisePolicy.RAISE_NOTHING

    with client.sign_v2_tx(0, 0, 4294967295, test_v2_transaction):
        if firmware.is_nano:
            instructions = __get_instructions(firmware, False)
            navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions)
        else:
            scenario_navigator.review_approve()


    response = client.get_async_response()
    assert response.status == Errors.SW_OK
    assert response.data == base64.b64decode(
        "zdx78WQzlMm/7wDKyW8wmHA8b3dQjBiZpYDYjia6V2KZKWdbkAaCbxw0/Jkg206ys+UbTNgl30iqa/tV48qLBA=="
    )
