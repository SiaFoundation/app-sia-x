import base64
from application_client.boilerplate_command_sender import (
    BoilerplateCommandSender,
    Errors,
)
from application_client.boilerplate_response_unpacker import (
    unpack_get_public_key_response,
    unpack_sign_tx_response,
)
from ragger.backend import RaisePolicy
from ragger.navigator import NavInsID
from utils import ROOT_SCREENSHOT_PATH

# In this tests we check the behavior of the device when asked to sign a transaction


# Encoded version of {"siacoininputs":[{"unlockhash":"bc9d0e935b4a5d6511c353cfd226990a31b47a409b069ca819280ec8440a0ba97f8b1081dc8c","unlockconditions":{"timelock":0,"requiredsignatures":1,"publickeys":["ed25519:4dd481abf56b5f96d82b13823ce81f8d8f0d0eb3ac2d656366ca2a822e526f49"]}}],"siacoinoutputs":[{"unlockhash":"7813b59b2da28959e13466b8701f40133ceda7677edfc7c17829c3b5c58d624596ea749b9d7c","value":"83117000000000000000000000000"},{"unlockhash":"6f4710e9acbc9a20987222d4e79f56baf3b5642059e2f3922ac8e6b1f4812df04fa00dff468f","value":"51405720000000000000000000000"}],"siafundinputs":null,"siafundoutputs":[{"unlockhash":"7813b59b2da28959e13466b8701f40133ceda7677edfc7c17829c3b5c58d624596ea749b9d7c","value":"83117000000000000000000000000"},{"unlockhash":"6f4710e9acbc9a20987222d4e79f56baf3b5642059e2f3922ac8e6b1f4812df04fa00dff468f","value":"51405720000000000000000000000"}],"storagecontracts":null,"contractrevisions":null,"storageproofs":null,"minerfees":null,"arbitrarydata":[],"transactionsignatures":[{"parentid":"784a77549f25083a69a388a1661e0a6b2ac8c7fc98e2b69edde6bd45d155ad03","signature":"9611b663d7f24e354b5eb9a82c26cf5855d958ad12617bee89c90ac38219adb76c74a97103a0ab4ec991b0120145d23aaa6471209d3542094377a4e96227f70b","publickeyindex":0,"coveredfields":{"wholetransaction":true}}]}
test_transaction = bytes.fromhex(
    "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000006564323535313900000000000000000020000000000000004dd481abf56b5f96d82b13823ce81f8d8f0d0eb3ac2d656366ca2a822e526f49000000000000000002000000000000000d00000000000000010c90c55e861d3c59cd0000007813b59b2da28959e13466b8701f40133ceda7677edfc7c17829c3b5c58d62450c00000000000000a619d0a11bec7c940f0000006f4710e9acbc9a20987222d4e79f56baf3b5642059e2f3922ac8e6b1f4812df0000000000000000000000000000000000000000000000000000000000000000002000000000000000d00000000000000010c90c55e861d3c59cd0000007813b59b2da28959e13466b8701f40133ceda7677edfc7c17829c3b5c58d624500000000000000000c00000000000000a619d0a11bec7c940f0000006f4710e9acbc9a20987222d4e79f56baf3b5642059e2f3922ac8e6b1f4812df00000000000000000000000000000000000000000000000000100000000000000784a77549f25083a69a388a1661e0a6b2ac8c7fc98e2b69edde6bd45d155ad03000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000f7ad756faeb777b7f6e1edf9e1be5e6fd6bcd9cdba71fe7ce7977de7c69dd76eb5edb79ef3d73dd1a737f36d7d69d6fbe9cef86bdef5d376b469be1e73df756f4d76d35e39776dda69aeb8ef5db4f5ddf9e36d3de37efb6b87bdeb6dbb7fbd1b"
)

# Transaction signature refused test
# The test will ask for a transaction signature that will be refused on screen
def test_sign_tx_refused(firmware, backend, navigator, test_name):
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)
    # Disable raising when trying to unpack an error APDU
    backend.raise_policy = RaisePolicy.RAISE_NOTHING

    with client.sign_tx(
        key_index=0,
        sig_index=0,
        change_index=4294967295,
        transaction=test_transaction,
    ):
        if firmware.device.startswith("nano"):
            instructions = []
            if firmware.device == "nanos":
                for i in range(2):
                    instructions.extend(4 * [NavInsID.RIGHT_CLICK])
                    instructions.extend([
                        NavInsID.BOTH_CLICK,
                        NavInsID.BOTH_CLICK,
                    ])
                for i in range(2):
                    instructions.extend(4 * [NavInsID.RIGHT_CLICK])
                    instructions.extend([
                        NavInsID.BOTH_CLICK,
                        NavInsID.RIGHT_CLICK,
                        NavInsID.BOTH_CLICK,
                    ])
            else:
                instructions.extend([
                    NavInsID.RIGHT_CLICK,
                    NavInsID.BOTH_CLICK,
                    NavInsID.BOTH_CLICK,
                    NavInsID.RIGHT_CLICK,
                    NavInsID.BOTH_CLICK,
                    NavInsID.BOTH_CLICK,
                    NavInsID.RIGHT_CLICK,
                    NavInsID.BOTH_CLICK,
                    NavInsID.BOTH_CLICK,
                    NavInsID.RIGHT_CLICK,
                    NavInsID.BOTH_CLICK,
                    NavInsID.BOTH_CLICK,
                ])

            instructions.extend([
                NavInsID.RIGHT_CLICK,
                NavInsID.RIGHT_CLICK,
                NavInsID.BOTH_CLICK,
            ])
            navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions)
        else:
            navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, [NavInsID.USE_CASE_REVIEW_REJECT])

    response = client.get_async_response()
    assert response.status == Errors.SW_DENY
    assert len(response.data) == 0


# Transaction signature accepted test
# The test will ask for a transaction signature that will be accepted on screen
def test_sign_tx_accept(firmware, backend, navigator, test_name):
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)
    # Disable raising when trying to unpack an error APDU
    backend.raise_policy = RaisePolicy.RAISE_NOTHING

    with client.sign_tx(key_index=0, sig_index=0, change_index=4294967295, transaction=test_transaction):
        if firmware.device.startswith("nano"):
            instructions = []
            if firmware.device == "nanos":
                for i in range(2):
                    instructions.extend(4 * [NavInsID.RIGHT_CLICK])
                    instructions.extend([
                        NavInsID.BOTH_CLICK,
                        NavInsID.BOTH_CLICK,
                    ])
                for i in range(2):
                    instructions.extend(4 * [NavInsID.RIGHT_CLICK])
                    instructions.extend([
                        NavInsID.BOTH_CLICK,
                        NavInsID.RIGHT_CLICK,
                        NavInsID.BOTH_CLICK,
                    ])
            else:
                instructions.extend([
                    NavInsID.RIGHT_CLICK,
                    NavInsID.BOTH_CLICK,
                    NavInsID.BOTH_CLICK,
                    NavInsID.RIGHT_CLICK,
                    NavInsID.BOTH_CLICK,
                    NavInsID.BOTH_CLICK,
                    NavInsID.RIGHT_CLICK,
                    NavInsID.BOTH_CLICK,
                    NavInsID.BOTH_CLICK,
                    NavInsID.RIGHT_CLICK,
                    NavInsID.BOTH_CLICK,
                    NavInsID.BOTH_CLICK,
                ])

            instructions.extend([
                NavInsID.RIGHT_CLICK,
                NavInsID.BOTH_CLICK,
            ])
            navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions)
        else:
            instructions = [
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_REVIEW_CONFIRM,
            ]
            navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions)


    response = client.get_async_response()
    assert response.status == Errors.SW_OK
    assert response.data == base64.b64decode(
        "mr7i3aLQDoyHIM1ZXV+OTd34EM3bSpemN3tmV2ilH3x/yEVUtoZTVBMpuW8BMQ9vV21QIgxUGpzBfZccEY0bAg=="
    )
