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


# Encoded version of {"siacoininputs":[{"parentid":"1ac932c4066849910b71cea45d41bd369c5a0ec0d1fb402b5817609267472203","unlockconditions":{"timelock":0,"publickeys":[{"algorithm":"ed25519","key":"uufl5A7eDGRvmZXd/0BS4gGtwcvaI3RYpG6I3pu+MDU="}],"signaturesrequired":1}}],"siacoinoutputs":[{"value":"2258879985664589741577573652371","unlockhash":"fc8caec1fc8fd727fe5107bd949009dafbf330515ab4ad29e6e36d62f17982acc458e71d3694"}],"filecontracts":[],"filecontractrevisions":[],"storageproofs":[],"siafundinputs":[],"siafundoutputs":[],"minerfees":["22500000000000000000000"],"arbitrarydata":[],"transactionsignatures":[{"parentid":"1ac932c4066849910b71cea45d41bd369c5a0ec0d1fb402b5817609267472203","publickeyindex":0,"timelock":0,"coveredfields":{"wholetransaction":true,"siacoininputs":[],"siacoinoutputs":[],"filecontracts":[],"filecontractrevisions":[],"storageproofs":[],"siafundinputs":[],"siafundoutputs":[],"minerfees":[],"arbitrarydata":[],"transactionsignatures":[]},"signature":"FuJGOEirwrmtCISF368SJrk10cGmHCIsg28BKxrtABojEaAO7LmTK1o5cF+p8pFy5VAs0vDUPX7x7dXk6jDLDw=="}]}
test_transaction = bytes.fromhex(
    "01000000000000001ac932c4066849910b71cea45d41bd369c5a0ec0d1fb402b581760926747220300000000000000000100000000000000656432353531390000000000000000002000000000000000bae7e5e40ede0c646f9995ddff4052e201adc1cbda237458a46e88de9bbe3035010000000000000001000000000000000d000000000000001c82d5baf014236c48f88e5793fc8caec1fc8fd727fe5107bd949009dafbf330515ab4ad29e6e36d62f17982ac0000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000a0000000000000004c3ba39c5e411100000000000000000000001000000000000001ac932c4066849910b71cea45d41bd369c5a0ec0d1fb402b581760926747220300000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000016e2463848abc2b9ad088485dfaf1226b935d1c1a61c222c836f012b1aed001a2311a00eecb9932b5a39705fa9f29172e5502cd2f0d43d7ef1edd5e4ea30cb0f"
)

# Transaction signature refused test
# The test will ask for a transaction signature that will be refused on screen
def test_sign_tx_refused(firmware, backend, navigator, test_name):
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)
    # Disable raising when trying to unpack an error APDU
    backend.raise_policy = RaisePolicy.RAISE_NOTHING

    # The full message isn't sent all at once which prevents us from being
    # able to navigate through menus nicely like we can in other tests.
    # There may be a better way to do this but I couldn't find any other
    # way that worked.

    def skip_loop():
        for i in range(5):
            if firmware.device.startswith("nano"):
                backend.right_click()
                backend.both_click()
            else:
                backend.finger_touch()

    def skip_end():
        if firmware.device.startswith("nano"):
            backend.both_click()
        else:
            backend.finger_touch()

    with client.sign_tx(
        skip_loop=skip_loop,
        skip_end=skip_end,
        key_index=0,
        sig_index=0,
        change_index=4294967295,
        transaction=test_transaction,
    ):
        if firmware.device.startswith("nano"):
            navigator.navigate_until_text_and_compare(
                NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                "Reject",
                ROOT_SCREENSHOT_PATH,
                test_name,
            )
        else:
            navigator.navigate([NavInsID.USE_CASE_REVIEW_REJECT])

    response = client.get_async_response()
    assert response.status == Errors.SW_DENY
    assert len(response.data) == 0


# Transaction signature accepted test
# The test will ask for a transaction signature that will be accepted on screen
def test_sign_tx_accept(firmware, backend, navigator, test_name):
    if firmware.device.startswith("stax"):
        return
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)
    # Disable raising when trying to unpack an error APDU
    backend.raise_policy = RaisePolicy.RAISE_NOTHING

    # The full message isn't sent all at once which prevents us from being
    # able to navigate through menus nicely like we can in other tests.
    # There may be a better way to do this but I couldn't find any other
    # way that worked.

    def skip_loop():
        for i in range(5):
            if firmware.device.startswith("nano"):
                backend.right_click()
                backend.both_click()
            else:
                backend.finger_touch()

    def skip_end():
        if firmware.device.startswith("nano"):
            backend.both_click()
        else:
            backend.finger_touch()

    with client.sign_tx(
        skip_loop=skip_loop,
        skip_end=skip_end,
        key_index=0,
        sig_index=0,
        change_index=4294967295,
        transaction=test_transaction,
    ):
        if firmware.device.startswith("nano"):
            navigator.navigate_until_text_and_compare(
                NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                "Approve",
                ROOT_SCREENSHOT_PATH,
                test_name,
            )


    response = client.get_async_response()
    assert response.status == Errors.SW_OK
    assert response.data == base64.b64decode(
        "4qZznM8H4VStLIdWeppafXsi9VgTT6A8sM0dG84pXO9NvnaaQK1EJw9iJuMwwPEItANNTIAEvuAzqPPPidMcAg=="
    )
