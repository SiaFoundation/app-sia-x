import base64

from application_client.boilerplate_command_sender import (
    BoilerplateCommandSender,
    Errors,
)

from ragger.backend import BackendInterface, RaisePolicy
from ragger.navigator.navigation_scenario import NavigateWithScenario

# In this tests we check the behavior of the device when asked to sign a transaction

# pylint: disable=line-too-long
# Encoded version of {"id":"7a1b7edecec4a8816ea6cda10875b9133f574dd00e762af26072507d298e937c","siacoinInputs":[{"parentID":"7f2577cee9a0d7c447f8bccddbcf68dd2b2f8ee0d071b8979fa32a1f7b3a5b23","unlockConditions":{"timelock":0,"publicKeys":["ed25519:32da8bafcd970e1d4bdfeccac961337b594ae61178f0f896cf7b2c366df20f78"],"signaturesRequired":1}}],"siacoinOutputs":[{"value":"13110000000000000000000000","address":"38db280f548439c64ec3456c190e8d582aaba28aaab92fc751f2b72ce441bab4b724b95f1c7f"},{"value":"26220000000000000000000000","address":"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"}],"siafundInputs":[{"parentID":"6c65dad1d50c936098bd30141a335c4c1e47e9769fa2adb7ec447a84166f6c1c","unlockConditions":{"timelock":0,"publicKeys":["ed25519:32da8bafcd970e1d4bdfeccac961337b594ae61178f0f896cf7b2c366df20f78"],"signaturesRequired":1},"claimAddress":"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"}],"siafundOutputs":[{"value":25,"address":"38db280f548439c64ec3456c190e8d582aaba28aaab92fc751f2b72ce441bab4b724b95f1c7f"},{"value":50,"address":"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"}],"minerFees": ["12341234123444444"], "signatures":[{"parentID":"7f2577cee9a0d7c447f8bccddbcf68dd2b2f8ee0d071b8979fa32a1f7b3a5b23","publicKeyIndex":0,"coveredFields":{"wholeTransaction":true},"signature":"bxMu2triXLPvosopILeSpcyq4SYPVQry4gKdFKwPWyoNpoWRa1cnBVUFt4C8rZa8kZWJCwaeQyrwQQVN49FoDA=="},{"parentID":"6c65dad1d50c936098bd30141a335c4c1e47e9769fa2adb7ec447a84166f6c1c","publicKeyIndex":0,"coveredFields":{"wholeTransaction":true},"signature":"FzEMsjmD+4d974uAR7CFohzWFPA6whw0ojYNBz4Pb5kY+wUoIhvZ8oIFW3m9aYTub/ZcOVbZ1tJqqZsvPc02Dw=="}]}
test_transaction = bytes.fromhex(
    "01000000000000007f2577cee9a0d7c447f8bccddbcf68dd2b2f8ee0d071b8979fa32a1f7b3a5b230000000000000000010000000000000065643235353139000000000000000000200000000000000032da8bafcd970e1d4bdfeccac961337b594ae61178f0f896cf7b2c366df20f78010000000000000002000000000000000b000000000000000ad82686291316d5c0000038db280f548439c64ec3456c190e8d582aaba28aaab92fc751f2b72ce441bab40b0000000000000015b04d0c52262dab800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000006c65dad1d50c936098bd30141a335c4c1e47e9769fa2adb7ec447a84166f6c1c0000000000000000010000000000000065643235353139000000000000000000200000000000000032da8bafcd970e1d4bdfeccac961337b594ae61178f0f896cf7b2c366df20f7801000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000001000000000000001938db280f548439c64ec3456c190e8d582aaba28aaab92fc751f2b72ce441bab4000000000000000001000000000000003200000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000007000000000000002bd8497c0490dc000000000000000002000000000000007f2577cee9a0d7c447f8bccddbcf68dd2b2f8ee0d071b8979fa32a1f7b3a5b230000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000006f132edadae25cb3efa2ca2920b792a5ccaae1260f550af2e2029d14ac0f5b2a0da685916b5727055505b780bcad96bc9195890b069e432af041054de3d1680c6c65dad1d50c936098bd30141a335c4c1e47e9769fa2adb7ec447a84166f6c1c00000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000017310cb23983fb877def8b8047b085a21cd614f03ac21c34a2360d073e0f6f9918fb0528221bd9f282055b79bd6984ee6ff65c3956d9d6d26aa99b2f3dcd360f"
)
# pylint: enable=line-too-long


# Transaction signature refused test
# The test will ask for a transaction signature that will be refused on screen
def test_sign_tx_refused(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
):
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)
    # Disable raising when trying to unpack an error APDU
    backend.raise_policy = RaisePolicy.RAISE_NOTHING

    with client.sign_tx(0, 0, 4294967295, test_transaction):
        scenario_navigator.review_reject()

    response = client.get_async_response()
    assert response.status == Errors.SW_DENY
    assert len(response.data) == 0


# Transaction signature accepted test
# The test will ask for a transaction signature that will be accepted on screen
def test_sign_tx_accept(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
):
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)

    with client.sign_tx(0, 0, 4294967295, test_transaction):
        scenario_navigator.review_approve(custom_screen_text="Sign Transaction")

    response = client.get_async_response()
    assert response.status == Errors.SW_OK
    assert response.data == base64.b64decode(
        "4RPOV1ZVT0HmzVgfjhpRIhHGu3iO1D8476rWlUhPWvvEc58gR65UtTaPuDxV/pp2o5gSOmEp3IABH8jf+2aNBA=="
    )
