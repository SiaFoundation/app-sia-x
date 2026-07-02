from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.backend import BackendInterface, RaisePolicy
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.boilerplate_command_sender import (
    BoilerplateCommandSender,
    Errors,
)


# Test will ask to generate a public key that will be accepted on screen
def test_get_public_key_confirm_accepted(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
):
    client = BoilerplateCommandSender(backend)
    index = 5

    with client.get_public_key_with_confirmation(index=index):
        scenario_navigator.address_review_approve()

    response = client.get_async_response()
    ref_public_key, _ = calculate_public_key_and_chaincode(
        CurveChoice.Ed25519Slip, f"44'/93'/{index}'/0'/0'"
    )
    assert response.status == Errors.SW_OK
    assert response.data[:32].hex() == ref_public_key[2:]


# Test will ask to generate a public key that will be rejected on screen
def test_get_public_key_confirm_refused(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
):
    client = BoilerplateCommandSender(backend)
    index = 5

    with client.get_public_key_with_confirmation(index=index):
        # Disable raising when trying to unpack an error APDU
        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        scenario_navigator.address_review_reject()

    response = client.get_async_response()
    # Assert that we have received a refusal
    assert response.status == Errors.SW_DENY
    assert len(response.data) == 0


# Test will ask to generate an address that will be accepted on screen
def test_get_address_confirm_accepted(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
):
    client = BoilerplateCommandSender(backend)
    index = 5

    with client.get_address_with_confirmation(index=index):
        scenario_navigator.address_review_approve()

    response = client.get_async_response()
    ref_public_key, _ = calculate_public_key_and_chaincode(
        CurveChoice.Ed25519Slip, f"44'/93'/{index}'/0'/0'"
    )
    assert response.status == Errors.SW_OK
    assert response.data[:32].hex() == ref_public_key[2:]


# Test will ask to generate an address that will be rejected on screen
def test_get_address_confirm_refused(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
):
    client = BoilerplateCommandSender(backend)
    index = 5

    with client.get_address_with_confirmation(index=index):
        # Disable raising when trying to unpack an error APDU
        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        scenario_navigator.address_review_reject()

    response = client.get_async_response()
    # Assert that we have received a refusal
    assert response.status == Errors.SW_DENY
    assert len(response.data) == 0
