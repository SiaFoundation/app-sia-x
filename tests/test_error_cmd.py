from ragger.backend import RaisePolicy
from application_client.boilerplate_command_sender import CLA, InsType, P1, P2, Errors


# Ensure the app returns an error when a bad CLA is used
# Standard io library does not raise error in this situation
# def test_bad_cla(backend):
#     # Disable raising when trying to unpack an error APDU
#     backend.raise_policy = RaisePolicy.RAISE_NOTHING
#     rapdu = backend.exchange(cla=CLA + 1, ins=InsType.GET_VERSION)
#     assert rapdu.status == Errors.SW_INVALID_PARAM


# Ensure the app returns an error when a bad INS is used
def test_bad_ins(backend):
    # Disable raising when trying to unpack an error APDU
    backend.raise_policy = RaisePolicy.RAISE_NOTHING
    rapdu = backend.exchange(cla=CLA, ins=0xFF)
    assert rapdu.status == Errors.SW_INS_NOT_SUPPORTED
