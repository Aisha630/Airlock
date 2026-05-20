"""The handshake: agreement, authentication, key separation, and ordering."""

import pytest

from akex.dh import DHKeyPair, InvalidPublicKey
from akex.kdf import hmac_sha256
from akex.params import MODP_2048, MODP_3072
from akex.protocol import (
    AuthenticationError,
    Initiator,
    ProtocolError,
    Responder,
    derive_keys,
    run_handshake,
)
from akex.wire import ConfirmMessage, InitMessage, ResponseMessage, transcript_hash

PSK = b"a pre-shared key for the lab"


def test_handshake_agrees_on_all_four_keys():
    initiator_keys, responder_keys = run_handshake(PSK)
    assert initiator_keys == responder_keys


def test_handshake_survives_a_full_wire_round_trip():
    """Both parties must work from decoded bytes, not shared Python objects."""
    initiator = Initiator(psk=PSK)
    responder = Responder(psk=PSK)
    init_msg = InitMessage.decode(initiator.start().encode())
    response, _ = responder.respond(init_msg)
    confirm, initiator_keys = initiator.finish(
        ResponseMessage.decode(response.encode())
    )
    responder_keys = responder.confirm(ConfirmMessage.decode(confirm.encode()))
    assert initiator_keys == responder_keys


def test_keys_are_pairwise_distinct():
    keys, _ = run_handshake(PSK)
    derived = [keys.auth_i, keys.auth_r, keys.session_i2r, keys.session_r2i]
    assert len(set(derived)) == 4
    assert all(len(key) == 32 for key in derived)


def test_each_handshake_produces_fresh_keys():
    """Ephemeral keys and fresh nonces: the same PSK must not repeat a session."""
    first, _ = run_handshake(PSK)
    second, _ = run_handshake(PSK)
    assert first.session_i2r != second.session_i2r
    assert first.fingerprint() != second.fingerprint()


def test_wrong_psk_fails_at_the_responder_tag():
    initiator = Initiator(psk=PSK)
    responder = Responder(psk=b"the wrong key")
    response, _ = responder.respond(initiator.start())
    with pytest.raises(AuthenticationError):
        initiator.finish(response)


def test_initiator_tag_is_checked_by_the_responder():
    """A responder must not accept a forged final message."""
    initiator = Initiator(psk=PSK)
    responder = Responder(psk=PSK)
    response, _ = responder.respond(initiator.start())
    initiator.finish(response)
    with pytest.raises(AuthenticationError):
        responder.confirm(ConfirmMessage(tag_i=b"\x00" * 32))


@pytest.mark.parametrize("field", ["nonce_r", "tag_r"])
def test_tampering_with_message_two_is_detected(field):
    initiator = Initiator(psk=PSK)
    responder = Responder(psk=PSK)
    response, _ = responder.respond(initiator.start())

    corrupted = bytearray(getattr(response, field))
    corrupted[0] ^= 0x01
    forged = ResponseMessage(
        group_id=response.group_id,
        nonce_r=bytes(corrupted) if field == "nonce_r" else response.nonce_r,
        pub_r=response.pub_r,
        tag_r=bytes(corrupted) if field == "tag_r" else response.tag_r,
    )
    with pytest.raises(AuthenticationError):
        initiator.finish(forged)


def test_tampering_with_the_public_key_is_caught_by_validation():
    """Corrupting g^r trips the subgroup check before the tag is even reached."""
    initiator = Initiator(psk=PSK)
    responder = Responder(psk=PSK)
    response, _ = responder.respond(initiator.start())
    corrupted = bytearray(response.pub_r)
    corrupted[-1] ^= 0x01
    forged = ResponseMessage(
        group_id=response.group_id,
        nonce_r=response.nonce_r,
        pub_r=bytes(corrupted),
        tag_r=response.tag_r,
    )
    with pytest.raises((AuthenticationError, InvalidPublicKey)):
        initiator.finish(forged)


def test_group_downgrade_is_refused():
    initiator = Initiator(psk=PSK, group=MODP_3072)
    initiator.start()
    forged = ResponseMessage(
        group_id=MODP_2048.group_id,
        nonce_r=b"\x00" * 32,
        pub_r=b"\x02" * MODP_2048.size_bytes,
        tag_r=b"\x00" * 32,
    )
    with pytest.raises((ProtocolError, AuthenticationError)):
        initiator.finish(forged)


def test_responder_enforces_its_group_policy():
    responder = Responder(psk=PSK, group=MODP_3072)
    weak = Initiator(psk=PSK, group=MODP_2048).start()
    with pytest.raises(ProtocolError):
        responder.respond(weak)


def test_responder_rejects_a_wrongly_sized_public_key():
    responder = Responder(psk=PSK)
    with pytest.raises(ProtocolError, match="requires"):
        responder.respond(
            InitMessage(group_id=14, nonce_i=b"\x00" * 32, pub_i=b"\x02" * 16)
        )


def test_responder_rejects_a_degenerate_public_key():
    responder = Responder(psk=PSK)
    with pytest.raises(InvalidPublicKey):
        responder.respond(
            InitMessage(
                group_id=14,
                nonce_i=b"\x00" * 32,
                pub_i=(1).to_bytes(MODP_2048.size_bytes, "big"),
            )
        )


def test_state_machine_rejects_out_of_order_calls():
    with pytest.raises(ProtocolError):
        Initiator(psk=PSK).finish(
            ResponseMessage(14, b"\x00" * 32, b"\x02" * 256, b"\x00" * 32)
        )
    with pytest.raises(ProtocolError):
        Responder(psk=PSK).confirm(ConfirmMessage(tag_i=b"\x00" * 32))


def test_mitm_without_the_psk_cannot_forge_a_tag():
    """The attack the protocol exists to stop."""
    initiator = Initiator(psk=PSK)
    init_msg = initiator.start()
    attacker_key = DHKeyPair.generate(MODP_2048)
    core = ResponseMessage(
        group_id=14, nonce_r=b"\x07" * 32, pub_r=attacker_key.public_bytes()
    )
    transcript = transcript_hash(init_msg.encode(), core.core_bytes())
    forged = ResponseMessage(
        group_id=14,
        nonce_r=b"\x07" * 32,
        pub_r=attacker_key.public_bytes(),
        tag_r=hmac_sha256(b"guessed psk", transcript),
    )
    with pytest.raises(AuthenticationError):
        initiator.finish(forged)


def test_key_derivation_binds_every_input():
    """Changing any one input must change every derived key."""
    base = dict(
        shared_secret=b"\x01" * 256,
        psk=b"psk",
        nonce_i=b"\x02" * 32,
        nonce_r=b"\x03" * 32,
        transcript=b"\x04" * 32,
    )
    reference = derive_keys(**base)
    for field, altered in [
        ("shared_secret", b"\x09" * 256),
        ("psk", b"other"),
        ("nonce_i", b"\x09" * 32),
        ("nonce_r", b"\x09" * 32),
        ("transcript", b"\x09" * 32),
    ]:
        changed = derive_keys(**{**base, field: altered})
        assert changed != reference, f"{field} is not bound into the key schedule"


def test_key_derivation_is_deterministic():
    args = (b"\x01" * 256, b"psk", b"\x02" * 32, b"\x03" * 32, b"\x04" * 32)
    assert derive_keys(*args) == derive_keys(*args)
