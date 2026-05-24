"""The record layer: integrity, ordering, direction, and framing."""

import pytest

from akex.channel import AuthenticatedChannel, RecordError
from akex.protocol import run_handshake

PSK = b"record layer test key"


def _pair():
    initiator_keys, responder_keys = run_handshake(PSK)
    return (
        AuthenticatedChannel.for_initiator(initiator_keys),
        AuthenticatedChannel.for_responder(responder_keys),
    )


def test_round_trip():
    sender, receiver = _pair()
    for payload in (b"", b"short", b"x" * 4096):
        assert receiver.open_record(sender.seal(payload)) == payload


def test_both_directions_work_independently():
    initiator, responder = _pair()
    assert responder.open_record(initiator.seal(b"ping")) == b"ping"
    assert initiator.open_record(responder.seal(b"pong")) == b"pong"


@pytest.mark.parametrize("offset", [0, 8, 12, 15, -1])
def test_any_single_bit_flip_is_detected(offset):
    """Header, payload and tag are all covered by the MAC."""
    sender, receiver = _pair()
    record = bytearray(sender.seal(b"an important instruction"))
    record[offset] ^= 0x01
    with pytest.raises(RecordError):
        receiver.open_record(bytes(record))


def test_replay_is_rejected():
    sender, receiver = _pair()
    record = sender.seal(b"unlock")
    assert receiver.open_record(record) == b"unlock"
    with pytest.raises(RecordError, match="replay"):
        receiver.open_record(record)


def test_reordering_is_rejected():
    """Records must arrive in order; an out-of-order valid record is refused."""
    sender, receiver = _pair()
    first = sender.seal(b"one")
    second = sender.seal(b"two")
    assert receiver.open_record(second) == b"two"
    with pytest.raises(RecordError, match="replay or reorder"):
        receiver.open_record(first)


def test_reflection_is_rejected():
    """A record sent by A must not verify when replayed back at A."""
    initiator, _responder = _pair()
    record = initiator.seal(b"bounce")
    with pytest.raises(RecordError, match="MAC verification failed"):
        initiator.open_record(record)


def test_records_from_a_different_session_are_rejected():
    sender, _ = _pair()
    _, other_receiver = _pair()
    with pytest.raises(RecordError, match="MAC verification failed"):
        other_receiver.open_record(sender.seal(b"cross-session"))


def test_truncated_record_is_rejected():
    sender, receiver = _pair()
    record = sender.seal(b"payload here")
    with pytest.raises(RecordError):
        receiver.open_record(record[:-1])
    with pytest.raises(RecordError, match="truncated"):
        receiver.open_record(record[:8])


def test_declared_length_must_match_the_actual_payload():
    """A lying length field must not let an attacker reshape the record."""
    sender, receiver = _pair()
    record = bytearray(sender.seal(b"0123456789"))
    record[8:12] = (9).to_bytes(4, "big")  # claim one byte fewer
    with pytest.raises(RecordError):
        receiver.open_record(bytes(record))


def test_sequence_numbers_advance():
    sender, receiver = _pair()
    for expected in range(5):
        assert sender.send_seq == expected
        receiver.open_record(sender.seal(b"tick"))
    assert receiver.recv_seq == 5
