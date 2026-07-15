"""EAPOL-Key parsing, message identification, and handshake tracking."""

import struct

import pytest

from wifi.eapol import (
    KEY_INFO_ACK,
    KEY_INFO_ENCRYPTED,
    KEY_INFO_INSTALL,
    KEY_INFO_MIC,
    KEY_INFO_PAIRWISE,
    KEY_INFO_SECURE,
    EapolParseError,
    HandshakeTracker,
    parse_eapol_key,
)

AP = "02:00:00:aa:00:01"
STA = "02:00:00:11:11:11"

M1 = KEY_INFO_PAIRWISE | KEY_INFO_ACK
M2 = KEY_INFO_PAIRWISE | KEY_INFO_MIC
M3 = (KEY_INFO_PAIRWISE | KEY_INFO_ACK | KEY_INFO_MIC
      | KEY_INFO_SECURE | KEY_INFO_INSTALL | KEY_INFO_ENCRYPTED)
M4 = KEY_INFO_PAIRWISE | KEY_INFO_MIC | KEY_INFO_SECURE


def build(key_info: int, replay_counter: int = 1, nonce: bytes = b"\xa1" * 32,
          key_data: bytes = b"") -> bytes:
    body = bytes([2]) + struct.pack("!HH", key_info, 16)
    body += struct.pack("!Q", replay_counter) + nonce
    body += b"\x00" * 16 + b"\x00" * 8 + b"\x00" * 8 + b"\x0f" * 16
    body += struct.pack("!H", len(key_data)) + key_data
    return struct.pack("!BBH", 2, 3, len(body)) + body


@pytest.mark.parametrize(
    "key_info,expected", [(M1, 1), (M2, 2), (M3, 3), (M4, 4)]
)
def test_message_numbers_are_identified_from_the_flag_bits(key_info, expected):
    assert parse_eapol_key(build(key_info)).message_number() == expected


def test_message_two_and_four_are_told_apart_by_the_secure_bit():
    """The only structural difference between M2 and M4."""
    assert parse_eapol_key(build(M2)).message_number() == 2
    assert parse_eapol_key(build(M2 | KEY_INFO_SECURE)).message_number() == 4


def test_group_key_handshake_is_not_mistaken_for_the_four_way():
    """Without the Pairwise bit this is a group rekey, not a four-way message."""
    group_frame = parse_eapol_key(build(KEY_INFO_ACK | KEY_INFO_MIC))
    assert not group_frame.pairwise
    assert group_frame.message_number() is None


def test_flag_accessors():
    frame = parse_eapol_key(build(M3))
    assert frame.pairwise and frame.ack and frame.has_mic
    assert frame.secure and frame.install and frame.encrypted_key_data


def test_fields_are_read_from_the_right_offsets():
    frame = parse_eapol_key(build(M1, replay_counter=42, nonce=b"\xbb" * 32))
    assert frame.descriptor_type == 2
    assert frame.replay_counter == 42
    assert frame.nonce == b"\xbb" * 32
    assert frame.key_mic == b"\x0f" * 16
    assert frame.key_length == 16


def test_message_four_carries_a_zero_nonce():
    assert parse_eapol_key(build(M4, nonce=b"\x00" * 32)).nonce_is_zero


def test_pmkid_is_extracted_from_message_one():
    pmkid = bytes.fromhex("0123456789abcdef0123456789abcdef")
    kde = b"\x00\x0f\xac\x04" + pmkid
    key_data = bytes([221, len(kde)]) + kde
    frame = parse_eapol_key(build(M1, key_data=key_data))
    assert frame.pmkid() == pmkid


def test_no_pmkid_when_absent_or_not_message_one():
    assert parse_eapol_key(build(M1)).pmkid() is None
    assert parse_eapol_key(build(M2, key_data=b"\x30\x02\x01\x00")).pmkid() is None


@pytest.mark.parametrize(
    "payload", [b"", b"\x02\x03", b"\x02\x03\x00\x10" + b"\x00" * 10]
)
def test_truncated_frames_are_refused(payload):
    with pytest.raises(EapolParseError):
        parse_eapol_key(payload)


def test_non_key_eapol_packets_are_refused():
    with pytest.raises(EapolParseError, match="not Key"):
        parse_eapol_key(struct.pack("!BBH", 2, 1, 0))  # EAPOL-Start


def test_lying_key_data_length_is_refused():
    body = bytes([2]) + struct.pack("!HH", M1, 16) + struct.pack("!Q", 1)
    body += b"\xa1" * 32 + b"\x00" * 48 + struct.pack("!H", 200)  # claims 200
    with pytest.raises(EapolParseError, match="data field truncated"):
        parse_eapol_key(struct.pack("!BBH", 2, 3, len(body)) + body)


def _run_handshake(tracker, base_time=0.0, counter=1, key_data=b""):
    for index, (key_info, transmitter, receiver) in enumerate([
        (M1, AP, STA), (M2, STA, AP), (M3, AP, STA), (M4, STA, AP)
    ]):
        frame = parse_eapol_key(build(
            key_info,
            replay_counter=counter + (index >= 2),
            key_data=key_data if index == 0 else b"",
        ))
        tracker.observe(frame, transmitter, receiver, base_time + index * 0.01, index)


def test_tracker_assembles_a_complete_handshake():
    tracker = HandshakeTracker()
    _run_handshake(tracker)
    handshakes = tracker.all()
    assert len(handshakes) == 1
    handshake = handshakes[0]
    assert handshake.complete
    assert handshake.observed == [1, 2, 3, 4]
    assert handshake.ap == AP and handshake.station == STA
    assert handshake.duration_ms == pytest.approx(30.0, abs=0.1)


def test_tracker_infers_roles_from_direction():
    """Messages 1 and 3 carry Ack, so their transmitter is the authenticator."""
    tracker = HandshakeTracker()
    _run_handshake(tracker)
    assert tracker.all()[0].ap == AP


def test_tracker_keeps_successive_handshakes_separate():
    """A rekey must not overwrite the earlier handshake, PMKID included."""
    pmkid = bytes.fromhex("aabbccddeeff00112233445566778899")
    kde = b"\x00\x0f\xac\x04" + pmkid
    tracker = HandshakeTracker()
    _run_handshake(tracker, base_time=0.0, counter=1,
                   key_data=bytes([221, len(kde)]) + kde)
    _run_handshake(tracker, base_time=5.0, counter=9)

    handshakes = tracker.all()
    assert len(handshakes) == 2
    assert all(h.complete for h in handshakes)
    assert handshakes[0].pmkid == pmkid
    assert handshakes[1].pmkid is None


def test_incomplete_handshake_is_reported_as_such():
    tracker = HandshakeTracker()
    tracker.observe(parse_eapol_key(build(M1)), AP, STA, 0.0, 0)
    tracker.observe(parse_eapol_key(build(M2)), STA, AP, 0.01, 1)
    handshake = tracker.all()[0]
    assert not handshake.complete
    assert handshake.duration_ms is None
    assert any("incomplete" in note for note in handshake.notes())


def test_out_of_order_replay_counters_are_noted():
    tracker = HandshakeTracker()
    for index, (key_info, transmitter, receiver, counter) in enumerate([
        (M1, AP, STA, 5), (M2, STA, AP, 5), (M3, AP, STA, 2), (M4, STA, AP, 2)
    ]):
        tracker.observe(
            parse_eapol_key(build(key_info, replay_counter=counter)),
            transmitter, receiver, index * 0.01, index,
        )
    assert any("out of order" in note for note in tracker.all()[0].notes())
