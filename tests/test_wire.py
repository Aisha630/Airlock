"""Wire encoding: canonical, round-tripping, and strict about malformed input."""

import pytest

from akex.wire import (
    ConfirmMessage,
    InitMessage,
    ResponseMessage,
    WireError,
    transcript_hash,
)


def test_init_round_trip():
    message = InitMessage(group_id=14, nonce_i=b"\x01" * 32, pub_i=b"\x02" * 256)
    assert InitMessage.decode(message.encode()) == message


def test_response_round_trip():
    message = ResponseMessage(14, b"\x03" * 32, b"\x04" * 256, b"\x05" * 32)
    assert ResponseMessage.decode(message.encode()) == message


def test_confirm_round_trip():
    message = ConfirmMessage(tag_i=b"\x06" * 32)
    assert ConfirmMessage.decode(message.encode()) == message


def test_encoding_is_canonical():
    """The same message must always encode to the same bytes."""
    message = InitMessage(group_id=14, nonce_i=b"\x01" * 32, pub_i=b"\x02" * 256)
    assert message.encode() == message.encode()


def test_response_core_excludes_the_tag():
    """A tag cannot cover itself, so the transcript uses the core bytes."""
    message = ResponseMessage(14, b"\x03" * 32, b"\x04" * 256, b"\x05" * 32)
    assert message.core_bytes() == message.encode()[: -32]


def test_message_types_do_not_cross_decode():
    init = InitMessage(14, b"\x01" * 32, b"\x02" * 256).encode()
    with pytest.raises(WireError, match="not a response"):
        ResponseMessage.decode(init)


@pytest.mark.parametrize(
    "corrupt,match",
    [
        (lambda raw: b"XXXX" + raw[4:], "magic"),
        (lambda raw: raw[:-1], "length mismatch"),
        (lambda raw: raw + b"\x00", "length mismatch"),
        (lambda raw: raw[:4], "truncated"),
    ],
)
def test_malformed_messages_are_refused(corrupt, match):
    raw = InitMessage(14, b"\x01" * 32, b"\x02" * 256).encode()
    with pytest.raises(WireError, match=match):
        InitMessage.decode(corrupt(raw))


def test_transcript_hash_is_order_sensitive():
    assert transcript_hash(b"a", b"b") != transcript_hash(b"b", b"a")


def test_transcript_hash_resists_splicing():
    """Length prefixes make concatenation unambiguous."""
    assert transcript_hash(b"ab", b"c") != transcript_hash(b"a", b"bc")


def test_transcript_hash_is_deterministic():
    assert transcript_hash(b"x", b"y") == transcript_hash(b"x", b"y")
    assert len(transcript_hash(b"x")) == 32
