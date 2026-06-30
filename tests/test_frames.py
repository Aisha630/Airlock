"""Frame type/subtype classification tables."""

import pytest

from wifi.frames import (
    REASON_CODES,
    TYPE_CONTROL,
    TYPE_DATA,
    TYPE_MANAGEMENT,
    TYPE_NAMES,
    FrameInfo,
    subtype_name,
)


@pytest.mark.parametrize(
    "frame_type,subtype,expected",
    [
        (TYPE_MANAGEMENT, 8, "beacon"),
        (TYPE_MANAGEMENT, 4, "probe-request"),
        (TYPE_MANAGEMENT, 5, "probe-response"),
        (TYPE_MANAGEMENT, 11, "authentication"),
        (TYPE_MANAGEMENT, 12, "deauthentication"),
        (TYPE_MANAGEMENT, 10, "disassociation"),
        (TYPE_MANAGEMENT, 0, "assoc-request"),
        (TYPE_CONTROL, 13, "ack"),
        (TYPE_CONTROL, 11, "rts"),
        (TYPE_CONTROL, 12, "cts"),
        (TYPE_CONTROL, 9, "block-ack"),
        (TYPE_DATA, 0, "data"),
        (TYPE_DATA, 8, "qos-data"),
        (TYPE_DATA, 4, "null"),
    ],
)
def test_known_subtypes(frame_type, subtype, expected):
    assert subtype_name(frame_type, subtype) == expected


def test_subtype_numbers_do_not_collide_across_types():
    """Subtype 13 is an ACK in control and an Action frame in management."""
    assert subtype_name(TYPE_CONTROL, 13) == "ack"
    assert subtype_name(TYPE_MANAGEMENT, 13) == "action"


def test_unknown_subtype_is_labelled_not_dropped():
    assert subtype_name(TYPE_MANAGEMENT, 7) == "subtype-7"
    assert subtype_name(99, 1) == "subtype-1"


def test_type_names_cover_all_four_types():
    assert set(TYPE_NAMES) == {0, 1, 2, 3}


def test_frame_predicates_are_mutually_exclusive():
    for frame_type in (TYPE_MANAGEMENT, TYPE_CONTROL, TYPE_DATA):
        frame = FrameInfo(
            index=0, timestamp=0.0, frame_type=frame_type, subtype=0,
            type_name=TYPE_NAMES[frame_type], subtype_name="x",
        )
        assert sum([frame.is_management, frame.is_control, frame.is_data]) == 1


def test_addresses_use_receiver_transmitter_naming():
    """addr1 always receives and addr2 always transmits, whatever the DS bits."""
    frame = FrameInfo(
        index=0, timestamp=0.0, frame_type=TYPE_DATA, subtype=8,
        type_name="data", subtype_name="qos-data",
        addr1="aa:aa:aa:aa:aa:aa", addr2="bb:bb:bb:bb:bb:bb",
    )
    assert frame.receiver == "aa:aa:aa:aa:aa:aa"
    assert frame.transmitter == "bb:bb:bb:bb:bb:bb"


def test_describe_includes_the_decoded_reason_code():
    frame = FrameInfo(
        index=0, timestamp=0.0, frame_type=TYPE_MANAGEMENT, subtype=12,
        type_name="management", subtype_name="deauthentication", reason_code=7,
    )
    description = frame.describe()
    assert "deauthentication" in description
    assert REASON_CODES[7] in description
