"""802.11 frame classification from header metadata.

The type/subtype pair lives in the two-byte Frame Control field at the head
of every 802.11 MAC header, which is transmitted in the clear even on a
fully protected network. This is the basis of the analyzer: an observer
who cannot read a single byte of your traffic can still see who is talking
to whom, when, and what they are doing.
"""

from dataclasses import dataclass, field

# IEEE 802.11-2020, Table 9-1. Type 3 is reserved for frame extensions
# (S1G / DMG); it is listed so unknown frames are labelled rather than lost.
TYPE_MANAGEMENT = 0
TYPE_CONTROL = 1
TYPE_DATA = 2
TYPE_EXTENSION = 3

TYPE_NAMES = {
    TYPE_MANAGEMENT: "management",
    TYPE_CONTROL: "control",
    TYPE_DATA: "data",
    TYPE_EXTENSION: "extension",
}

MANAGEMENT_SUBTYPES = {
    0: "assoc-request",
    1: "assoc-response",
    2: "reassoc-request",
    3: "reassoc-response",
    4: "probe-request",
    5: "probe-response",
    6: "timing-advertisement",
    8: "beacon",
    9: "atim",
    10: "disassociation",
    11: "authentication",
    12: "deauthentication",
    13: "action",
    14: "action-no-ack",
}

CONTROL_SUBTYPES = {
    2: "trigger",
    4: "beamforming-report-poll",
    5: "vht-he-ndp-announcement",
    6: "control-frame-extension",
    7: "control-wrapper",
    8: "block-ack-request",
    9: "block-ack",
    10: "ps-poll",
    11: "rts",
    12: "cts",
    13: "ack",
    14: "cf-end",
    15: "cf-end-cf-ack",
}

DATA_SUBTYPES = {
    0: "data",
    1: "data-cf-ack",
    2: "data-cf-poll",
    3: "data-cf-ack-poll",
    4: "null",
    5: "cf-ack",
    6: "cf-poll",
    7: "cf-ack-poll",
    8: "qos-data",
    9: "qos-data-cf-ack",
    10: "qos-data-cf-poll",
    11: "qos-data-cf-ack-poll",
    12: "qos-null",
    14: "qos-cf-poll",
    15: "qos-cf-ack-poll",
}

SUBTYPE_TABLES = {
    TYPE_MANAGEMENT: MANAGEMENT_SUBTYPES,
    TYPE_CONTROL: CONTROL_SUBTYPES,
    TYPE_DATA: DATA_SUBTYPES,
}

# IEEE 802.11-2020, Table 9-49. Only the codes this analyzer expects to
# see are named; anything else is reported by number.
REASON_CODES = {
    1: "unspecified",
    2: "previous authentication no longer valid",
    3: "deauthenticated because sending STA is leaving",
    4: "disassociated due to inactivity",
    5: "disassociated because AP is out of resources",
    6: "class 2 frame received from nonauthenticated STA",
    7: "class 3 frame received from nonassociated STA",
    8: "disassociated because sending STA is leaving",
    9: "STA requesting association is not authenticated",
    15: "4-way handshake timeout",
    16: "group key handshake timeout",
    23: "IEEE 802.1X authentication failed",
}

STATUS_CODES = {
    0: "success",
    1: "unspecified failure",
    17: "association denied: too many STAs",
    43: "invalid pairwise cipher",
    53: "invalid PMKID",
    76: "authentication rejected: anti-clogging token required",
    77: "authentication rejected: unsupported finite cyclic group",
}


def subtype_name(frame_type: int, subtype: int) -> str:
    """Human-readable subtype, falling back to the raw number."""
    table = SUBTYPE_TABLES.get(frame_type, {})
    return table.get(subtype, f"subtype-{subtype}")


@dataclass
class FrameInfo:
    """Metadata extracted from one captured 802.11 frame.

    Address semantics depend on the To DS / From DS bits, so `addr1..addr3`
    are kept under their positional names rather than being guessed into
    source/destination. `transmitter` and `receiver` hold the one
    interpretation that is always true: addr1 receives, addr2 transmits.
    """

    index: int
    timestamp: float
    frame_type: int
    subtype: int
    type_name: str
    subtype_name: str
    addr1: str | None = None
    addr2: str | None = None
    addr3: str | None = None
    bssid: str | None = None
    ssid: str | None = None
    to_ds: bool = False
    from_ds: bool = False
    protected: bool = False
    retry: bool = False
    length: int = 0
    signal_dbm: int | None = None
    channel: int | None = None
    reason_code: int | None = None
    status_code: int | None = None
    suspect: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def transmitter_is_valid(self) -> bool:
        """True when addr2 is a legal individual (unicast) address.

        IEEE 802.11 requires the transmitter address to be an individual
        address: the low bit of the first octet (the Individual/Group bit)
        must be clear. A frame claiming to be transmitted *by* a group
        address is structurally impossible, so in a real capture it means
        the frame was received corrupted -- monitor mode hands up frames
        that failed their checksum, and a flipped bit in the address field
        is as likely as anywhere else.

        This is an exact test, not a heuristic, which is why it is used to
        exclude frames rather than merely to flag them.
        """
        if not self.addr2:
            return True  # ACK and CTS legitimately carry no addr2
        try:
            return not (int(self.addr2.split(":")[0], 16) & 0x01)
        except (ValueError, IndexError):
            return False

    @property
    def receiver(self) -> str | None:
        """addr1 is the receiver address in every frame type."""
        return self.addr1

    @property
    def transmitter(self) -> str | None:
        """addr2 is the transmitter. Absent in ACK and CTS, which have no addr2."""
        return self.addr2

    @property
    def is_management(self) -> bool:
        return self.frame_type == TYPE_MANAGEMENT

    @property
    def is_control(self) -> bool:
        return self.frame_type == TYPE_CONTROL

    @property
    def is_data(self) -> bool:
        return self.frame_type == TYPE_DATA

    def describe(self) -> str:
        """One-line summary for the report tables."""
        parts = [f"{self.type_name}/{self.subtype_name}"]
        if self.ssid is not None:
            parts.append(f'ssid="{self.ssid}"')
        if self.transmitter:
            parts.append(f"from {self.transmitter}")
        if self.receiver:
            parts.append(f"to {self.receiver}")
        if self.protected:
            parts.append("protected")
        if self.reason_code is not None:
            reason = REASON_CODES.get(self.reason_code, "unknown")
            parts.append(f"reason={self.reason_code} ({reason})")
        return " ".join(parts)
