"""An authenticated record layer over the derived session keys.

Scope, stated up front so the README and the code agree: this layer provides
*integrity and authenticity only*. It does not encrypt. Messages travel in
the clear with an HMAC-SHA256 tag over a header that includes a sequence
number. Adding confidentiality would mean swapping the MAC for an AEAD
(AES-GCM or ChaCha20-Poly1305) keyed by the same session key -- a change
confined to `seal` and `open_record`. That is left out deliberately rather
than by oversight: calling a library AEAD would add a line of code and no
understanding, and the properties this layer *does* have are the ones the
tamper and replay demos exercise.
"""

import struct
from dataclasses import dataclass, field

from .kdf import constant_time_eq, hmac_sha256
from .protocol import SessionKeys
from .wire import LABEL_RECORD, TAG_LEN

DIR_I2R = 0
DIR_R2I = 1

# A 64-bit counter cannot wrap in any realistic session, but the check below
# is explicit rather than assumed: a silently wrapping counter would let an
# old record replay as a new one.
MAX_SEQ = (1 << 64) - 1


class RecordError(Exception):
    """Raised when a record fails authentication, ordering, or parsing."""


def _header(direction: int, seq: int, payload_len: int) -> bytes:
    """Build the authenticated header.

    The direction and the sequence number are covered by the tag, not merely
    transmitted. Leaving either out of the MAC input would allow reflection
    (bouncing a record back at its sender) and reordering respectively.
    The payload length is included so that a truncated record cannot be
    passed off as a shorter valid one.
    """
    return LABEL_RECORD + struct.pack("!BQI", direction, seq, payload_len)


@dataclass
class AuthenticatedChannel:
    """One direction's worth of send/receive state for a peer.

    Each peer holds one channel with a send key and a receive key, taken from
    the two directional session keys in opposite order.
    """

    send_key: bytes
    recv_key: bytes
    send_direction: int
    recv_direction: int
    send_seq: int = field(default=0)
    recv_seq: int = field(default=0)

    @classmethod
    def for_initiator(cls, keys: SessionKeys) -> "AuthenticatedChannel":
        return cls(
            send_key=keys.session_i2r,
            recv_key=keys.session_r2i,
            send_direction=DIR_I2R,
            recv_direction=DIR_R2I,
        )

    @classmethod
    def for_responder(cls, keys: SessionKeys) -> "AuthenticatedChannel":
        return cls(
            send_key=keys.session_r2i,
            recv_key=keys.session_i2r,
            send_direction=DIR_R2I,
            recv_direction=DIR_I2R,
        )

    def seal(self, payload: bytes) -> bytes:
        """Authenticate a payload and advance the send counter."""
        if self.send_seq > MAX_SEQ:
            raise RecordError("sequence number space exhausted; rekey required")
        header = _header(self.send_direction, self.send_seq, len(payload))
        tag = hmac_sha256(self.send_key, header + payload)
        record = struct.pack("!QI", self.send_seq, len(payload)) + payload + tag
        self.send_seq += 1
        return record

    def open_record(self, record: bytes) -> bytes:
        """Verify a record and return its payload.

        Ordering matters here. The tag is checked *before* the sequence
        number is accepted, so an attacker cannot move our replay window by
        sending unauthenticated garbage with a high sequence number.
        """
        if len(record) < 12 + TAG_LEN:
            raise RecordError("record truncated")
        seq, payload_len = struct.unpack("!QI", record[:12])
        payload = record[12 : 12 + payload_len]
        tag = record[12 + payload_len :]
        if len(payload) != payload_len or len(tag) != TAG_LEN:
            raise RecordError("record length mismatch")

        header = _header(self.recv_direction, seq, payload_len)
        expected = hmac_sha256(self.recv_key, header + payload)
        if not constant_time_eq(expected, tag):
            raise RecordError(
                "MAC verification failed: the record was modified in transit, "
                "forged, or reflected from the other direction"
            )

        # Strictly increasing sequence numbers. This rejects both a verbatim
        # replay (seq == recv_seq - 1) and any attempt to reorder records,
        # which for an authenticated-but-unencrypted channel is the remaining
        # way to change what the application sees without breaking a MAC.
        if seq < self.recv_seq:
            raise RecordError(
                f"replay or reorder detected: got sequence {seq}, "
                f"expected at least {self.recv_seq}"
            )
        self.recv_seq = seq + 1
        return payload
