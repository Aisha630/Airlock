"""Canonical wire encoding for handshake messages.

Every field is fixed-width or length-prefixed and every integer is
big-endian. The encoding has to be *canonical* -- exactly one byte string per
message -- because the transcript hash is computed over these bytes. If two
different encodings of the same logical message were both accepted, an
attacker could show one to each party and break the transcript binding.
"""

import hashlib
import struct
from dataclasses import dataclass

MAGIC = b"AKX1"
NONCE_LEN = 32
TAG_LEN = 32

MSG_INIT = 1
MSG_RESPONSE = 2
MSG_CONFIRM = 3

# Domain-separation labels. Distinct strings keep a tag computed for one
# purpose from ever verifying in another position in the protocol.
LABEL_RESPONDER_AUTH = b"AKEX v1 responder auth"
LABEL_INITIATOR_AUTH = b"AKEX v1 initiator auth"
LABEL_SESSION_I2R = b"AKEX v1 session key i2r"
LABEL_SESSION_R2I = b"AKEX v1 session key r2i"
LABEL_SALT = b"AKEX v1 salt"
LABEL_RECORD = b"AKEX v1 record"


class WireError(Exception):
    """Raised on a malformed or truncated message."""


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise WireError(message)


@dataclass(frozen=True)
class InitMessage:
    """Message 1, initiator -> responder: group choice, nonce, public key."""

    group_id: int
    nonce_i: bytes
    pub_i: bytes

    def encode(self) -> bytes:
        _check(len(self.nonce_i) == NONCE_LEN, "bad initiator nonce length")
        return (
            MAGIC
            + struct.pack("!BHH", MSG_INIT, self.group_id, len(self.pub_i))
            + self.nonce_i
            + self.pub_i
        )

    @classmethod
    def decode(cls, raw: bytes) -> "InitMessage":
        _check(len(raw) >= 9, "init message truncated")
        _check(raw[:4] == MAGIC, "bad magic")
        msg_type, group_id, pub_len = struct.unpack("!BHH", raw[4:9])
        _check(msg_type == MSG_INIT, "not an init message")
        body = raw[9:]
        _check(len(body) == NONCE_LEN + pub_len, "init message length mismatch")
        return cls(
            group_id=group_id,
            nonce_i=body[:NONCE_LEN],
            pub_i=body[NONCE_LEN:],
        )


@dataclass(frozen=True)
class ResponseMessage:
    """Message 2, responder -> initiator: nonce, public key, and auth tag.

    `core_bytes` (everything but the tag) is what gets hashed into the
    transcript the tag commits to -- a tag cannot cover itself.
    """

    group_id: int
    nonce_r: bytes
    pub_r: bytes
    tag_r: bytes = b""

    def core_bytes(self) -> bytes:
        _check(len(self.nonce_r) == NONCE_LEN, "bad responder nonce length")
        return (
            MAGIC
            + struct.pack("!BHH", MSG_RESPONSE, self.group_id, len(self.pub_r))
            + self.nonce_r
            + self.pub_r
        )

    def encode(self) -> bytes:
        _check(len(self.tag_r) == TAG_LEN, "bad responder tag length")
        return self.core_bytes() + self.tag_r

    @classmethod
    def decode(cls, raw: bytes) -> "ResponseMessage":
        _check(len(raw) >= 9, "response message truncated")
        _check(raw[:4] == MAGIC, "bad magic")
        msg_type, group_id, pub_len = struct.unpack("!BHH", raw[4:9])
        _check(msg_type == MSG_RESPONSE, "not a response message")
        body = raw[9:]
        _check(
            len(body) == NONCE_LEN + pub_len + TAG_LEN,
            "response message length mismatch",
        )
        return cls(
            group_id=group_id,
            nonce_r=body[:NONCE_LEN],
            pub_r=body[NONCE_LEN : NONCE_LEN + pub_len],
            tag_r=body[NONCE_LEN + pub_len :],
        )


@dataclass(frozen=True)
class ConfirmMessage:
    """Message 3, initiator -> responder: proof the initiator holds the PSK."""

    tag_i: bytes

    def encode(self) -> bytes:
        _check(len(self.tag_i) == TAG_LEN, "bad initiator tag length")
        return MAGIC + bytes([MSG_CONFIRM]) + self.tag_i

    @classmethod
    def decode(cls, raw: bytes) -> "ConfirmMessage":
        _check(len(raw) == 5 + TAG_LEN, "confirm message length mismatch")
        _check(raw[:4] == MAGIC, "bad magic")
        _check(raw[4] == MSG_CONFIRM, "not a confirm message")
        return cls(tag_i=raw[5:])


def transcript_hash(*chunks: bytes) -> bytes:
    """Hash an ordered list of message encodings into a transcript digest.

    Each chunk is length-prefixed before hashing so that concatenation is
    unambiguous. Without the prefix, (b"ab", b"c") and (b"a", b"bc") would
    produce the same digest -- a splicing attack on the transcript itself.
    """
    h = hashlib.sha256()
    for chunk in chunks:
        h.update(struct.pack("!I", len(chunk)))
        h.update(chunk)
    return h.digest()
