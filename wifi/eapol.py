"""EAPOL-Key parsing and WPA2 four-way handshake tracking.

The four-way handshake is the closest real-world relative of the AKEX
protocol in the other half of this lab, and the comparison is the point:

    AKEX                          WPA2 four-way handshake
    ----                          -----------------------
    PSK, hashed into HKDF salt    PMK, from PBKDF2(passphrase, SSID)
    ephemeral DH secret           ANonce + SNonce, no DH at all
    HKDF-SHA256 key schedule      PRF-384/512 -> PTK, split into KCK/KEK/TK
    HMAC tag over the transcript  Key MIC under the KCK
    tag_r in message 2            MIC on messages 2, 3, 4

The structural difference that matters: WPA2 has no Diffie-Hellman, so the
PTK is a deterministic function of the PMK and the two nonces. Anyone who
captures the handshake and later guesses the passphrase recovers the PTK and
decrypts the whole session retroactively. AKEX and WPA3-SAE both fix this
with a fresh key exchange per session -- that is what forward secrecy buys.

This module reads handshake *metadata* only. It does not attempt to recover
keys or crack passphrases.
"""

import struct
from dataclasses import dataclass, field

EAPOL_TYPE_KEY = 3

DESCRIPTOR_RSN = 2
DESCRIPTOR_WPA1 = 254

# IEEE 802.11-2020 Figure 12-34, Key Information bit positions.
KEY_INFO_PAIRWISE = 1 << 3
KEY_INFO_INSTALL = 1 << 6
KEY_INFO_ACK = 1 << 7
KEY_INFO_MIC = 1 << 8
KEY_INFO_SECURE = 1 << 9
KEY_INFO_ERROR = 1 << 10
KEY_INFO_REQUEST = 1 << 11
KEY_INFO_ENCRYPTED = 1 << 12

# Fixed EAPOL-Key body: descriptor type through key data length.
_KEY_BODY_LEN = 95


class EapolParseError(Exception):
    """Raised when an EAPOL-Key body is truncated or malformed."""


@dataclass
class EapolKeyFrame:
    """One parsed EAPOL-Key frame."""

    descriptor_type: int
    key_info: int
    key_length: int
    replay_counter: int
    nonce: bytes
    key_mic: bytes
    key_data_length: int
    key_data: bytes

    @property
    def pairwise(self) -> bool:
        return bool(self.key_info & KEY_INFO_PAIRWISE)

    @property
    def install(self) -> bool:
        return bool(self.key_info & KEY_INFO_INSTALL)

    @property
    def ack(self) -> bool:
        return bool(self.key_info & KEY_INFO_ACK)

    @property
    def has_mic(self) -> bool:
        return bool(self.key_info & KEY_INFO_MIC)

    @property
    def secure(self) -> bool:
        return bool(self.key_info & KEY_INFO_SECURE)

    @property
    def encrypted_key_data(self) -> bool:
        return bool(self.key_info & KEY_INFO_ENCRYPTED)

    @property
    def nonce_is_zero(self) -> bool:
        """Message 4 carries an all-zero nonce; messages 1-3 carry real ones."""
        return self.nonce == b"\x00" * 32

    def message_number(self) -> int | None:
        """Identify which of the four messages this is, from the flag bits.

        The four messages are distinguished by three bits, because the
        standard never gave them an explicit number:

            M1  pairwise, Ack,        no MIC     (AP sends ANonce)
            M2  pairwise,      MIC,   not Secure (STA sends SNonce + RSN IE)
            M3  pairwise, Ack, MIC,   Secure     (AP confirms, installs key)
            M4  pairwise,      MIC,   Secure     (STA acknowledges)

        M2 and M4 differ only in the Secure bit and the presence of key
        data, which is why a capture that starts mid-handshake can be
        genuinely ambiguous. Returns None rather than guessing.
        """
        if not self.pairwise:
            return None  # group key handshake, not the four-way
        if self.ack and not self.has_mic:
            return 1
        if self.has_mic and not self.ack and not self.secure:
            return 2
        if self.has_mic and self.ack:
            return 3
        if self.has_mic and not self.ack and self.secure:
            return 4
        return None

    def pmkid(self) -> bytes | None:
        """Extract a PMKID from message 1's key data, if the AP included one.

        An AP that volunteers a PMKID in M1 enables the "PMKID attack":
        the PMKID is HMAC-SHA1(PMK, "PMK Name" || AP MAC || STA MAC), so an
        attacker needs only this single frame -- no client, no full
        handshake, no deauthentication -- to mount an offline dictionary
        attack on the passphrase. Worth flagging wherever it appears.
        """
        if self.message_number() != 1 or not self.key_data:
            return None
        data = self.key_data
        offset = 0
        while offset + 2 <= len(data):
            element_id, length = data[offset], data[offset + 1]
            body = data[offset + 2 : offset + 2 + length]
            if len(body) != length:
                return None
            # RSN element (48) whose optional trailing field is a PMKID list.
            if element_id == 221 and len(body) >= 4 and body[:3] == b"\x00\x0f\xac":
                if body[3] == 4 and len(body) >= 20:
                    return body[4:20]
            offset += 2 + length
        return None


def parse_eapol_key(payload: bytes) -> EapolKeyFrame:
    """Parse an EAPOL-Key frame starting at the EAPOL header."""
    if len(payload) < 4:
        raise EapolParseError("EAPOL header truncated")
    _version, packet_type, _body_length = struct.unpack("!BBH", payload[:4])
    if packet_type != EAPOL_TYPE_KEY:
        raise EapolParseError(f"EAPOL packet type {packet_type} is not Key")

    body = payload[4:]
    if len(body) < _KEY_BODY_LEN:
        raise EapolParseError("EAPOL-Key body truncated")

    descriptor_type = body[0]
    key_info, key_length = struct.unpack("!HH", body[1:5])
    (replay_counter,) = struct.unpack("!Q", body[5:13])
    nonce = body[13:45]
    # body[45:61] Key IV, body[61:69] Key RSC, body[69:77] reserved.
    key_mic = body[77:93]
    (key_data_length,) = struct.unpack("!H", body[93:95])
    key_data = body[95 : 95 + key_data_length]
    if len(key_data) != key_data_length:
        raise EapolParseError("EAPOL-Key data field truncated")

    return EapolKeyFrame(
        descriptor_type=descriptor_type,
        key_info=key_info,
        key_length=key_length,
        replay_counter=replay_counter,
        nonce=nonce,
        key_mic=key_mic,
        key_data_length=key_data_length,
        key_data=key_data,
    )


@dataclass
class Handshake:
    """State of one four-way handshake between an AP and a station."""

    ap: str
    station: str
    messages: dict[int, float] = field(default_factory=dict)
    replay_counters: dict[int, int] = field(default_factory=dict)
    anonce: bytes | None = None
    snonce: bytes | None = None
    pmkid: bytes | None = None
    frame_indices: dict[int, int] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        """All four messages observed."""
        return set(self.messages) == {1, 2, 3, 4}

    @property
    def observed(self) -> list[int]:
        return sorted(self.messages)

    @property
    def duration_ms(self) -> float | None:
        """Wall-clock time from message 1 to message 4."""
        if not self.complete:
            return None
        return (self.messages[4] - self.messages[1]) * 1000.0

    def notes(self) -> list[str]:
        """Observations about this handshake."""
        out = []
        if self.complete:
            out.append(
                f"complete four-way handshake in {self.duration_ms:.1f} ms; "
                "an observer who records this and later guesses the passphrase "
                "can derive the PTK and decrypt the session offline"
            )
        else:
            missing = [n for n in (1, 2, 3, 4) if n not in self.messages]
            out.append(
                f"incomplete: saw messages {self.observed}, missing {missing} "
                "(capture may have started late, or the handshake failed)"
            )
        if self.pmkid:
            out.append(
                f"AP volunteered a PMKID ({self.pmkid.hex()[:16]}...) in message 1; "
                "this single frame is enough for an offline dictionary attack, "
                "with no client interaction needed"
            )
        # Each message should advance or match the AP's replay counter.
        counters = [self.replay_counters[n] for n in self.observed]
        if counters != sorted(counters):
            out.append(
                f"replay counters out of order across messages: {counters}; "
                "consistent with a replayed or injected EAPOL frame"
            )
        return out


class HandshakeTracker:
    """Groups EAPOL-Key frames into per-(AP, station) handshakes.

    A station may handshake with the same AP several times in one capture --
    after a deauthentication, or on a periodic rekey. Each attempt is kept
    as its own record rather than overwriting the last, because the earlier
    ones are often the interesting ones: the handshake captured right after
    a deauth flood is the attacker's objective, and it is the first message 1
    that tends to carry the PMKID.
    """

    def __init__(self) -> None:
        self._active: dict[tuple[str, str], Handshake] = {}
        self._handshakes: list[Handshake] = []

    def observe(
        self,
        frame: EapolKeyFrame,
        transmitter: str,
        receiver: str,
        timestamp: float,
        index: int,
    ) -> int | None:
        """Record one EAPOL-Key frame. Returns the message number, if known.

        Direction tells us which endpoint is the AP: messages 1 and 3 carry
        the Ack bit and always flow from the authenticator.
        """
        number = frame.message_number()
        if number is None:
            return None

        ap, station = (
            (transmitter, receiver) if number in (1, 3) else (receiver, transmitter)
        )
        key = (ap, station)
        handshake = self._active.get(key)

        # A fresh message 1 starts a new session (a rekey or a reconnection)
        # rather than continuing the old one. The previous handshake stays in
        # the list; only the "currently open" slot is replaced.
        if handshake is None or number == 1:
            handshake = Handshake(ap=ap, station=station)
            self._active[key] = handshake
            self._handshakes.append(handshake)

        handshake.messages[number] = timestamp
        handshake.replay_counters[number] = frame.replay_counter
        handshake.frame_indices[number] = index
        if number == 1:
            handshake.anonce = frame.nonce
            handshake.pmkid = frame.pmkid()
        elif number == 2:
            handshake.snonce = frame.nonce
        return number

    def all(self) -> list[Handshake]:
        """Every handshake attempt, in the order it started."""
        return list(self._handshakes)
