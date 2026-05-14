"""The AKEX handshake: authenticated ephemeral Diffie-Hellman.

    I -> R   InitMessage      group, nonce_i, g^i
    R -> I   ResponseMessage  nonce_r, g^r, tag_r
    I -> R   ConfirmMessage   tag_i

Plain Diffie-Hellman agrees a key with *somebody* but says nothing about who.
A machine-in-the-middle can run one exchange with each side and relay
plaintext forever. The two tags are what fix that: each is an HMAC over the
handshake transcript under a key derived from both the DH secret and a
pre-shared key, so producing one requires knowing the PSK *and* having run
the exchange. This is the same shape as the WPA2 four-way handshake, where
MICs under a PMK-derived key authenticate nonces the two sides just traded.

Security properties, stated plainly:

  * Mutual authentication, against anyone who does not hold the PSK.
  * Forward secrecy: DH keys are ephemeral, so recording traffic today and
    stealing the PSK tomorrow does not recover the session keys.
  * Transcript integrity: every field of messages 1 and 2, the group id
    included, is hashed into both tags, so a downgrade is detected.
  * Key separation: four independent keys from one exchange via HKDF info
    labels.

What it does not do: resist an offline dictionary attack on a low-entropy
PSK. See THREAT_MODEL.md.
"""

import secrets
from dataclasses import dataclass, field

from .dh import DHKeyPair
from .kdf import constant_time_eq, hkdf_expand, hkdf_extract, hmac_sha256
from .params import DEFAULT_GROUP, DHGroup, get_group
from .wire import (
    LABEL_INITIATOR_AUTH,
    LABEL_RESPONDER_AUTH,
    LABEL_SALT,
    LABEL_SESSION_I2R,
    LABEL_SESSION_R2I,
    NONCE_LEN,
    ConfirmMessage,
    InitMessage,
    ResponseMessage,
    transcript_hash,
)

KEY_LEN = 32


class AuthenticationError(Exception):
    """Raised when a peer's tag does not verify.

    This is the failure that matters. It fires for a tampered transcript, a
    machine-in-the-middle without the PSK, and a wrong PSK alike -- the
    receiver cannot tell which, and does not need to.
    """


class ProtocolError(Exception):
    """Raised when messages arrive out of order or a field is unacceptable."""


@dataclass(frozen=True)
class SessionKeys:
    """The four keys derived from one handshake.

    Directional session keys mean a record the initiator sent can never be
    reflected back at it and accepted as one the responder sent.
    """

    auth_i: bytes
    auth_r: bytes
    session_i2r: bytes
    session_r2i: bytes

    def fingerprint(self) -> str:
        """Short public digest of the session, for demos and logs.

        Derived by hashing, never by printing key material: two parties can
        compare fingerprints out loud without revealing anything useful.
        """
        import hashlib

        return hashlib.sha256(
            b"AKEX v1 fingerprint" + self.session_i2r + self.session_r2i
        ).hexdigest()[:32]


def derive_keys(
    shared_secret: bytes,
    psk: bytes,
    nonce_i: bytes,
    nonce_r: bytes,
    transcript: bytes,
) -> SessionKeys:
    """Turn the DH secret and the PSK into four independent keys.

    Two stages, following HKDF's extract-then-expand split:

    Extract. The salt is a hash of both nonces and the PSK, and the input
    keying material is the DH shared secret. Binding the PSK here means the
    PRK -- and therefore every key below it -- is unreachable without both
    the PSK and the DH secret. Binding the nonces means two handshakes with
    the same PSK and (through some failure) the same DH keys still produce
    different keys.

    Expand. Four calls that differ only in the `info` label, each with the
    transcript hash appended. Distinct labels give independent keys; the
    transcript makes those keys depend on every byte of the handshake, so
    the peers agree on keys only if they saw the identical conversation.
    """
    import hashlib

    salt = hashlib.sha256(LABEL_SALT + nonce_i + nonce_r + psk).digest()
    prk = hkdf_extract(salt, shared_secret)
    return SessionKeys(
        auth_i=hkdf_expand(prk, LABEL_INITIATOR_AUTH + transcript, KEY_LEN),
        auth_r=hkdf_expand(prk, LABEL_RESPONDER_AUTH + transcript, KEY_LEN),
        session_i2r=hkdf_expand(prk, LABEL_SESSION_I2R + transcript, KEY_LEN),
        session_r2i=hkdf_expand(prk, LABEL_SESSION_R2I + transcript, KEY_LEN),
    )


@dataclass
class Initiator:
    """Initiator state machine. Call `start`, then `finish`."""

    psk: bytes
    group: DHGroup = DEFAULT_GROUP
    keypair: DHKeyPair = field(init=False)
    nonce_i: bytes = field(init=False)
    _init_bytes: bytes = field(init=False, default=b"")
    keys: SessionKeys | None = field(init=False, default=None)

    def start(self) -> InitMessage:
        """Generate the ephemeral key pair and nonce, and emit message 1."""
        self.keypair = DHKeyPair.generate(self.group)
        self.nonce_i = secrets.token_bytes(NONCE_LEN)
        message = InitMessage(
            group_id=self.group.group_id,
            nonce_i=self.nonce_i,
            pub_i=self.keypair.public_bytes(),
        )
        self._init_bytes = message.encode()
        return message

    def finish(self, response: ResponseMessage) -> tuple[ConfirmMessage, SessionKeys]:
        """Verify the responder's tag, then emit our own.

        The order is deliberate: derive, verify, and only then treat the
        session as live. Nothing derived from an unverified transcript is
        allowed to escape this method.
        """
        if not self._init_bytes:
            raise ProtocolError("finish() called before start()")
        if response.group_id != self.group.group_id:
            # The group id is inside the transcript, so this would also be
            # caught by the tag check. Failing early gives a clearer error
            # and avoids a pointless 2048-bit modexp.
            raise ProtocolError(
                f"responder changed group: sent {response.group_id}, "
                f"expected {self.group.group_id}"
            )

        peer_public = int.from_bytes(response.pub_r, "big")
        shared = self.keypair.exchange(peer_public)  # validates the peer key

        transcript = transcript_hash(self._init_bytes, response.core_bytes())
        keys = derive_keys(shared, self.psk, self.nonce_i, response.nonce_r, transcript)

        expected = hmac_sha256(keys.auth_r, transcript)
        if not constant_time_eq(expected, response.tag_r):
            raise AuthenticationError(
                "responder tag verification failed: wrong PSK, a tampered "
                "transcript, or a machine-in-the-middle"
            )

        # The initiator's tag covers the responder's tag too, so it confirms
        # the exact message 2 we accepted, not merely its unauthenticated core.
        final_transcript = transcript_hash(self._init_bytes, response.encode())
        confirm = ConfirmMessage(tag_i=hmac_sha256(keys.auth_i, final_transcript))
        self.keys = keys
        return confirm, keys


@dataclass
class Responder:
    """Responder state machine. Call `respond`, then `confirm`."""

    psk: bytes
    group: DHGroup | None = None
    keypair: DHKeyPair = field(init=False)
    nonce_r: bytes = field(init=False)
    _init_bytes: bytes = field(init=False, default=b"")
    _response_bytes: bytes = field(init=False, default=b"")
    _transcript: bytes = field(init=False, default=b"")
    keys: SessionKeys | None = field(init=False, default=None)

    def respond(self, init: InitMessage) -> tuple[ResponseMessage, SessionKeys]:
        """Process message 1 and emit message 2 with our tag.

        The responder authenticates first. That ordering is what lets the
        initiator abort against an impostor before sending anything of its
        own, and it mirrors the WPA2 four-way handshake, where the AP's
        message 3 MIC is what proves the AP knows the PMK.
        """
        group = get_group(init.group_id)  # rejects unknown ids outright
        if self.group is not None and group.group_id != self.group.group_id:
            raise ProtocolError(
                f"initiator requested group {group.group_id}, "
                f"policy requires {self.group.group_id}"
            )
        self.group = group

        if len(init.pub_i) != group.size_bytes:
            raise ProtocolError(
                f"public key is {len(init.pub_i)} bytes, "
                f"group {group.group_id} requires {group.size_bytes}"
            )

        self.keypair = DHKeyPair.generate(group)
        self.nonce_r = secrets.token_bytes(NONCE_LEN)

        peer_public = int.from_bytes(init.pub_i, "big")
        shared = self.keypair.exchange(peer_public)  # validates the peer key

        response = ResponseMessage(
            group_id=group.group_id,
            nonce_r=self.nonce_r,
            pub_r=self.keypair.public_bytes(),
        )
        self._init_bytes = init.encode()
        transcript = transcript_hash(self._init_bytes, response.core_bytes())
        keys = derive_keys(shared, self.psk, init.nonce_i, self.nonce_r, transcript)

        response = ResponseMessage(
            group_id=group.group_id,
            nonce_r=self.nonce_r,
            pub_r=self.keypair.public_bytes(),
            tag_r=hmac_sha256(keys.auth_r, transcript),
        )
        self._response_bytes = response.encode()
        self._transcript = transcript
        self.keys = keys
        return response, keys

    def confirm(self, confirm: ConfirmMessage) -> SessionKeys:
        """Verify the initiator's tag. Until this succeeds, nothing is live.

        The responder has usable keys after `respond`, but it must not act on
        them yet: at that point it has proved itself to the initiator without
        the initiator having proved anything back.
        """
        if not self._response_bytes or self.keys is None:
            raise ProtocolError("confirm() called before respond()")

        final_transcript = transcript_hash(self._init_bytes, self._response_bytes)
        expected = hmac_sha256(self.keys.auth_i, final_transcript)
        if not constant_time_eq(expected, confirm.tag_i):
            raise AuthenticationError(
                "initiator tag verification failed: wrong PSK, a tampered "
                "transcript, or a machine-in-the-middle"
            )
        return self.keys


def run_handshake(
    psk: bytes, group: DHGroup = DEFAULT_GROUP
) -> tuple[SessionKeys, SessionKeys]:
    """Run a full in-process handshake. Returns (initiator keys, responder keys)."""
    initiator = Initiator(psk=psk, group=group)
    responder = Responder(psk=psk, group=group)

    init_msg = initiator.start()
    response, responder_keys = responder.respond(InitMessage.decode(init_msg.encode()))
    confirm, initiator_keys = initiator.finish(
        ResponseMessage.decode(response.encode())
    )
    responder.confirm(ConfirmMessage.decode(confirm.encode()))
    return initiator_keys, responder_keys
