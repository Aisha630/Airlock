"""Finite-field Diffie-Hellman with strict public-key validation.

The arithmetic here is three lines. Everything else is validation, which is
where finite-field DH actually goes wrong in practice.
"""

import secrets
from dataclasses import dataclass

from .params import DEFAULT_GROUP, DHGroup


class InvalidPublicKey(Exception):
    """Raised when a peer's public value fails validation.

    Treated as fatal by the protocol layer: a peer sending an invalid public
    key is either broken or probing, and neither deserves a second message.
    """


# A 256-bit exponent gives ~128-bit security in these groups: the best known
# attack on the discrete log is the generic sqrt(2^256) = 2^128 baby-step
# giant-step / Pollard rho bound. Using a full-width (2048-bit) exponent costs
# 8x the modexp time and buys nothing.
EXPONENT_BITS = 256


def validate_public_key(y: int, group: DHGroup) -> None:
    """Reject peer public values that are not honest subgroup elements.

    Two distinct checks, for two distinct attacks:

    1. Range. y in {0, 1, p-1} forces the shared secret to a value the
       attacker already knows (0, 1, or +/-1), regardless of our private key.
       This is the classic "small subgroup confinement" degenerate case.

    2. Subgroup membership, y^q mod p == 1. In a safe-prime group the only
       subgroups are of order 1, 2, q, and 2q. An element outside the
       order-q subgroup leaks one bit of our private exponent per handshake
       through the Legendre symbol of the shared secret. Cheap to check,
       so we check it.
    """
    if not isinstance(y, int):
        raise InvalidPublicKey("public key must be an integer")
    if y <= 1 or y >= group.p - 1:
        raise InvalidPublicKey(
            "public key outside the valid range 2 <= y <= p-2 "
            "(degenerate value forces a known shared secret)"
        )
    if pow(y, group.q, group.p) != 1:
        raise InvalidPublicKey(
            "public key is not in the prime-order subgroup "
            "(leaks private-key bits via the Legendre symbol)"
        )


@dataclass
class DHKeyPair:
    """An ephemeral DH key pair. One handshake, then discard.

    Ephemeral keys are what give this protocol forward secrecy: the private
    exponent never touches disk, so a later compromise of the long-term PSK
    does not decrypt a recorded past session.
    """

    group: DHGroup
    private: int
    public: int

    @classmethod
    def generate(cls, group: DHGroup = DEFAULT_GROUP) -> "DHKeyPair":
        """Generate a fresh key pair using the OS CSPRNG.

        `secrets` is used rather than `random`: the Mersenne Twister behind
        `random` is fully reconstructible from 624 observed outputs.
        """
        while True:
            # Range [2, 2^256) -- reject 0 and 1, which give trivial publics.
            private = secrets.randbelow(1 << EXPONENT_BITS)
            if private < 2:
                continue
            public = pow(group.g, private, group.p)
            # g generates the order-q subgroup, so this only trips on an
            # astronomically unlikely exponent. Checked anyway.
            if 1 < public < group.p - 1:
                return cls(group=group, private=private, public=public)

    def public_bytes(self) -> bytes:
        """Encode the public value at the group's fixed width."""
        return self.public.to_bytes(self.group.size_bytes, "big")

    def exchange(self, peer_public: int) -> bytes:
        """Validate the peer's public value and compute the shared secret.

        Returns the secret zero-padded to the group width. The padding
        matters: an unpadded encoding would make the shared secret's *length*
        depend on its value, and that length feeds the key schedule.
        """
        validate_public_key(peer_public, self.group)
        shared = pow(peer_public, self.private, self.group.p)
        if shared <= 1:
            # Unreachable given the validation above; kept as a hard stop so
            # that a future change to validation cannot silently produce a
            # degenerate secret.
            raise InvalidPublicKey("degenerate shared secret")
        return shared.to_bytes(self.group.size_bytes, "big")
