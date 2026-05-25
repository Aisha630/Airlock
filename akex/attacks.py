"""Adversary simulations against AKEX.

Each function plays one attack and returns a short verdict. The point of the
module is not that the attacks fail -- it is that the *reason* each one fails
maps to one specific design decision, and that removing that decision makes
the attack succeed. `mitm_unauthenticated_dh` is the control: the same
machine-in-the-middle, run against a key exchange with the authentication
taken out, and it wins.
"""

import secrets
from dataclasses import dataclass

from .channel import AuthenticatedChannel, RecordError
from .dh import DHKeyPair, InvalidPublicKey
from .kdf import hmac_sha256
from .params import DEFAULT_GROUP, MODP_3072
from .protocol import (
    AuthenticationError,
    Initiator,
    ProtocolError,
    Responder,
    run_handshake,
)
from .wire import ConfirmMessage, InitMessage, ResponseMessage, transcript_hash

PSK = b"correct horse battery staple"


@dataclass
class Result:
    """Outcome of one simulated attack."""

    name: str
    defended: bool
    detail: str
    defense: str

    def render(self) -> str:
        mark = "BLOCKED" if self.defended else "SUCCEEDED"
        return (
            f"[{mark:>9}] {self.name}\n"
            f"             what happened: {self.detail}\n"
            f"             mechanism:     {self.defense}"
        )


def baseline() -> Result:
    """Control case: an honest handshake must actually work."""
    initiator_keys, responder_keys = run_handshake(PSK)
    agreed = initiator_keys == responder_keys
    return Result(
        name="Honest handshake (control)",
        defended=agreed,
        detail=(
            f"both parties derived identical keys; "
            f"session fingerprint {initiator_keys.fingerprint()}"
        ),
        defense="Diffie-Hellman agreement over MODP group 14, keys via HKDF-SHA256",
    )


def wrong_psk() -> Result:
    """A peer with the wrong pre-shared key must not complete the handshake."""
    initiator = Initiator(psk=PSK)
    responder = Responder(psk=b"a different pre-shared key")
    init_msg = initiator.start()
    response, _ = responder.respond(init_msg)
    try:
        initiator.finish(response)
    except AuthenticationError as exc:
        return Result(
            name="Peer with the wrong PSK",
            defended=True,
            detail=str(exc),
            defense=(
                "the PSK is hashed into the HKDF salt, so a different PSK "
                "yields a different auth key and an unverifiable tag"
            ),
        )
    return Result("Peer with the wrong PSK", False, "handshake completed", "none")


def tamper_with_transcript() -> Result:
    """Flipping a single bit of the responder's nonce must be caught.

    The nonce is the right field to target for this demo. Corrupting the
    public key instead would trip the subgroup check in `dh.py` first, which
    is a real defense but a different one -- tampering with the nonce leaves
    every structural check satisfied, so the transcript tag is the only thing
    standing between the attacker and a completed handshake.
    """
    initiator = Initiator(psk=PSK)
    responder = Responder(psk=PSK)
    init_msg = initiator.start()
    response, _ = responder.respond(init_msg)

    corrupted_nonce = bytearray(response.nonce_r)
    corrupted_nonce[-1] ^= 0x01  # one bit
    forged = ResponseMessage(
        group_id=response.group_id,
        nonce_r=bytes(corrupted_nonce),
        pub_r=response.pub_r,
        tag_r=response.tag_r,
    )
    try:
        initiator.finish(forged)
    except (AuthenticationError, InvalidPublicKey) as exc:
        return Result(
            name="Single-bit tamper with the handshake transcript (nonce)",
            defended=True,
            detail=f"{type(exc).__name__}: {exc}",
            defense=(
                "every handshake field is hashed into the transcript that "
                "both tags commit to; one flipped bit changes the digest"
            ),
        )
    return Result(
        "Single-bit tamper with the handshake transcript (nonce)", False, "accepted", "none"
    )


def tamper_with_record() -> Result:
    """Modifying application data after the handshake must be caught."""
    initiator_keys, responder_keys = run_handshake(PSK)
    sender = AuthenticatedChannel.for_initiator(initiator_keys)
    receiver = AuthenticatedChannel.for_responder(responder_keys)

    record = bytearray(sender.seal(b"TRANSFER 100 TO ACCOUNT 4471"))
    # Rewrite the amount in flight. Offset 12 skips the sequence/length header.
    record[12 + 9] = ord("9")
    try:
        receiver.open_record(bytes(record))
    except RecordError as exc:
        return Result(
            name="Tamper with an application record in flight",
            defended=True,
            detail=str(exc),
            defense="HMAC-SHA256 over header plus payload, compared in constant time",
        )
    return Result(
        "Tamper with an application record in flight", False, "accepted", "none"
    )


def replay_record() -> Result:
    """Re-sending a captured, perfectly valid record must be caught."""
    initiator_keys, responder_keys = run_handshake(PSK)
    sender = AuthenticatedChannel.for_initiator(initiator_keys)
    receiver = AuthenticatedChannel.for_responder(responder_keys)

    record = sender.seal(b"UNLOCK DOOR")
    receiver.open_record(record)  # legitimate delivery
    try:
        receiver.open_record(record)  # attacker rebroadcasts the same bytes
    except RecordError as exc:
        return Result(
            name="Replay of a captured valid record",
            defended=True,
            detail=str(exc),
            defense=(
                "the sequence number is inside the MAC input and the receiver "
                "requires it to strictly increase, so a valid tag is not enough"
            ),
        )
    return Result("Replay of a captured valid record", False, "accepted", "none")


def mitm_against_akex() -> Result:
    """A machine-in-the-middle without the PSK substitutes its own DH key.

    The attacker runs a clean exchange with each side. The DH math works
    perfectly -- it always does. The attacker fails at the tag, because
    forging one requires the PSK.
    """
    initiator = Initiator(psk=PSK)
    responder = Responder(psk=PSK)
    attacker_key = DHKeyPair.generate(DEFAULT_GROUP)

    init_msg = initiator.start()
    # Attacker swaps in its own public key toward the responder.
    responder.respond(
        InitMessage(
            group_id=init_msg.group_id,
            nonce_i=init_msg.nonce_i,
            pub_i=attacker_key.public_bytes(),
        )
    )
    # ...and forges a response toward the initiator, with the best tag it can
    # produce: an HMAC under a key derived from a guessed PSK.
    attacker_nonce = secrets.token_bytes(32)
    forged_core = ResponseMessage(
        group_id=init_msg.group_id,
        nonce_r=attacker_nonce,
        pub_r=attacker_key.public_bytes(),
    )
    guessed_transcript = transcript_hash(init_msg.encode(), forged_core.core_bytes())
    forged = ResponseMessage(
        group_id=init_msg.group_id,
        nonce_r=attacker_nonce,
        pub_r=attacker_key.public_bytes(),
        tag_r=hmac_sha256(b"attacker's guess at the PSK", guessed_transcript),
    )
    try:
        initiator.finish(forged)
    except AuthenticationError as exc:
        return Result(
            name="Machine-in-the-middle without the PSK",
            defended=True,
            detail=(
                "the attacker completed the DH exchange with both sides but "
                f"could not produce a valid tag: {exc}"
            ),
            defense=(
                "authentication binds the exchange to the PSK; DH agreement "
                "alone proves nothing about identity"
            ),
        )
    return Result("Machine-in-the-middle without the PSK", False, "relayed", "none")


def mitm_unauthenticated_dh() -> Result:
    """The control case: the same attack on bare DH, which it wins.

    This is the most important function in the module. It is the evidence
    that the tags in AKEX are load-bearing and not decoration.
    """
    group = DEFAULT_GROUP
    alice = DHKeyPair.generate(group)
    bob = DHKeyPair.generate(group)
    mallory_to_alice = DHKeyPair.generate(group)
    mallory_to_bob = DHKeyPair.generate(group)

    # Neither side ever sees the other's real public key.
    alice_secret = alice.exchange(mallory_to_alice.public)
    bob_secret = bob.exchange(mallory_to_bob.public)
    mallory_with_alice = mallory_to_alice.exchange(alice.public)
    mallory_with_bob = mallory_to_bob.exchange(bob.public)

    owned = (
        alice_secret == mallory_with_alice
        and bob_secret == mallory_with_bob
        and alice_secret != bob_secret
    )
    return Result(
        name="Machine-in-the-middle against UNAUTHENTICATED DH (control)",
        defended=not owned,
        detail=(
            "the attacker holds both session secrets and can read and rewrite "
            "everything; neither party detects anything wrong"
            if owned
            else "attack unexpectedly failed"
        ),
        defense=(
            "none -- this is plain DH with the authentication removed, shown "
            "to make the case that the tags above are what stop the attack"
        ),
    )


def invalid_public_key() -> Result:
    """Degenerate and non-subgroup public keys must be rejected."""
    group = DEFAULT_GROUP
    victim = DHKeyPair.generate(group)
    # y = p-1 has order 2: the shared secret collapses to +/-1 whatever the
    # victim's private exponent is. y = 11 is a non-residue for this modulus,
    # so it sits outside the prime-order subgroup and leaks an exponent bit.
    hostile_values = {
        "y = 1 (order 1)": 1,
        "y = p-1 (order 2)": group.p - 1,
        "y = 11 (outside the prime-order subgroup)": 11,
    }
    rejected = []
    for label, value in hostile_values.items():
        try:
            victim.exchange(value)
        except InvalidPublicKey as exc:
            rejected.append(f"{label}: {exc}".split("(")[0].strip())
        else:
            return Result(
                "Small-subgroup / degenerate public key", False, f"accepted {label}", "none"
            )
    return Result(
        name="Small-subgroup / degenerate public key",
        defended=True,
        detail=f"all {len(hostile_values)} hostile values rejected",
        defense=(
            "range check plus the subgroup test y^q mod p == 1 before the "
            "shared secret is ever computed"
        ),
    )


def group_downgrade() -> Result:
    """A responder switching to a different group mid-handshake must be caught."""
    initiator = Initiator(psk=PSK, group=MODP_3072)
    init_msg = initiator.start()
    # Attacker rewrites the group id in message 2 to the weaker group.
    forged = ResponseMessage(
        group_id=DEFAULT_GROUP.group_id,
        nonce_r=secrets.token_bytes(32),
        pub_r=b"\x02" * DEFAULT_GROUP.size_bytes,
        tag_r=b"\x00" * 32,
    )
    try:
        initiator.finish(forged)
    except (ProtocolError, AuthenticationError) as exc:
        return Result(
            name="Downgrade to a weaker DH group",
            defended=True,
            detail=f"{type(exc).__name__}: {exc}",
            defense=(
                "the negotiated group id is pinned by policy and also hashed "
                "into the transcript both tags cover"
            ),
        )
    return Result("Downgrade to a weaker DH group", False, "accepted", "none")


ATTACKS = (
    baseline,
    wrong_psk,
    tamper_with_transcript,
    tamper_with_record,
    replay_record,
    mitm_against_akex,
    invalid_public_key,
    group_downgrade,
    mitm_unauthenticated_dh,
)


def run_all() -> list[Result]:
    """Run every simulation in order."""
    return [attack() for attack in ATTACKS]
