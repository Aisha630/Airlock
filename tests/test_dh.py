"""Diffie-Hellman arithmetic and, mostly, public-key validation."""

import pytest

from akex.dh import EXPONENT_BITS, DHKeyPair, InvalidPublicKey, validate_public_key
from akex.params import GROUPS, MODP_2048, MODP_3072, get_group


@pytest.mark.parametrize("group", [MODP_2048, MODP_3072], ids=lambda g: f"modp{g.bits}")
def test_group_parameters_are_well_formed(group):
    """p must be the advertised size, and g must generate the order-q subgroup."""
    assert group.p.bit_length() == group.bits
    assert group.size_bytes == group.bits // 8
    # p is a safe prime, so q = (p-1)/2 and g^q == 1 iff g is in that subgroup.
    assert group.q * 2 + 1 == group.p
    assert pow(group.g, group.q, group.p) == 1


def test_key_agreement():
    alice = DHKeyPair.generate(MODP_2048)
    bob = DHKeyPair.generate(MODP_2048)
    assert alice.exchange(bob.public) == bob.exchange(alice.public)


def test_key_pairs_are_distinct():
    """A repeated key pair would mean the CSPRNG is not being used properly."""
    keys = {DHKeyPair.generate(MODP_2048).private for _ in range(8)}
    assert len(keys) == 8


def test_private_exponent_is_in_range():
    for _ in range(8):
        keypair = DHKeyPair.generate(MODP_2048)
        assert 2 <= keypair.private < (1 << EXPONENT_BITS)


def test_public_bytes_are_fixed_width():
    """Encoding must be padded, or the transcript would depend on value size."""
    for _ in range(8):
        keypair = DHKeyPair.generate(MODP_2048)
        assert len(keypair.public_bytes()) == MODP_2048.size_bytes


def test_shared_secret_is_fixed_width():
    alice = DHKeyPair.generate(MODP_2048)
    bob = DHKeyPair.generate(MODP_2048)
    assert len(alice.exchange(bob.public)) == MODP_2048.size_bytes


@pytest.mark.parametrize(
    "value,reason",
    [
        (0, "zero"),
        (1, "order 1: shared secret is always 1"),
        (MODP_2048.p - 1, "order 2: shared secret is always +/-1"),
        (MODP_2048.p, "equals the modulus"),
        (MODP_2048.p + 1, "above the modulus"),
        (-1, "negative"),
    ],
)
def test_degenerate_public_keys_are_rejected(value, reason):
    with pytest.raises(InvalidPublicKey):
        validate_public_key(value, MODP_2048)


def test_non_subgroup_public_key_is_rejected():
    """A quadratic non-residue is outside the order-q subgroup and leaks a bit."""
    non_residue = next(
        y for y in range(2, 100) if pow(y, MODP_2048.q, MODP_2048.p) != 1
    )
    assert pow(non_residue, MODP_2048.q, MODP_2048.p) != 1
    with pytest.raises(InvalidPublicKey, match="prime-order subgroup"):
        validate_public_key(non_residue, MODP_2048)


def test_valid_subgroup_element_is_accepted():
    """Guard against validation that rejects everything and looks 'secure'."""
    keypair = DHKeyPair.generate(MODP_2048)
    validate_public_key(keypair.public, MODP_2048)
    # A quadratic residue is in the subgroup by construction.
    validate_public_key(pow(7, 2, MODP_2048.p), MODP_2048)


def test_exchange_validates_before_computing():
    keypair = DHKeyPair.generate(MODP_2048)
    with pytest.raises(InvalidPublicKey):
        keypair.exchange(1)


def test_unknown_group_id_is_refused():
    """Refusing unknown groups is what blocks a downgrade to a weak group."""
    with pytest.raises(ValueError):
        get_group(1)  # the 768-bit MODP group, long since broken
    for group_id, group in GROUPS.items():
        assert get_group(group_id) is group
