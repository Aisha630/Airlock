"""HKDF-SHA256 against the official test vectors in RFC 5869 Appendix A.

These are the tests that matter most in the whole suite. Everything in the
key schedule rests on HKDF being correct, and "it produces 32 bytes that
look random" is not evidence of that. Matching the published vectors byte
for byte is.
"""

import pytest

from akex.kdf import (
    HASH_LEN,
    constant_time_eq,
    hkdf,
    hkdf_expand,
    hkdf_extract,
)


def _hex(text: str) -> bytes:
    return bytes.fromhex(text)


# RFC 5869 Appendix A. Only the SHA-256 cases apply here; cases 4-7 use SHA-1.
VECTORS = [
    pytest.param(
        _hex("0b" * 22),
        _hex("000102030405060708090a0b0c"),
        _hex("f0f1f2f3f4f5f6f7f8f9"),
        42,
        _hex("077709362c2e32df0ddc3f0dc47bba63"
             "90b6c73bb50f9c3122ec844ad7c2b3e5"),
        _hex("3cb25f25faacd57a90434f64d0362f2a"
             "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
             "34007208d5b887185865"),
        id="rfc5869-case-1-basic",
    ),
    pytest.param(
        _hex("".join(f"{i:02x}" for i in range(0x50))),
        _hex("".join(f"{i:02x}" for i in range(0x60, 0xB0))),
        _hex("".join(f"{i:02x}" for i in range(0xB0, 0x100))),
        82,
        _hex("06a6b88c5853361a06104c9ceb35b45c"
             "ef760014904671014a193f40c15fc244"),
        _hex("b11e398dc80327a1c8e7f78c596a4934"
             "4f012eda2d4efad8a050cc4c19afa97c"
             "59045a99cac7827271cb41c65e590e09"
             "da3275600c2f09b8367793a9aca3db71"
             "cc30c58179ec3e87c14c01d5c1f3434f"
             "1d87"),
        id="rfc5869-case-2-long-inputs",
    ),
    pytest.param(
        _hex("0b" * 22),
        b"",
        b"",
        42,
        _hex("19ef24a32c717b167f33a91d6f648bdf"
             "96596776afdb6377ac434c1c293ccb04"),
        _hex("8da4e775a563c18f715f802a063c5a31"
             "b8a11f5c5ee1879ec3454e5f3c738d2d"
             "9d201395faa4b61a96c8"),
        id="rfc5869-case-3-empty-salt-and-info",
    ),
]


@pytest.mark.parametrize("ikm,salt,info,length,expected_prk,expected_okm", VECTORS)
def test_hkdf_matches_rfc5869(ikm, salt, info, length, expected_prk, expected_okm):
    prk = hkdf_extract(salt, ikm)
    assert prk == expected_prk, "extract does not match the RFC"
    okm = hkdf_expand(prk, info, length)
    assert okm == expected_okm, "expand does not match the RFC"
    assert hkdf(ikm, salt, info, length) == expected_okm


def test_empty_salt_equals_zero_salt():
    """RFC 5869 Section 2.2: an absent salt means HashLen zero bytes."""
    ikm = b"input keying material"
    assert hkdf_extract(b"", ikm) == hkdf_extract(b"\x00" * HASH_LEN, ikm)


def test_different_info_gives_independent_output():
    """The property the key schedule depends on: info separates keys."""
    prk = hkdf_extract(b"salt", b"ikm")
    assert hkdf_expand(prk, b"purpose A", 32) != hkdf_expand(prk, b"purpose B", 32)


def test_expand_is_deterministic():
    prk = hkdf_extract(b"salt", b"ikm")
    assert hkdf_expand(prk, b"info", 64) == hkdf_expand(prk, b"info", 64)


def test_expand_output_is_a_prefix_of_a_longer_expansion():
    """HKDF is a stream: the first N bytes do not depend on the total length."""
    prk = hkdf_extract(b"salt", b"ikm")
    assert hkdf_expand(prk, b"info", 100)[:32] == hkdf_expand(prk, b"info", 32)


def test_expand_rejects_more_than_255_blocks():
    """RFC 5869 caps output at 255 * HashLen; the counter is one byte."""
    prk = hkdf_extract(b"salt", b"ikm")
    assert len(hkdf_expand(prk, b"info", 255 * HASH_LEN)) == 255 * HASH_LEN
    with pytest.raises(ValueError):
        hkdf_expand(prk, b"info", 255 * HASH_LEN + 1)


def test_expand_rejects_short_prk():
    with pytest.raises(ValueError):
        hkdf_expand(b"too short", b"info", 32)


def test_constant_time_eq():
    assert constant_time_eq(b"abc", b"abc")
    assert not constant_time_eq(b"abc", b"abd")
    assert not constant_time_eq(b"abc", b"abcd")
