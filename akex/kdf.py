"""HKDF-SHA256, implemented directly from RFC 5869.

This is deliberately hand-rolled rather than imported: the whole point of the
exercise is to build the key schedule out of one primitive (HMAC-SHA256) and
be able to defend every line of it. `tests/test_kdf.py` checks this
implementation against the test vectors in RFC 5869 Appendix A.
"""

import hashlib
import hmac

HASH = hashlib.sha256
HASH_LEN = HASH().digest_size  # 32


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256. The single primitive the rest of the schedule is built on."""
    return hmac.new(key, data, HASH).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 Section 2.2: compress input keying material to a fixed-size PRK.

    Extract exists because raw DH output is not uniformly random -- it is a
    field element with structure. HMAC with the salt as key is what turns it
    into something we can treat as a uniform 256-bit key.
    """
    if not salt:
        salt = b"\x00" * HASH_LEN
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 Section 2.3: stretch a PRK into `length` bytes bound to `info`.

    `info` is the domain separator. Two keys derived from the same PRK with
    different `info` strings are computationally independent, which is what
    lets one handshake produce four distinct keys safely.
    """
    if length < 0:
        raise ValueError("length must be non-negative")
    max_length = 255 * HASH_LEN
    if length > max_length:
        raise ValueError(f"cannot expand to more than {max_length} bytes")
    if len(prk) < HASH_LEN:
        raise ValueError("prk is shorter than the hash length")

    okm = bytearray()
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac_sha256(prk, block + info + bytes([counter]))
        okm += block
        counter += 1
    return bytes(okm[:length])


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Full extract-then-expand, for callers that do not reuse the PRK."""
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def constant_time_eq(a: bytes, b: bytes) -> bool:
    """Compare two byte strings without leaking where they first differ.

    A naive `a == b` returns as soon as it hits a mismatching byte. An
    attacker who can time many verification attempts can use that to recover
    a tag byte by byte, turning a 2^256 forgery into roughly 32 * 256 tries.
    """
    return hmac.compare_digest(a, b)
