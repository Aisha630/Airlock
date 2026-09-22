# Airlock

I built Airlock to work through two sides of the same question: what a key
exchange has to do to resist an active attacker, and how much of a wireless
network stays visible to a passive one even after encryption is applied.

It has two halves. In `akex/` I implemented an authenticated Diffie-Hellman
key exchange: ephemeral DH over RFC 3526 MODP groups, keys derived with
HKDF-SHA256, and the handshake transcript authenticated with HMAC-SHA256
under a pre-shared key. In `wifi/` I wrote an 802.11 capture analyzer that
reads pcap files recorded in monitor mode, classifies frames, parses the
security capabilities an access point advertises, reconstructs WPA2 four-way
handshakes, and reports findings.

It needs Python 3.10 or later and Scapy. There are 177 tests.

## Running it

```sh
make setup                                   # create .venv, install dependencies
make test                                    # run the test suite
make demo                                    # exercise both halves

python -m akex handshake [--psk TEXT] [--group {14,15}]
python -m akex attacks
python -m wifi synth [OUTPUT]
python -m wifi analyze PCAP [--json PATH] [--fail-on-high]
```

`--fail-on-high` exits non-zero when a high-severity finding is present, so
the analyzer can run as an automated check rather than something a person
reads. Sample output is committed at `docs/sample-report.txt`.

## The key exchange

The handshake is three messages. The initiator sends a group identifier, a
nonce and its public value. The responder replies with its own nonce, public
value and an authentication tag. The initiator returns a second tag.

```
  I -> R    group_id, nonce_i, g^i
  R -> I    nonce_r, g^r, tag_r
  I -> R    tag_i
```

Diffie-Hellman on its own agrees a secret with whoever you actually talked
to, and says nothing about who that was, so an attacker can run a separate
exchange with each party and relay between them indefinitely. I bind the
exchange to a pre-shared key that both sides already hold. Each tag is an
HMAC-SHA256 over a hash of the transcript so far, computed under a key
derived from both the DH shared secret and the pre-shared key. Producing a
valid tag therefore proves two things at once: that you hold the pre-shared
key, and that you saw this exact exchange.

I derive the keys with the extract-then-expand construction from RFC 5869:

```
salt = SHA256("AKEX v1 salt" || nonce_i || nonce_r || psk)
prk  = HKDF-Extract(salt, g^ir)
th   = SHA256(length-prefixed msg1 || length-prefixed msg2 core)

auth_i      = HKDF-Expand(prk, "AKEX v1 initiator auth"  || th, 32)
auth_r      = HKDF-Expand(prk, "AKEX v1 responder auth"  || th, 32)
session_i2r = HKDF-Expand(prk, "AKEX v1 session key i2r" || th, 32)
session_r2i = HKDF-Expand(prk, "AKEX v1 session key r2i" || th, 32)
```

Putting the pre-shared key in the extraction salt means both inputs are
needed to reach the pseudorandom key, so a peer with the wrong pre-shared
key diverges from the first step. Appending the transcript hash to every
expansion label ties each derived key to the exact handshake observed, which
is what catches a modification in transit, including a substituted group
identifier. The four distinct labels give four computationally independent
keys, and making the session keys directional stops a record being reflected
back at whoever sent it. I wrote the HKDF in `akex/kdf.py` directly from RFC
5869 and check it against the Appendix A vectors, because an implementation
that merely produces random-looking bytes is not evidence of anything.

Most of what can go wrong with finite-field DH is not the arithmetic but the
validation, so `akex/dh.py` checks a peer's public value before computing
any shared secret. The range check `2 <= y <= p-2` rules out 0, 1 and p-1,
each of which pins the shared secret to a value the attacker already knows
whatever my private exponent is. The subgroup test `y^q mod p == 1` rules
out elements outside the prime-order subgroup, which would leak a bit of my
private exponent per handshake through the Legendre symbol of the result.
Both groups I support, MODP-2048 and MODP-3072, have safe-prime moduli, so
that single exponentiation is a complete subgroup test. I reject group
identifiers I do not recognise, since accepting them is the usual way into a
downgrade attack.

On top of the session keys, `akex/channel.py` provides an authenticated
record layer. Every record carries an HMAC-SHA256 tag over a header holding
the direction, a sequence number and the payload length, then the payload.
The direction stops reflection, the sequence number stops replay, and the
length stops a truncated record passing as a shorter valid one. I verify the
tag before looking at the sequence number, so an attacker cannot push the
replay window forward with unauthenticated data. This layer authenticates
but does not encrypt, which is a deliberate choice I describe under
Limitations.

`python -m akex attacks` runs seven attacks, all of which fail, plus two
controls. The attacks are a wrong pre-shared key, a single-bit change to the
transcript, a modified application record, a replayed record, an interposed
attacker without the pre-shared key, a small-subgroup public value, and a
downgrade to a weaker group. The first control checks that an honest
handshake completes with both sides agreeing. The second matters more: it
repeats the interposition attack against the same exchange with the
authentication taken out, where it succeeds completely. Without that,
reporting seven blocked attacks would say nothing about whether the
authentication was doing the work.

## The capture analyzer

The analyzer takes any pcap containing 802.11 frames and reads header
metadata only. I do not attempt to decrypt payloads or recover keys. Frames
are classified from the type and subtype fields of the Frame Control field,
which are sent unencrypted on every network, since a receiver has to
interpret them before it knows which key applies.

I read security capabilities from the RSN information element defined in
IEEE 802.11-2020 §9.4.2.24, and from the older vendor-specific WPA element,
which gives me the group cipher, pairwise ciphers, AKM suites, RSN
capabilities and group management cipher. I parse the element from its byte
layout in `wifi/rsn.py` rather than using a library helper, mainly to get at
bits 6 and 7 of the RSN capabilities field, which say whether management
frame protection is required and whether it is supported. Those two bits
decide whether forged deauthentication frames work against a network, so I
treat them as a primary output. The parser recognises WPA1, WPA2-Personal,
WPA2 and WPA3 Enterprise, WPA3-Personal using SAE, OWE, and WPA3/WPA2
transition mode. I report transition mode separately, because offering SAE
and PSK together lets a client that supports both be pushed onto the PSK
path.

`wifi/eapol.py` parses EAPOL-Key frames and groups them into per-pair
handshakes. The four messages carry no ordinal on the wire, so I identify
each from the Key Ack, Key MIC and Secure bits of the Key Information field.
Messages two and four differ only in the Secure bit and the presence of key
data, so a capture that starts mid-exchange is genuinely ambiguous, and the
parser returns nothing rather than guessing. I extract PMKIDs disclosed in
the first message, and keep successive handshakes between the same pair
separately instead of overwriting.

Five detectors run over the parsed metadata. I find deauthentication floods
with a two-pointer sliding window over frames grouped by source and target,
which gives the true peak rate instead of a sample at fixed intervals, and I
correlate the bursts against the advertised management frame protection
state, since the same burst means something different on a network that
requires protection. An SSID advertised by several BSSIDs with disagreeing
security configurations is reported as a possible rogue access point, on the
reasoning that an impersonator can copy an SSID but not the credential. The
remaining two report weak configurations, meaning WEP, TKIP, open networks,
absent management frame protection and transition-mode exposure, and
material supporting an offline dictionary attack, meaning complete
handshakes and disclosed PMKIDs. Every finding carries a severity, the
evidence behind it, and a benign explanation where one exists, because a
detector that only says "suspicious" cannot be acted on.

## Testing

The suite covers the HKDF implementation against the RFC 5869 Appendix A
vectors, group structure and rejection of invalid public values, handshake
agreement and each authentication failure mode, the record layer under
modification, replay, reordering and reflection, RSN parsing across security
generations including malformed elements, EAPOL message identification and
handshake tracking, and an end-to-end analysis of a generated capture whose
contents I know exactly.

I also ran the analyzer against 104 seconds of live monitor-mode capture,
31,708 frames across 41 BSSIDs, which turned up two defects I could not have
reached with generated data. An information element whose length field
overran its frame raised an exception that killed the whole run, so parsing
is now bounded per frame, with failures recorded and analysis continuing.
Corrupted beacons were also being reported as real networks, producing
nineteen spurious findings. Frames whose transmitter address has the
Individual/Group bit set are structurally invalid under IEEE 802.11, and
there were 163 of them in the capture, so I exclude those from network
discovery and apply a minimum-evidence threshold to the rest. I report what
was excluded rather than dropping it silently. Findings on that capture fell
from 49, of which 24 were high severity, to 14, of which 2 were.

The same run showed my generated capture is not representative of live
traffic: management frames are 47.5 per cent of it against 9.5 per cent of
the live capture. I keep it because it makes the tests deterministic, not
because it models the medium.

I do not commit live captures, since a monitor-mode capture records the MAC
address and SSID of every device in radio range. The generated capture is
the only one tracked.

## How it compares to WPA2 and WPA3

|                               | Airlock          | WPA2 four-way         | WPA3-SAE       |
|-------------------------------|------------------|-----------------------|----------------|
| Credential                    | Pre-shared key   | PMK from PBKDF2       | Password       |
| Key exchange                  | Ephemeral DH     | None                  | Dragonfly PAKE |
| Key derivation                | HKDF-SHA256      | PRF-384/512           | HKDF           |
| Authentication                | HMAC, transcript | Key MIC under the KCK | Confirm phase  |
| Forward secrecy               | Yes              | No                    | Yes            |
| Offline dictionary resistance | No               | No                    | Yes            |

WPA2 derives the pairwise transient key from the pairwise master key and two
nonces with no key exchange at all, so anyone who recorded a handshake and
later recovers the passphrase can decrypt that session retrospectively. That
is why the analyzer reports a captured handshake as exposure rather than as
a healthy event. Airlock runs a fresh DH exchange per session, as WPA3-SAE
does, so it does not have that property. It does not fix the other half:
an attacker who records an Airlock handshake can still test guesses against
a low-entropy pre-shared key offline, and fixing that needs a
password-authenticated key exchange such as SAE or OPAQUE.

## Limitations

The record layer gives integrity and authenticity but not confidentiality.
Adding an AEAD would be confined to two functions in `akex/channel.py`. I
did not reimplement any cryptographic primitive; HMAC-SHA256 comes from the
standard library, and what I built is the protocol around it. The analyzer
does no passphrase recovery, key recovery or payload decryption. Python's
arbitrary-precision exponentiation is not constant time, and although tag
comparison uses `hmac.compare_digest`, a production implementation would
need a constant-time bignum library. The detectors are heuristics with
documented false-positive modes. All capture work was done against hardware
I own on an isolated network, and the deauthentication frames in the
generated capture were never transmitted.

## Layout

```
akex/   params.py     RFC 3526 MODP group definitions
        dh.py         Diffie-Hellman with public value validation
        kdf.py        HKDF-SHA256 (RFC 5869)
        wire.py       Canonical message encoding and transcript hashing
        protocol.py   Handshake state machines and key schedule
        channel.py    Authenticated record layer
        attacks.py    Adversary simulations
wifi/   frames.py     Frame classification, reason and status codes
        rsn.py        RSN and legacy WPA element parser
        eapol.py      EAPOL-Key parsing and handshake tracking
        capture.py    pcap ingestion
        anomalies.py  Detectors
        synth.py      Generated capture
```

`THREAT_MODEL.md` has a STRIDE analysis of both halves with mitigations
mapped to individual tests, and the risks I accepted. `docs/CAPTURE.md`
covers the monitor-mode capture procedure on macOS and Linux and the
containment I followed.

## References

- IEEE 802.11-2020, §9.4.2.24 (RSN element) and §12.7 (key hierarchy)
- RFC 5869, HMAC-based Extract-and-Expand Key Derivation Function
- RFC 3526, More Modular Exponential Diffie-Hellman Groups for IKE
- RFC 2104, HMAC: Keyed-Hashing for Message Authentication
