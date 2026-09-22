# Airlock

Airlock implements an authenticated Diffie-Hellman key exchange and an
802.11 capture analyzer. The two components address the same question from
opposite directions: what a key exchange must do to resist an active
attacker, and how much of a wireless network remains observable to a passive
one after encryption is applied.

The key exchange (`akex/`) performs ephemeral Diffie-Hellman over RFC 3526
MODP groups, derives keys with HKDF-SHA256, and authenticates the handshake
transcript with HMAC-SHA256 under a pre-shared key. The analyzer (`wifi/`)
reads pcap files produced in monitor mode, classifies frames, parses
advertised security capabilities, reconstructs WPA2 four-way handshakes, and
reports findings.

Requires Python 3.10 or later and Scapy. The test suite comprises 177 tests.

## Installation and use

```sh
make setup                                   # create .venv, install dependencies
make test                                    # run the test suite
make demo                                    # exercise both components

python -m akex handshake [--psk TEXT] [--group {14,15}]
python -m akex attacks
python -m wifi synth [OUTPUT]
python -m wifi analyze PCAP [--json PATH] [--fail-on-high]
```

The `--fail-on-high` flag returns a non-zero exit status when a
high-severity finding is present, permitting use as an automated check.
Sample analyzer output is committed at `docs/sample-report.txt`.

## Authenticated key exchange

The protocol consists of three messages. The initiator sends a group
identifier, a nonce and its public value; the responder replies with its own
nonce, public value and an authentication tag; the initiator returns a
second tag.

```
  I -> R    group_id, nonce_i, g^i
  R -> I    nonce_r, g^r, tag_r
  I -> R    tag_i
```

Diffie-Hellman alone establishes a shared secret with an unauthenticated
peer and is therefore defeated by an interposed attacker who conducts a
separate exchange with each party. Airlock binds the exchange to a
pre-shared key held by both parties. Each tag is an HMAC-SHA256 over a hash
of the preceding transcript, computed under a key derived from both the
Diffie-Hellman shared secret and the pre-shared key, so a valid tag
demonstrates possession of the pre-shared key and participation in this
particular exchange.

The key schedule follows the extract-then-expand construction of RFC 5869:

```
salt = SHA256("AKEX v1 salt" || nonce_i || nonce_r || psk)
prk  = HKDF-Extract(salt, g^ir)
th   = SHA256(length-prefixed msg1 || length-prefixed msg2 core)

auth_i      = HKDF-Expand(prk, "AKEX v1 initiator auth"  || th, 32)
auth_r      = HKDF-Expand(prk, "AKEX v1 responder auth"  || th, 32)
session_i2r = HKDF-Expand(prk, "AKEX v1 session key i2r" || th, 32)
session_r2i = HKDF-Expand(prk, "AKEX v1 session key r2i" || th, 32)
```

Binding the pre-shared key into the extraction salt makes both inputs
necessary to derive the pseudorandom key. Appending the transcript hash to
each expansion label binds every derived key to the exact handshake
observed, so any modification in transit, including substitution of the
group identifier, produces divergent keys and a failed tag verification.
Distinct labels yield computationally independent keys, and the directional
session keys prevent a record from being reflected toward its sender. The
HKDF implementation in `akex/kdf.py` is written directly from RFC 5869 and
verified against the test vectors in Appendix A of that document.

Public values received from a peer are validated in `akex/dh.py` before any
shared secret is computed. The range check `2 <= y <= p-2` excludes the
degenerate values 0, 1 and p-1, each of which forces a shared secret already
known to the attacker irrespective of the recipient's private exponent. The
subgroup test `y^q mod p == 1` excludes elements outside the prime-order
subgroup, which would otherwise disclose one bit of the private exponent per
handshake through the Legendre symbol of the resulting secret. Both
supported groups, MODP-2048 and MODP-3072, have safe-prime moduli, so a
single modular exponentiation constitutes a complete subgroup test.
Unrecognised group identifiers are rejected rather than accepted, since
accepting them is the usual entry point for downgrade attacks against
protocols with negotiated parameters.

An authenticated record layer over the derived session keys is provided in
`akex/channel.py`. Each record carries an HMAC-SHA256 tag computed over a
header containing the transmission direction, a sequence number and the
payload length, followed by the payload itself. Including the direction
prevents reflection, the sequence number prevents replay, and the length
prevents a truncated record from being accepted as a shorter valid one.
Receivers verify the tag before evaluating the sequence number, so an
attacker cannot advance the replay window with unauthenticated data. The
layer provides integrity and authenticity but not confidentiality; see
Limitations.

The command `python -m akex attacks` executes seven attacks, all of which
fail, together with two controls. The attacks comprise an incorrect
pre-shared key, single-bit modification of the transcript, modification of
an application record, replay of a valid record, interposition without the
pre-shared key, a small-subgroup public value and a downgrade to a weaker
group. The first control confirms that an honest handshake completes with
both parties agreeing on identical keys. The second repeats the
interposition attack against the same exchange with authentication removed,
where it succeeds completely, establishing that the authentication mechanism
rather than an incidental property accounts for the difference in outcome.

## Capture analysis

The analyzer accepts any pcap containing 802.11 frames and operates
exclusively on header metadata; no payload decryption or key recovery is
attempted. Frames are classified by the type and subtype fields of the Frame
Control field, which are transmitted unencrypted on all networks because a
receiver must interpret them before any key is determined.

Security capabilities are read from the RSN information element defined in
IEEE 802.11-2020 §9.4.2.24, and from the legacy vendor-specific WPA element,
yielding the group cipher, pairwise ciphers, AKM suites, RSN capabilities
and group management cipher. The implementation in `wifi/rsn.py` parses the
element directly from its byte layout in order to expose bits 6 and 7 of the
RSN capabilities field, which specify whether management frame protection is
required and whether it is supported. These two bits determine whether
forged deauthentication frames are effective against a given network, and
are therefore treated as a primary output rather than an incidental one.
Recognised configurations include WPA1, WPA2-Personal, WPA2 and WPA3
Enterprise, WPA3-Personal using SAE, OWE, and WPA3/WPA2 transition mode. The
last is reported separately because offering SAE and PSK concurrently
permits a client supporting both to be directed onto the PSK path.

EAPOL-Key frames are parsed in `wifi/eapol.py` and grouped into per-pair
handshakes. The four messages of the exchange carry no explicit ordinal, so
each is identified from the Key Ack, Key MIC and Secure bits of the Key
Information field. Messages two and four are distinguished only by the
Secure bit and the presence of key data; where a capture begins mid-exchange
the classification is genuinely ambiguous, and the parser returns no result
rather than inferring one. PMKIDs disclosed in the first message are
extracted, and successive handshakes between the same pair are retained
separately rather than overwritten.

Five detectors operate over the parsed metadata. Deauthentication floods are
located by a two-pointer sliding window over frames grouped by source and
target, giving the true peak rate rather than a sample at fixed intervals,
and the resulting bursts are correlated against the advertised management
frame protection state, since an identical burst carries different
significance on a network that requires protection. An SSID advertised by
multiple BSSIDs with differing security configurations is reported as a
possible rogue access point, an impersonating device being able to replicate
an SSID but not the credential. The remaining detectors report weak
configurations, comprising WEP, TKIP, open networks, absent management frame
protection and transition-mode exposure, and material supporting an offline
dictionary attack, comprising complete handshakes and disclosed PMKIDs. Each
finding carries a severity, supporting evidence and a documented benign
explanation where one exists.

## Validation

The test suite covers the HKDF implementation against the RFC 5869 Appendix
A vectors, group structure and rejection of invalid public values, handshake
agreement and authentication failure modes, record layer integrity under
modification, replay, reordering and reflection, RSN parsing across security
generations including malformed elements, EAPOL message identification and
handshake tracking, and end-to-end analysis of a generated capture whose
contents are known.

The analyzer was additionally validated against 104 seconds of live
monitor-mode capture comprising 31,708 frames and 41 BSSIDs, which exposed
two defects not reachable with generated data. An information element whose
length field overran the containing frame raised an exception terminating
the run, so parsing is now bounded per frame, with failures recorded and
analysis continuing. Corrupted beacons were additionally reported as
distinct networks, producing nineteen spurious findings; frames whose
transmitter address has the Individual/Group bit set are structurally
invalid under IEEE 802.11, and the 163 such frames in the capture are now
excluded from network discovery, with a minimum-evidence threshold applied
to the remainder and all exclusions reported rather than discarded. Findings
fell from 49, of which 24 were high severity, to 14, of which 2 were.

The generated capture proved unrepresentative of live traffic in
composition, management frames accounting for 47.5 per cent of it against
9.5 per cent of the live capture. It is retained because it makes the test
suite deterministic, not because it models the medium.

Live captures are excluded from version control, since a monitor-mode
capture records the MAC address and SSID of every device within radio range.
The generated capture is the only tracked capture.

## Relation to deployed protocols

|                               | Airlock          | WPA2 four-way         | WPA3-SAE       |
|-------------------------------|------------------|-----------------------|----------------|
| Credential                    | Pre-shared key   | PMK from PBKDF2       | Password       |
| Key exchange                  | Ephemeral DH     | None                  | Dragonfly PAKE |
| Key derivation                | HKDF-SHA256      | PRF-384/512           | HKDF           |
| Authentication                | HMAC, transcript | Key MIC under the KCK | Confirm phase  |
| Forward secrecy               | Yes              | No                    | Yes            |
| Offline dictionary resistance | No               | No                    | Yes            |

WPA2 derives the pairwise transient key from the pairwise master key and two
nonces without any key exchange. A recorded handshake combined with
subsequent recovery of the passphrase therefore permits retrospective
decryption of that session. Airlock performs a fresh Diffie-Hellman exchange
per session, as WPA3-SAE does, and does not exhibit this property. Airlock
remains vulnerable to an offline dictionary attack against a low-entropy
pre-shared key; addressing that requires a password-authenticated key
exchange such as SAE or OPAQUE.

## Limitations

The record layer provides integrity and authenticity but not
confidentiality; introducing an AEAD would be confined to two functions in
`akex/channel.py`. No cryptographic primitive is reimplemented, HMAC-SHA256
being taken from the standard library, as the subject of the work is the
protocol constructed around it. The analyzer performs no passphrase
recovery, key recovery or payload decryption. Python's arbitrary-precision
exponentiation is not constant time, and although tag comparison uses
`hmac.compare_digest`, a production implementation would require a
constant-time bignum library. The detectors are heuristics with documented
false-positive modes. All capture work was conducted against hardware owned
by the author on an isolated network, and the deauthentication frames
present in the generated capture were never transmitted.

## Repository layout

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

`THREAT_MODEL.md` contains a STRIDE analysis of both components with
mitigations mapped to individual tests, together with accepted risks.
`docs/CAPTURE.md` documents the monitor-mode capture procedure for macOS and
Linux and the containment measures observed.

## References

IEEE 802.11-2020, §9.4.2.24 (RSN element) and §12.7 (key hierarchy).
RFC 5869, HMAC-based Extract-and-Expand Key Derivation Function.
RFC 3526, More Modular Exponential Diffie-Hellman Groups for IKE.
RFC 2104, HMAC: Keyed-Hashing for Message Authentication.
