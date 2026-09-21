# Airlock

An authenticated Diffie-Hellman key exchange and an 802.11 capture
analyzer, implemented in Python.

- **`akex/`**: an authenticated key exchange over RFC 3526 MODP groups,
  with an HKDF-SHA256 key schedule, HMAC-SHA256 transcript authentication,
  and an authenticated record layer.
- **`wifi/`**: a capture analyzer that classifies 802.11 frames, parses RSN
  security capabilities, reconstructs WPA2 four-way handshakes, and reports
  security findings.

Requires Python 3.10+ and Scapy. 177 tests.

## Installation

```sh
make setup        # creates .venv and installs dependencies
make test         # runs the test suite
make demo         # runs both components against sample data
```

## Usage

```sh
python -m akex handshake [--psk TEXT] [--group {14,15}]
python -m akex attacks

python -m wifi synth [OUTPUT]
python -m wifi analyze PCAP [--json PATH] [--fail-on-high]
```

`--fail-on-high` returns a non-zero exit status when any high-severity
finding is reported, for use in an automated check.

---

## Part 1: AKEX key exchange

### Protocol

```
  Initiator                                        Responder
      |  1.  group_id, nonce_i, g^i                    |
      | ---------------------------------------------> |
      |  2.  nonce_r, g^r, tag_r                       |
      | <--------------------------------------------- |
      |  3.  tag_i                                     |
      | ---------------------------------------------> |
```

Both parties hold a pre-shared key. Each tag is an HMAC-SHA256 over a hash
of the handshake transcript, keyed from material derived from both the
Diffie-Hellman shared secret and the PSK. Producing a valid tag therefore
requires possession of the PSK and participation in the exchange.

Properties provided:

| Property | Mechanism |
|---|---|
| Mutual authentication | HMAC tags over the transcript, keyed via the PSK |
| Forward secrecy | Ephemeral DH key pairs, discarded after each handshake |
| Transcript integrity | All fields of messages 1 and 2 hashed into both tags |
| Downgrade resistance | Group identifier pinned by policy and covered by the transcript |
| Key separation | Four independent keys via distinct HKDF `info` labels |

### Key schedule

```
salt = SHA256("AKEX v1 salt" || nonce_i || nonce_r || psk)
prk  = HKDF-Extract(salt, g^ir)
th   = SHA256(len-prefixed msg1 || len-prefixed msg2 core)

auth_i      = HKDF-Expand(prk, "AKEX v1 initiator auth"  || th, 32)
auth_r      = HKDF-Expand(prk, "AKEX v1 responder auth"  || th, 32)
session_i2r = HKDF-Expand(prk, "AKEX v1 session key i2r" || th, 32)
session_r2i = HKDF-Expand(prk, "AKEX v1 session key r2i" || th, 32)
```

The PSK is bound into the extract salt, so both the DH secret and the PSK
are required to derive the PRK. The transcript hash is appended to every
expansion label, binding all derived keys to the exact handshake observed.
Session keys are directional, preventing a record from being replayed back
toward its sender.

HKDF-SHA256 is implemented in `akex/kdf.py` from RFC 5869 and verified
against the test vectors in that document's Appendix A.

### Public-key validation

Peer public values are validated in `akex/dh.py` before any shared secret is
computed:

| Check | Rejects |
|---|---|
| `2 ≤ y ≤ p-2` | Degenerate values (`0`, `1`, `p-1`) that force a shared secret known to the attacker |
| `y^q mod p == 1` | Elements outside the prime-order subgroup, which leak one private-key bit per handshake |

Groups are RFC 3526 MODP-2048 (id 14) and MODP-3072 (id 15). Both moduli are
safe primes, so a single exponentiation constitutes a complete subgroup
test. Unrecognised group identifiers are rejected.

### Record layer

`akex/channel.py` provides an authenticated record layer over the derived
session keys. Each record is tagged with HMAC-SHA256 over a header
containing the direction, sequence number and payload length, followed by
the payload. Receivers verify the tag before evaluating the sequence number,
and require sequence numbers to strictly increase.

This layer provides integrity and authenticity only; it does not provide
confidentiality. See [Limitations](#limitations).

### Adversary harness

`python -m akex attacks` executes seven attacks and two controls:

| Scenario | Result |
|---|---|
| Peer with an incorrect PSK | Blocked |
| Single-bit transcript modification | Blocked |
| Application record modification | Blocked |
| Replay of a valid record | Blocked |
| Machine-in-the-middle without the PSK | Blocked |
| Small-subgroup or degenerate public key | Blocked |
| Downgrade to a weaker DH group | Blocked |
| Honest handshake (control) | Completes, keys agree |
| Machine-in-the-middle against unauthenticated DH (control) | Succeeds, as expected |

The second control runs the same machine-in-the-middle attack against a key
exchange with authentication removed, establishing that the authentication
mechanism accounts for the difference in outcome.

---

## Part 2: 802.11 analyzer

`python -m wifi analyze PCAP` accepts any pcap containing 802.11 frames and
produces a report in six sections. Sample output is committed at
[`docs/sample-report.txt`](docs/sample-report.txt).

### Frame classification

Frames are classified by the type and subtype fields of the Frame Control
field, which are transmitted unencrypted on all networks. The report gives
counts and proportions per class, subtype breakdowns, protected-frame
counts, and retransmission counts.

### Security capability analysis

The RSN information element (IEEE 802.11-2020 §9.4.2.24) and the legacy
vendor-specific WPA element are parsed in `wifi/rsn.py`, yielding the group
cipher, pairwise ciphers, AKM suites, RSN capabilities and group management
cipher. Recognised configurations include WPA1, WPA2-Personal,
WPA2/WPA3-Enterprise, WPA3-Personal (SAE), OWE, and WPA3/WPA2 transition
mode. Management frame protection state is derived from bits 6 (MFPR) and 7
(MFPC) of the RSN capabilities field.

### Four-way handshake reconstruction

`wifi/eapol.py` parses EAPOL-Key frames and groups them into per-(AP,
station) handshakes. Message numbers are derived from the Key Ack, Key MIC
and Secure bits of the Key Information field. Messages 2 and 4 are
distinguished by the Secure bit; where a capture is ambiguous, the parser
returns no result rather than inferring one. PMKIDs present in message 1 are
extracted. Successive handshakes between the same pair are retained
separately.

### Detectors

| Detector | Method |
|---|---|
| Deauthentication flood | Sliding window over frames grouped by source and target, reporting peak rate |
| Forgeable management frames | Observed deauthentications correlated against advertised MFP state |
| Evil twin | One SSID advertised by multiple BSSIDs with differing security configurations |
| Weak configuration | WEP, TKIP, open networks, absent MFP, and transition-mode downgrade exposure |
| Handshake exposure | Complete four-way handshakes and disclosed PMKIDs |

Findings carry a severity, supporting evidence, and a documented benign
explanation where one exists.

---

## Validation

### Test suite

177 tests, including:

- HKDF-SHA256 against the RFC 5869 Appendix A test vectors
- DH group structure, key agreement, and rejection of invalid public keys
- Handshake agreement, authentication failure modes, and state ordering
- Record layer integrity, replay, reordering and reflection handling
- RSN parsing across security generations, including malformed elements
- EAPOL message identification and handshake tracking
- End-to-end analysis of a generated capture with known ground truth

### Real capture

The analyzer was additionally validated against 104 seconds of live
monitor-mode capture (31,708 frames, 41 BSSIDs), which identified three
defects not exposed by generated data:

1. An information element with a length field overrunning the frame raised
   an exception that terminated the run. Frame parsing is now bounded per
   frame, with failures recorded and analysis continuing.
2. Corrupted beacons were reported as distinct networks, producing 19
   spurious findings. Frames whose transmitter address has the
   Individual/Group bit set are structurally invalid under IEEE 802.11 and
   are now excluded from network discovery (163 such frames in the capture).
   A minimum-evidence threshold handles the remainder; excluded observations
   are reported rather than discarded.
3. The generated capture's frame distribution differs substantially from
   live traffic:

   | Class | Generated | Live |
   |---|---|---|
   | Management | 47.5% | 9.5% |
   | Control | 29.5% | 45.0% |
   | Data | 23.0% | 45.5% |

Findings on the live capture fell from 49 (24 high severity) to 14 (2 high
severity) after these corrections.

Live captures are excluded from version control, as they contain the MAC
address and SSID of every device within radio range. The generated capture
in `captures/` is the only tracked capture.

---

## Comparison with deployed protocols

| | AKEX | WPA2 four-way | WPA3-SAE |
|---|---|---|---|
| Credential | Pre-shared key | PMK from PBKDF2 | Password |
| Key exchange | Ephemeral DH | None | Dragonfly PAKE |
| Key derivation | HKDF-SHA256 | PRF-384/512 | HKDF |
| Authentication | HMAC over transcript | Key MIC under the KCK | Confirm exchange |
| Forward secrecy | Yes | No | Yes |
| Offline dictionary resistance | No | No | Yes |

WPA2 derives the PTK from the PMK and two nonces without a key exchange, so
a recorded handshake combined with subsequent passphrase recovery permits
retrospective decryption. AKEX performs a fresh Diffie-Hellman exchange per
session, as WPA3-SAE does, and therefore does not share this property.

AKEX remains vulnerable to an offline dictionary attack against a
low-entropy PSK. Addressing this requires a password-authenticated key
exchange such as SAE or OPAQUE.

---

## Limitations

- The record layer provides integrity and authenticity only. Adding an AEAD
  would be confined to `seal` and `open_record` in `akex/channel.py`.
- No cryptographic primitives are reimplemented. HMAC-SHA256 is taken from
  the standard library; the protocol constructed around it is the subject of
  this project.
- No passphrase recovery, key recovery or payload decryption is performed.
  The analyzer operates on frame metadata only.
- Python's arbitrary-precision `pow` is not constant time. Tag comparison
  uses `hmac.compare_digest`, but a production implementation would require
  a constant-time bignum library.
- Detectors are heuristics with documented false-positive modes.
- All capture work was performed against hardware owned by the author on an
  isolated network. Deauthentication frames present in the generated capture
  were never transmitted.

---

## Project structure

```
akex/   params.py     RFC 3526 MODP group definitions
        dh.py         Diffie-Hellman with public-key validation
        kdf.py        HKDF-SHA256 (RFC 5869)
        wire.py       Canonical message encoding, transcript hashing
        protocol.py   Handshake state machines and key schedule
        channel.py    Authenticated record layer
        attacks.py    Adversary simulations
        cli.py        Command line interface

wifi/   frames.py     Frame classification, reason and status codes
        rsn.py        RSN and legacy WPA element parser
        eapol.py      EAPOL-Key parsing, handshake tracking
        capture.py    pcap ingestion
        anomalies.py  Detectors
        synth.py      Generated capture
        analyze.py    Command line interface
```

## Documentation

- [`THREAT_MODEL.md`](THREAT_MODEL.md): STRIDE analysis for both components,
  with mitigations mapped to tests, and accepted risks.
- [`docs/CAPTURE.md`](docs/CAPTURE.md): monitor-mode capture procedure for
  macOS and Linux, Wireshark filters, and containment procedure.
- [`docs/sample-report.txt`](docs/sample-report.txt): full analyzer output.

## References

- IEEE 802.11-2020, §9.4.2.24 (RSN element), §12.7 (key hierarchy)
- RFC 5869: HMAC-based Key Derivation Function (HKDF)
- RFC 3526: MODP Diffie-Hellman groups for IKE
- RFC 2104: HMAC
