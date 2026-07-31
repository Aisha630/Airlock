# Airlock

An 802.11 security lab and authenticated key exchange — two halves of the
same problem: a key exchange built correctly from the inside, and what a key
exchange looks like from the outside to someone in radio range.

1. **`akex/`** — an authenticated Diffie–Hellman key exchange built on
   HMAC-SHA256 and a hand-written HKDF, with an adversary harness that runs
   seven attacks against it.
2. **`wifi/`** — an 802.11 capture analyzer that classifies management,
   control and data frames, reads advertised security capabilities,
   reconstructs WPA2 four-way handshakes, and reports anomalies.

**177 tests**, including the RFC 5869 HKDF vectors and an end-to-end
analysis against known ground truth.

```sh
make setup
make demo
```

---

## Part 1 — the key exchange

```
  Initiator                                        Responder
      |  1.  group, nonce_i, g^i                       |
      | ---------------------------------------------> |
      |  2.  nonce_r, g^r, tag_r                       |
      | <--------------------------------------------- |
      |  3.  tag_i                                     |
      | ---------------------------------------------> |
      |          session live, four keys agreed        |
```

Plain DH agrees a key with *somebody* and says nothing about who. Each tag
is an HMAC-SHA256 over the handshake transcript, keyed from a value derived
from both the DH secret and a pre-shared key — so forging one requires the
PSK.

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

- **PSK in the extract salt** — both the DH secret and the PSK are needed to
  reach the PRK.
- **Transcript hash in every label** — keys depend on every handshake byte,
  so a downgrade changes them.
- **Distinct labels** — four independent keys from one exchange.
- **Directional session keys** — a record cannot be reflected back at its
  sender.

### Public-key validation

The DH arithmetic is three lines; the rest of `akex/dh.py` is validation,
which is where finite-field DH actually fails. Both checks run before any
secret is computed:

| Check | Attack it stops |
|---|---|
| `2 ≤ y ≤ p-2` | `y ∈ {0, 1, p-1}` forces a shared secret the attacker already knows |
| `y^q mod p == 1` | Elements outside the prime-order subgroup leak a private-key bit per handshake |

Groups are RFC 3526 MODP-2048 and MODP-3072 — safe primes, so one
exponentiation is a complete subgroup test. Unknown group ids are refused.

### Adversary harness

`make attacks`:

```
[  BLOCKED] Peer with the wrong PSK
[  BLOCKED] Single-bit tamper with the handshake transcript (nonce)
[  BLOCKED] Tamper with an application record in flight
[  BLOCKED] Replay of a captured valid record
[  BLOCKED] Machine-in-the-middle without the PSK
[  BLOCKED] Small-subgroup / degenerate public key
[  BLOCKED] Downgrade to a weaker DH group
[SUCCEEDED] Machine-in-the-middle against UNAUTHENTICATED DH (control)
```

The last line is the point: the same attack against the same code with the
authentication removed wins completely. Without that control, "7/7 blocked"
is a claim about nothing.

---

## Part 2 — the 802.11 analyzer

`python -m wifi analyze <pcap>` — full output in
[`docs/sample-report.txt`](docs/sample-report.txt).

**Frame classification.** The type/subtype pair is in the clear on every
frame, even on a fully protected network.

```
class          count    share   subtypes
management        66    47.5%   deauthentication x27, beacon x23, ...
control           41    29.5%   ack x33, rts x3, cts x3, block-ack x2
data              32    23.0%   qos-data x24, data x8
```

**Security posture.** The RSN element is parsed by hand from the byte layout
(IEEE 802.11-2020 §9.4.2.24), including the two MFP bits that decide whether
deauthentication attacks work:

```
LabNet-WPA3  [02:00:00:bb:00:01]
  security: WPA3-Personal (SAE)
  ciphers:  group CCMP-128, pairwise CCMP-128
  MFP:      required (RSN capabilities 0x00c0)
```

Distinguishes WPA1, WPA2-PSK, Enterprise, WPA3-SAE, OWE, and WPA3/WPA2
transition mode — the last flagged separately because offering SAE and PSK
together allows a downgrade to the PSK path.

**Four-way handshakes.** Messages carry no numbers on the wire; they are
identified from three flag bits in Key Information. M2 and M4 differ only by
the Secure bit, so an ambiguous capture returns `None` rather than a guess.

```
  M1  t+  0.627s  AP -> STA  replay counter 1  (ANonce, no MIC yet)
  M2  t+  0.635s  STA -> AP  replay counter 1  (SNonce + RSN element, MIC)
  M3  t+  0.642s  AP -> STA  replay counter 2  (install key, encrypted data)
  M4  t+  0.649s  STA -> AP  replay counter 2  (zero nonce, ack only)
  note: AP volunteered a PMKID in message 1; this single frame supports an
        offline dictionary attack with no client interaction
```

**Detectors.** Deauthentication floods (sliding window), forgeable
management frames correlated against the MFP bits, evil twins (same SSID,
disagreeing security), weak ciphers and open networks, and captured
offline-attack material. Every finding carries severity, evidence, and the
benign explanation where one exists.

---

## AKEX vs. the real thing

| | AKEX | WPA2 four-way | WPA3-SAE |
|---|---|---|---|
| Credential | PSK | PMK from PBKDF2 | password |
| Key exchange | ephemeral DH | **none** | Dragonfly PAKE |
| Key schedule | HKDF-SHA256 | PRF-384/512 | HKDF |
| Authentication | HMAC over transcript | MIC under the KCK | confirm exchange |
| Forward secrecy | yes | **no** | yes |
| Offline dictionary attack | yes, on a weak PSK | yes | **no** |

WPA2 derives the PTK from the PMK and two nonces with no key exchange, so a
recorded handshake plus a later passphrase recovery decrypts the session
retroactively. AKEX avoids that the way WPA3 does — a fresh exchange per
session — which is why the analyzer reports every captured handshake as
exposure.

AKEX does **not** fix the offline dictionary attack on a weak PSK. Fixing
that needs a PAKE (SAE, OPAQUE). See [`THREAT_MODEL.md`](THREAT_MODEL.md).

---

## Validation against a real capture

Developed against the synthetic capture, then run on 104 seconds of real
monitor-mode capture (31,708 frames, 41 BSSIDs). Three failures, each now
covered by `tests/test_robustness.py`: a crash on a malformed information
element; 19 false "open networks" from corrupted beacons, fixed by rejecting
frames whose transmitter address has the group bit set (structurally
impossible per IEEE 802.11) plus a minimum-evidence bar; and a synthetic
frame mix nothing like real air (management 47.5% vs 9.5%).

**49 findings (24 high) → 14 (2 high)**, all survivors genuine.

Real captures are gitignored — they contain the MAC and SSID of every device
in range. Only the synthetic capture is tracked.

---

## Running it

```sh
make setup        # virtualenv + dependencies
make test         # 177 tests
make demo         # handshake, attacks, capture analysis

python -m akex handshake [--group 15]
python -m akex attacks
python -m wifi synth captures/lab.pcap
python -m wifi analyze capture.pcap --json report.json --fail-on-high
```

`--fail-on-high` exits non-zero on a high-severity finding, so the analyzer
works as a pipeline check. To analyze your own capture, see
[`docs/CAPTURE.md`](docs/CAPTURE.md) for monitor-mode setup on macOS and
Linux.

---

## Layout

```
akex/       params.py  RFC 3526 groups      wifi/   frames.py    classification
            dh.py      DH + validation              rsn.py       RSN/WPA parser
            kdf.py     HKDF (RFC 5869)              eapol.py     four-way handshake
            wire.py    canonical encoding           capture.py   pcap -> frames
            protocol.py  handshake + keys           anomalies.py detectors
            channel.py   record layer               synth.py     lab capture
            attacks.py   adversary harness          analyze.py   CLI
```

`THREAT_MODEL.md` has STRIDE tables for both halves. `docs/CAPTURE.md`
covers capture methodology and lab containment.

---

## Scope

- **The record layer authenticates; it does not encrypt.** Adding an AEAD is
  confined to two functions; left out deliberately.
- **No primitive was reimplemented.** HMAC-SHA256 comes from `hmac`. What is
  built here is the protocol around it — HKDF, key schedule, transcript
  binding, state machines, record layer.
- **No passphrase cracking or payload decryption.** Metadata only.
- **`pow` is not constant time.** Tag comparison uses `compare_digest`, but
  production would need a constant-time bignum library.
- **Detectors are heuristics** with documented false-positive modes.
- **Run against hardware I own on an isolated lab network.** The deauth
  frames in the synthetic capture were never transmitted.
