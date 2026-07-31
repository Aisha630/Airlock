# Airlock — threat model

Two systems are in scope and they have different adversaries, so they are
modelled separately. The purpose of this document is to be explicit about
what is defended, what is deliberately not, and how each claim is tested --
a security claim without a stated attacker and a test behind it is decoration.

---

## Part 1 — AKEX, the authenticated key exchange

### Assets

| Asset | Why it matters |
|---|---|
| Pre-shared key (PSK) | Long-term credential; compromise allows impersonation of either party |
| DH private exponents | Ephemeral; compromise breaks the confidentiality of one session |
| Session keys | Authenticate application records |
| Handshake transcript integrity | Every key is bound to it |

### Adversary

A Dolev-Yao network attacker. They see every byte, can drop, reorder, replay,
modify and inject messages, and can start sessions with either party. They do
**not** hold the PSK, do not have host access, and cannot solve discrete log
in a 2048-bit MODP group. Assumed computationally bounded at roughly 2^128.

### Threats and mitigations (STRIDE)

| # | STRIDE | Threat | Mitigation | Test |
|---|---|---|---|---|
| 1 | Spoofing | Machine-in-the-middle substitutes its own DH public key | Both tags are HMACs over the transcript keyed from the PSK; the attacker cannot forge either | `test_mitm_without_the_psk_cannot_forge_a_tag`, `attacks.mitm_against_akex` |
| 2 | Spoofing | Peer with the wrong PSK completes the handshake | PSK is hashed into the HKDF salt, so the whole key schedule diverges | `test_wrong_psk_fails_at_the_responder_tag` |
| 3 | Tampering | Any handshake field is modified in flight | Length-prefixed transcript hash covers every field of messages 1 and 2 | `test_tampering_with_message_two_is_detected` |
| 4 | Tampering | Application data is modified | HMAC-SHA256 over header and payload | `test_any_single_bit_flip_is_detected` |
| 5 | Tampering | Downgrade to a weaker DH group | Group id pinned by policy and covered by the transcript; unknown ids refused outright | `test_group_downgrade_is_refused`, `test_unknown_group_id_is_refused` |
| 6 | Tampering | Small-subgroup / degenerate public key forces a known shared secret or leaks exponent bits | Range check plus `y^q mod p == 1` before any secret is computed | `test_degenerate_public_keys_are_rejected`, `test_non_subgroup_public_key_is_rejected` |
| 7 | Repudiation | Peer denies having participated | Out of scope: symmetric PSK authentication is deniable by construction — either party could have produced any tag. Non-repudiation needs signatures. | — |
| 8 | Information disclosure | Timing side channel on tag comparison | All comparisons use `hmac.compare_digest` | `test_constant_time_eq` |
| 9 | Information disclosure | Past sessions decrypted after PSK compromise | Ephemeral DH keys per handshake give forward secrecy | `test_each_handshake_produces_fresh_keys` |
| 10 | Information disclosure | Application payloads are readable on the wire | **Accepted, not mitigated.** The record layer authenticates only. See "Out of scope" below. | — |
| 11 | Denial of service | Attacker forces expensive modexp by flooding message 1 | **Accepted.** No cookie or puzzle mechanism. Noted as the main unhandled DoS. | — |
| 12 | Elevation of privilege | Record replayed or reflected back at its sender | Sequence number and direction are inside the MAC input; receiver requires strictly increasing sequence | `test_replay_is_rejected`, `test_reflection_is_rejected` |
| 13 | Elevation of privilege | Responder acts on keys before the initiator authenticates | `confirm()` must succeed before the session is live | `test_initiator_tag_is_checked_by_the_responder` |

### Explicitly out of scope

- **Confidentiality of application data.** The record layer is a MAC, not an
  AEAD. Adding AES-GCM or ChaCha20-Poly1305 keyed by the same session key is
  a change confined to `seal`/`open_record`. Left out on purpose: calling a
  library AEAD would add a line of code and no understanding.
- **Offline dictionary attack on a low-entropy PSK.** An attacker who records
  a handshake can test passphrase guesses offline against the tag. This is
  the same weakness WPA2-PSK has, and the same one WPA3-SAE fixes with a
  password-authenticated key exchange. AKEX does not fix it; a real design
  at this point should use SAE or OPAQUE rather than a raw PSK.
- **Identity hiding.** Nonces and public keys are sent in the clear.
- **Key compromise impersonation, and host compromise generally.**
- **Side channels beyond tag comparison.** Python's big-integer `pow` is not
  constant time. A production implementation would use a constant-time
  library; this one would leak exponent information to a local attacker who
  can measure it.

---

## Part 2 — the 802.11 analyzer

### Adversary and position

A passive observer in radio range with a monitor-mode adapter — which is to
say, anyone nearby. No association, no credentials, no interaction with the
network at all. For the deauthentication case the attacker also transmits,
which needs nothing more than the same adapter.

### What stays exposed regardless of encryption

This is the analyzer's whole premise. On a fully WPA3-protected network, an
observer still reads:

| Exposed | Consequence |
|---|---|
| Frame type and subtype | Traffic patterns, activity timing, when devices join and leave |
| MAC addresses | Device identity and presence tracking over time |
| SSIDs in beacons and probe requests | Network identity; probe requests leak the *client's* previously joined networks |
| RSN element | Exact security configuration, and therefore which attacks apply |
| Frame sizes and timing | Traffic analysis, and coarse activity fingerprinting |
| EAPOL handshake | Material for an offline attack on a WPA2 passphrase |

Payload confidentiality is not the same thing as privacy. Everything above
is metadata, and it is transmitted in the clear by design, because receivers
need it before any key exists.

### Threats the analyzer detects

| Threat | Detector | Why it works |
|---|---|---|
| Deauthentication flood (DoS, or forcing a handshake capture) | `detect_deauth_flood` | Unprotected deauths are unauthenticated: no MIC, no sequence binding, forgeable by anyone in range |
| Forgeable management frames | `detect_unprotected_deauth` | Correlates observed deauths against the RSN MFP bits — the same burst means something different on an MFP-required network |
| Evil twin / rogue AP | `detect_evil_twin` | A clone can copy an SSID but not the credential, so its advertised security disagrees |
| Weak or broken ciphers (WEP, TKIP), open networks | `detect_weak_security` | Read directly from the advertised RSN element |
| WPA3→WPA2 downgrade exposure | `RSNInfo.generation` | Transition mode offers SAE and PSK together; a client can be pushed onto the PSK path |
| Offline attack material (PMKID, full handshake) | `detect_handshake_exposure` | A PMKID in message 1 needs no client interaction at all |

### Known limitations, stated rather than hidden

- **Heuristics, not proof.** Every detector has a benign explanation, and
  the report prints it alongside the finding. A deauth burst is also what a
  rebooting AP looks like.
- **Spoofed source addresses.** A forged deauth carries the AP's address in
  `addr2`, so the analyzer attributes it to the AP. Nothing in an
  unprotected management frame distinguishes the real transmitter — that is
  precisely the vulnerability. Radiotap signal strength is a weak hint and
  is not used to make the call.
- **Single-channel capture.** A monitor-mode adapter hears one channel at a
  time, so activity on other channels is invisible unless hopping.
- **Metadata only.** No payload decryption is attempted, and no key
  recovery or passphrase cracking is implemented.
- **Thresholds are tuned for small lab captures** and are parameters, not
  constants, so they can be re-tuned for a longer capture.

### Legal and ethical scope

Everything in this repository was built and exercised against hardware I own
on an isolated lab network. The deauthentication frames in the sample capture
are synthetic — generated by `wifi/synth.py`, not transmitted. Capturing or
disrupting networks you do not own or have written authorization to test is
illegal in most jurisdictions, including under the US Computer Fraud and
Abuse Act. See `docs/CAPTURE.md` for how the lab was contained.
