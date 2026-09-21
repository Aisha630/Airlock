"""Anomaly detection over parsed 802.11 metadata.

Every detector here works on unencrypted header fields, which is what makes
them usable against a WPA2 or WPA3 network whose payloads you cannot read.
Each returns findings with a severity and an explicit reason, because a
detector that says only "suspicious" cannot be acted on.

These are heuristics with honest false-positive modes, documented per
detector. A deauthentication burst is the signature of an attack, but it is
also what a busy AP does when it sheds clients, and the analyzer says so.
"""

from collections import defaultdict
from dataclasses import dataclass, field

from .capture import Capture, Network
from .frames import REASON_CODES, FrameInfo

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# A deauth flood is defined by rate, not by count: a handful of deauths over
# a long capture is normal roaming. These thresholds are tuned for a small
# capture and are arguments to the detector so they can be re-tuned.
DEAUTH_WINDOW_SECONDS = 5.0
DEAUTH_BURST_THRESHOLD = 8

# An access point beacons roughly ten times a second, so over any capture of
# reasonable length a real network produces many beacons. A BSSID seen once
# is far more likely to be a corrupted frame that survived the structural
# address check than a genuine access point. Networks below this threshold
# are summarised rather than reported individually -- excluded from the
# findings, but never silently dropped.
MIN_BEACONS_FOR_A_FINDING = 2


@dataclass
class Finding:
    """One anomaly, with the evidence behind it."""

    severity: str
    title: str
    detail: str
    evidence: list[str] = field(default_factory=list)
    false_positive: str = ""

    def render(self, indent: str = "") -> str:
        lines = [f"{indent}[{self.severity.upper():>6}] {self.title}",
                 f"{indent}         {self.detail}"]
        for item in self.evidence:
            lines.append(f"{indent}         - {item}")
        if self.false_positive:
            lines.append(f"{indent}         benign explanation: {self.false_positive}")
        return "\n".join(lines)


def detect_deauth_flood(
    capture: Capture,
    window: float = DEAUTH_WINDOW_SECONDS,
    threshold: int = DEAUTH_BURST_THRESHOLD,
) -> list[Finding]:
    """Flag bursts of deauthentication or disassociation frames.

    A deauth frame is a management frame. On a network without management
    frame protection it carries no authentication whatsoever, so anyone
    within radio range can forge one from any address and knock a client
    off. That is the entire attack: no key material, no association, no
    knowledge of the passphrase.

    Detection is a sliding window over frames grouped by (source,
    destination): a genuine disconnect is one or two frames, a flood is a
    sustained stream aimed at keeping a client off the network.
    """
    findings: list[Finding] = []
    groups: dict[tuple[str, str], list[FrameInfo]] = defaultdict(list)
    for frame in capture.frames:
        if frame.subtype_name in ("deauthentication", "disassociation"):
            source = frame.transmitter or "unknown"
            destination = frame.receiver or "unknown"
            groups[(source, destination)].append(frame)

    for (source, destination), frames in sorted(groups.items()):
        peak, peak_start = _max_in_window(frames, window)
        if peak < threshold:
            continue

        reasons = sorted({f.reason_code for f in frames if f.reason_code is not None})
        reason_text = ", ".join(
            f"{code} ({REASON_CODES.get(code, 'unknown')})" for code in reasons
        )
        target = "the whole BSS (broadcast)" if destination.startswith("ff:") else destination
        protected = sum(1 for f in frames if f.protected)

        evidence = [
            f"{len(frames)} frames total, peak {peak} within {window:g} s "
            f"starting at t+{peak_start:.2f} s",
            f"source {source} -> target {target}",
            f"reason codes seen: {reason_text or 'none decoded'}",
            f"{protected}/{len(frames)} frames were cryptographically protected",
        ]
        if protected == 0:
            evidence.append(
                "none were protected, so every one of them is forgeable by "
                "any device in range"
            )

        findings.append(
            Finding(
                severity="high",
                title="Deauthentication / disassociation flood",
                detail=(
                    f"{peak} deauth-class frames from {source} inside a "
                    f"{window:g}-second window -- the signature of a forced "
                    f"disconnect, used either as denial of service or to make "
                    f"a client reconnect so its four-way handshake can be captured"
                ),
                evidence=evidence,
                false_positive=(
                    "an access point rebooting, shedding clients under load, or "
                    "steering a client to another band also emits deauths, though "
                    "rarely this many this fast from one address"
                ),
            )
        )
    return findings


def _max_in_window(frames: list[FrameInfo], window: float) -> tuple[int, float]:
    """Largest number of frames inside any `window`-second span.

    Two pointers over time-sorted frames: O(n) rather than O(n^2), and it
    finds the true peak instead of only checking fixed bucket boundaries,
    which would miss a burst that straddles two buckets.
    """
    if not frames:
        return 0, 0.0
    times = sorted(f.timestamp for f in frames)
    best = 0
    best_start = times[0]
    left = 0
    for right, end in enumerate(times):
        while end - times[left] > window:
            left += 1
        if right - left + 1 > best:
            best = right - left + 1
            best_start = times[left]
    return best, best_start - times[0]


def detect_unprotected_deauth(capture: Capture) -> list[Finding]:
    """Flag networks whose deauths are unprotected because MFP is off.

    This is the pairing that matters: an MFP-required network makes the
    forged-deauth attack impossible, so the same burst of frames means
    something quite different depending on what the beacon advertised.
    """
    findings = []
    deauth_bssids = {
        frame.bssid
        for frame in capture.frames
        if frame.subtype_name in ("deauthentication", "disassociation")
        and frame.bssid
        and not frame.protected
    }
    for bssid in sorted(deauth_bssids):
        network = capture.networks.get(bssid)
        if network is None or network.rsn is None:
            continue
        if network.rsn.mfp_required:
            # MFP required and yet an unprotected deauth was accepted on the
            # air: worth seeing, since a compliant client should ignore it.
            findings.append(
                Finding(
                    severity="low",
                    title="Unprotected deauth on an MFP-required network",
                    detail=(
                        f'"{network.ssid}" ({bssid}) requires management frame '
                        "protection, so compliant clients will ignore these "
                        "unprotected frames -- the attack is visible but ineffective"
                    ),
                    evidence=[f"RSN capabilities: MFP {network.rsn.mfp_state}"],
                )
            )
            continue
        findings.append(
            Finding(
                severity="high",
                title="Forgeable management frames (no MFP)",
                detail=(
                    f'"{network.ssid}" ({bssid}) advertises MFP as '
                    f"{network.rsn.mfp_state}, and unprotected deauthentication "
                    "frames were observed on it; these frames are unauthenticated "
                    "and can be forged by anyone in range"
                ),
                evidence=[
                    f"security: {network.rsn.generation}",
                    f"RSN capabilities word: 0x{network.rsn.raw_capabilities:04x}",
                    "remediation: enable 802.11w (PMF) as required, which is "
                    "mandatory in WPA3 and optional in WPA2",
                ],
            )
        )
    return findings


def detect_evil_twin(capture: Capture) -> list[Finding]:
    """Flag one SSID advertised from more than one BSSID with different security.

    A roaming network legitimately has many BSSIDs per SSID, so the BSSID
    count alone proves nothing. What is suspicious is the *security* of those
    BSSIDs disagreeing: a rogue AP cloning an SSID usually cannot clone the
    passphrase, so it comes up open or with a weaker AKM, hoping clients
    attach to the stronger signal.
    """
    findings = []
    by_ssid: dict[str, list[Network]] = defaultdict(list)
    for network in capture.networks.values():
        if (
            network.ssid
            and network.ssid != "<wildcard/hidden>"
            and _well_attested(network)
        ):
            by_ssid[network.ssid].append(network)

    for ssid, networks in sorted(by_ssid.items()):
        if len(networks) < 2:
            continue
        profiles = {n.security for n in networks}
        if len(profiles) == 1:
            findings.append(
                Finding(
                    severity="info",
                    title="SSID advertised by multiple BSSIDs",
                    detail=(
                        f'"{ssid}" is advertised by {len(networks)} BSSIDs with '
                        "identical security settings, which is what a normal "
                        "multi-AP or multi-band deployment looks like"
                    ),
                    evidence=[f"{n.bssid} ({n.security})" for n in networks],
                )
            )
            continue
        findings.append(
            Finding(
                severity="high",
                title="Possible evil twin: same SSID, different security",
                detail=(
                    f'"{ssid}" is advertised by {len(networks)} BSSIDs that do not '
                    "agree on their security configuration; a rogue AP cloning an "
                    "SSID cannot clone the credential, so it typically advertises "
                    "weaker or no security"
                ),
                evidence=[
                    f"{n.bssid}: {n.security}, "
                    f"{n.beacon_count} beacons, channel {n.channel}"
                    for n in sorted(networks, key=lambda x: x.bssid)
                ],
                false_positive=(
                    "a deliberate transition-mode deployment, or an AP mid-way "
                    "through a configuration change, produces the same pattern"
                ),
            )
        )
    return findings


def _well_attested(network: Network) -> bool:
    """True when there is enough evidence that this network is real."""
    return (
        network.beacon_count + network.probe_response_count
        >= MIN_BEACONS_FOR_A_FINDING
    )


def _describe(network: Network, bssid: str) -> str:
    """Label a network for a finding, without printing 'None' as an SSID."""
    ssid = network.ssid if network.ssid else "<no SSID element>"
    return f'"{ssid}" ({bssid})'


def detect_low_confidence_networks(capture: Capture) -> list[Finding]:
    """Account for what was excluded, so exclusions stay visible."""
    weak_evidence = [
        (bssid, network)
        for bssid, network in sorted(capture.networks.items())
        if not _well_attested(network)
    ]
    if not weak_evidence and not capture.suspect_frames:
        return []

    evidence = []
    if capture.suspect_frames:
        evidence.append(
            f"{capture.suspect_frames} frames had a structurally invalid "
            "transmitter address (group bit set) and were excluded from "
            "network discovery entirely"
        )
    if weak_evidence:
        evidence.append(
            f"{len(weak_evidence)} BSSIDs were seen fewer than "
            f"{MIN_BEACONS_FOR_A_FINDING} times and are not reported "
            "individually"
        )
        evidence.extend(
            f"{bssid}: {network.beacon_count} beacons, "
            f"ssid {network.ssid!r}"
            for bssid, network in weak_evidence[:5]
        )
        if len(weak_evidence) > 5:
            evidence.append(f"... and {len(weak_evidence) - 5} more")

    return [
        Finding(
            severity="info",
            title="Low-confidence observations excluded from the findings",
            detail=(
                "a real access point beacons about ten times a second, so a "
                "BSSID seen once in a capture of any length is far more "
                "likely to be a corrupted frame than a network; these are "
                "listed here rather than reported as findings"
            ),
            evidence=evidence,
            false_positive=(
                "a genuine but very distant access point, or one captured "
                "for only a moment while channel hopping, can also appear "
                "this way"
            ),
        )
    ]


def detect_weak_security(capture: Capture) -> list[Finding]:
    """Turn each network's advertised RSN weaknesses into findings."""
    findings = []
    for bssid, network in sorted(capture.networks.items()):
        if not _well_attested(network):
            continue  # accounted for by detect_low_confidence_networks
        label = _describe(network, bssid)
        if network.rsn is None:
            findings.append(
                Finding(
                    severity="high",
                    title="Open network",
                    detail=(
                        f"{label} advertises no RSN element, so traffic is "
                        "unencrypted and unauthenticated on the air"
                    ),
                    evidence=[f"{network.beacon_count} beacons observed"],
                )
            )
            continue
        for weakness in network.rsn.weaknesses():
            severity = "high" if "broken" in weakness or "downgrade" in weakness else "medium"
            findings.append(
                Finding(
                    severity=severity,
                    title=f"Weak configuration: {network.rsn.generation}",
                    detail=f"{label}: {weakness}",
                    evidence=[
                        f"group cipher {network.rsn.group_cipher}, "
                        f"pairwise {'/'.join(network.rsn.pairwise_ciphers)}, "
                        f"AKM {'/'.join(network.rsn.akm_suites)}, "
                        f"MFP {network.rsn.mfp_state}"
                    ],
                )
            )
    return findings


def detect_handshake_exposure(capture: Capture, handshakes) -> list[Finding]:
    """Flag captured four-way handshakes and PMKIDs as offline-attack material."""
    findings = []
    for handshake in handshakes:
        network = capture.networks.get(handshake.ap)
        ssid = network.ssid if network else "unknown"
        if handshake.pmkid:
            findings.append(
                Finding(
                    severity="high",
                    title="PMKID disclosed in EAPOL message 1",
                    detail=(
                        f'AP {handshake.ap} ("{ssid}") included a PMKID in message 1. '
                        "Because the PMKID is HMAC-SHA1(PMK, \"PMK Name\" || AP || STA), "
                        "this one frame supports an offline dictionary attack on the "
                        "passphrase with no client and no full handshake required"
                    ),
                    evidence=[
                        f"PMKID {handshake.pmkid.hex()}",
                        f"station {handshake.station}",
                        "remediation: WPA3-SAE, or disable PMKID caching on the AP",
                    ],
                )
            )
        if handshake.complete:
            findings.append(
                Finding(
                    severity="medium",
                    title="Complete four-way handshake captured",
                    detail=(
                        f'the full handshake between {handshake.station} and '
                        f'{handshake.ap} ("{ssid}") is in this capture. WPA2 derives '
                        "the PTK from the PMK and the two nonces with no key "
                        "exchange, so recovering the passphrase later decrypts this "
                        "session retroactively -- WPA2-PSK has no forward secrecy"
                    ),
                    evidence=[
                        f"completed in {handshake.duration_ms:.1f} ms",
                        f"ANonce {handshake.anonce.hex()[:16]}..." if handshake.anonce else "ANonce not captured",
                        f"SNonce {handshake.snonce.hex()[:16]}..." if handshake.snonce else "SNonce not captured",
                        "remediation: WPA3-SAE runs a Dragonfly key exchange per "
                        "session, so a later passphrase compromise reveals nothing",
                    ],
                )
            )
    return findings


def run_all_detectors(capture: Capture, handshakes) -> list[Finding]:
    """Run every detector and return findings sorted by severity."""
    findings = (
        detect_deauth_flood(capture)
        + detect_unprotected_deauth(capture)
        + detect_evil_twin(capture)
        + detect_weak_security(capture)
        + detect_handshake_exposure(capture, handshakes)
        + detect_low_confidence_networks(capture)
    )
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.title))
