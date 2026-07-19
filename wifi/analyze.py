"""Command line 802.11 capture analyzer.

    python -m wifi analyze captures/lab-synthetic.pcap
    python -m wifi analyze capture.pcap --json report.json
    python -m wifi synth captures/lab-synthetic.pcap
"""

import argparse
import json
import sys
from collections import Counter

from .anomalies import SEVERITY_ORDER, run_all_detectors
from .capture import Capture, load_capture
from .eapol import HandshakeTracker
from .frames import TYPE_MANAGEMENT, TYPE_NAMES


def _rule(title: str) -> str:
    return f"\n{title}\n{'=' * len(title)}"


def _sub(title: str) -> str:
    return f"\n{title}\n{'-' * len(title)}"


def track_handshakes(capture: Capture) -> HandshakeTracker:
    """Feed every EAPOL-Key frame through the handshake tracker in order."""
    tracker = HandshakeTracker()
    for info, key_frame in capture.eapol_frames:
        if info.transmitter is None or info.receiver is None:
            continue
        tracker.observe(
            key_frame,
            transmitter=info.transmitter,
            receiver=info.receiver,
            timestamp=info.timestamp,
            index=info.index,
        )
    return tracker


def report_overview(capture: Capture) -> list[str]:
    lines = [_rule("Capture overview")]
    lines.append(f"file:     {capture.path}")
    lines.append(f"frames:   {len(capture.frames)}")
    lines.append(f"duration: {capture.duration:.2f} s")
    if capture.frames:
        bytes_total = sum(f.length for f in capture.frames)
        lines.append(f"bytes:    {bytes_total} ({bytes_total / 1024:.1f} KiB)")
    if capture.suspect_frames:
        lines.append(
            f"corrupt:  {capture.suspect_frames} frames with an invalid "
            f"transmitter address (excluded from network discovery)"
        )
    if capture.parse_errors:
        lines.append(f"parse errors: {len(capture.parse_errors)}")
        for error in capture.parse_errors[:5]:
            lines.append(f"  - {error}")
    return lines


def report_frame_classes(capture: Capture) -> list[str]:
    """The management / control / data breakdown.

    This is the headline table: it is the part of the traffic that stays
    readable no matter how strong the encryption is.
    """
    lines = [_rule("Frame classification")]
    total = len(capture.frames)
    if total == 0:
        return lines + ["no 802.11 frames in this capture"]

    by_type = Counter(f.frame_type for f in capture.frames)
    lines.append(f"{'class':<12} {'count':>7} {'share':>8}   subtypes")
    lines.append("-" * 74)
    for frame_type, count in sorted(by_type.items()):
        name = TYPE_NAMES.get(frame_type, f"type-{frame_type}")
        subtypes = Counter(
            f.subtype_name for f in capture.frames if f.frame_type == frame_type
        )
        breakdown = ", ".join(
            f"{sub} x{n}" for sub, n in subtypes.most_common(6)
        )
        if len(subtypes) > 6:
            breakdown += f", +{len(subtypes) - 6} more"
        lines.append(
            f"{name:<12} {count:>7} {count / total * 100:>7.1f}%   {breakdown}"
        )
    lines.append("-" * 74)
    lines.append(f"{'total':<12} {total:>7} {100.0:>7.1f}%")

    protected = sum(1 for f in capture.frames if f.protected)
    data_frames = [f for f in capture.frames if f.is_data]
    if data_frames:
        protected_data = sum(1 for f in data_frames if f.protected)
        lines.append(
            f"\n{protected_data}/{len(data_frames)} data frames carry the Protected "
            f"Frame bit ({protected} frames overall)"
        )
    retries = sum(1 for f in capture.frames if f.retry)
    if retries:
        lines.append(f"{retries} frames are retransmissions")
    return lines


def report_networks(capture: Capture) -> list[str]:
    lines = [_rule("Networks observed")]
    if not capture.networks:
        return lines + ["no beacons or probe responses in this capture"]

    for bssid, network in sorted(
        capture.networks.items(), key=lambda kv: -kv[1].beacon_count
    ):
        lines.append(_sub(f'{network.ssid or "<unknown>"}  [{bssid}]'))
        lines.append(f"  channel:  {network.channel}")
        lines.append(f"  security: {network.security}")
        if network.rsn:
            rsn = network.rsn
            lines.append(
                f"  ciphers:  group {rsn.group_cipher}, "
                f"pairwise {'/'.join(rsn.pairwise_ciphers) or 'none'}"
            )
            lines.append(f"  AKM:      {'/'.join(rsn.akm_suites) or 'none'}")
            lines.append(
                f"  MFP:      {rsn.mfp_state} "
                f"(RSN capabilities 0x{rsn.raw_capabilities:04x})"
            )
            if rsn.group_mgmt_cipher:
                lines.append(f"  group mgmt cipher: {rsn.group_mgmt_cipher}")
        lines.append(
            f"  beacons:  {network.beacon_count}, "
            f"probe responses: {network.probe_response_count}"
        )
        if network.clients:
            lines.append(f"  stations: {', '.join(sorted(network.clients))}")
    return lines


def report_association(capture: Capture) -> list[str]:
    """Walk the management exchanges that bring a client onto a network."""
    lines = [_rule("Association and authentication sequence")]
    interesting = {
        "probe-request", "probe-response", "authentication",
        "assoc-request", "assoc-response", "reassoc-request",
        "reassoc-response", "deauthentication", "disassociation",
    }
    selected = [
        f for f in capture.frames
        if f.frame_type == TYPE_MANAGEMENT and f.subtype_name in interesting
    ]
    if not selected:
        return lines + ["no association-related management frames"]

    start = capture.frames[0].timestamp
    lines.append(f"{'t+s':>8}  {'frame':<18} {'transmitter':<18} {'receiver':<18} detail")
    lines.append("-" * 100)
    shown = 0
    deauth_run = 0
    for frame in selected:
        # Collapse the deauth flood: one line for the burst, not 24.
        if frame.subtype_name in ("deauthentication", "disassociation"):
            deauth_run += 1
            if deauth_run > 2:
                continue
        else:
            deauth_run = 0

        detail = []
        if "auth_algorithm" in frame.extra:
            detail.append(
                f"algo={frame.extra['auth_algorithm']} seq={frame.extra['auth_seq']}"
            )
        if frame.status_code is not None:
            detail.append(f"status={frame.status_code}")
        if frame.reason_code is not None:
            detail.append(f"reason={frame.reason_code}")
        if frame.ssid is not None:
            detail.append(f'ssid="{frame.ssid}"')
        lines.append(
            f"{frame.timestamp - start:>8.3f}  {frame.subtype_name:<18} "
            f"{frame.transmitter or '-':<18} {frame.receiver or '-':<18} "
            f"{' '.join(detail)}"
        )
        shown += 1

    skipped = len(selected) - shown
    if skipped > 0:
        lines.append(f"... {skipped} further deauth-class frames collapsed (see findings)")
    return lines


def report_handshakes(capture: Capture, tracker: HandshakeTracker) -> list[str]:
    lines = [_rule("WPA four-way handshakes")]
    handshakes = tracker.all()
    if not handshakes:
        return lines + ["no EAPOL-Key frames in this capture"]

    start = capture.frames[0].timestamp
    for handshake in handshakes:
        network = capture.networks.get(handshake.ap)
        ssid = network.ssid if network else "unknown"
        lines.append(_sub(f'{handshake.station} <-> {handshake.ap} ("{ssid}")'))
        for number in sorted(handshake.messages):
            offset = handshake.messages[number] - start
            counter = handshake.replay_counters[number]
            role = "AP -> STA" if number in (1, 3) else "STA -> AP"
            content = {
                1: "ANonce, no MIC yet",
                2: "SNonce + RSN element, MIC present",
                3: "install key, encrypted key data, MIC",
                4: "zero nonce, acknowledgement only",
            }[number]
            lines.append(
                f"  M{number}  t+{offset:>7.3f}s  {role}  "
                f"replay counter {counter}  ({content})"
            )
        for note in handshake.notes():
            lines.append(f"  note: {note}")
    return lines


def report_findings(findings) -> list[str]:
    lines = [_rule("Security findings")]
    if not findings:
        return lines + ["no findings"]
    counts = Counter(f.severity for f in findings)
    summary = ", ".join(
        f"{counts[s]} {s}" for s in sorted(counts, key=lambda x: SEVERITY_ORDER.get(x, 9))
    )
    lines.append(f"{len(findings)} findings: {summary}\n")
    for finding in findings:
        lines.append(finding.render())
        lines.append("")
    return lines


def build_json(capture: Capture, tracker: HandshakeTracker, findings) -> dict:
    """Machine-readable form of the same report."""
    return {
        "capture": {
            "path": capture.path,
            "frames": len(capture.frames),
            "duration_seconds": round(capture.duration, 3),
            "suspect_frames": capture.suspect_frames,
            "parse_errors": capture.parse_errors,
        },
        "frame_classes": {
            TYPE_NAMES.get(t, f"type-{t}"): count
            for t, count in sorted(Counter(f.frame_type for f in capture.frames).items())
        },
        "frame_subtypes": dict(Counter(f.subtype_name for f in capture.frames)),
        "networks": [
            {
                "bssid": network.bssid,
                "ssid": network.ssid,
                "channel": network.channel,
                "security": network.security,
                "group_cipher": network.rsn.group_cipher if network.rsn else None,
                "pairwise_ciphers": network.rsn.pairwise_ciphers if network.rsn else [],
                "akm_suites": network.rsn.akm_suites if network.rsn else [],
                "mfp": network.rsn.mfp_state if network.rsn else None,
                "beacons": network.beacon_count,
                "clients": sorted(network.clients),
            }
            for network in sorted(capture.networks.values(), key=lambda n: n.bssid)
        ],
        "handshakes": [
            {
                "ap": handshake.ap,
                "station": handshake.station,
                "messages_seen": handshake.observed,
                "complete": handshake.complete,
                "duration_ms": (
                    round(handshake.duration_ms, 3) if handshake.complete else None
                ),
                "pmkid": handshake.pmkid.hex() if handshake.pmkid else None,
                "notes": handshake.notes(),
            }
            for handshake in tracker.all()
        ],
        "findings": [
            {
                "severity": finding.severity,
                "title": finding.title,
                "detail": finding.detail,
                "evidence": finding.evidence,
                "benign_explanation": finding.false_positive,
            }
            for finding in findings
        ],
    }


def cmd_analyze(args: argparse.Namespace) -> int:
    capture = load_capture(args.pcap)
    tracker = track_handshakes(capture)
    findings = run_all_detectors(capture, tracker.all())

    sections = [
        report_overview(capture),
        report_frame_classes(capture),
        report_networks(capture),
        report_association(capture),
        report_handshakes(capture, tracker),
        report_findings(findings),
    ]
    for section in sections:
        print("\n".join(section))

    if args.json:
        with open(args.json, "w") as handle:
            json.dump(build_json(capture, tracker, findings), handle, indent=2)
        print(f"\nJSON report written to {args.json}")

    # A non-zero exit on high-severity findings makes this usable as a
    # check in a pipeline, not just as something a human reads.
    high = [f for f in findings if f.severity == "high"]
    if high and args.fail_on_high:
        print(f"\n{len(high)} high-severity findings")
        return 1
    return 0


def cmd_synth(args: argparse.Namespace) -> int:
    from .synth import write_capture

    count = write_capture(args.output)
    print(f"wrote {count} synthetic frames to {args.output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m wifi",
        description="802.11 capture analyzer: classification, security posture, anomalies.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="analyze a pcap of 802.11 frames")
    analyze.add_argument("pcap", help="path to a pcap/pcapng capture")
    analyze.add_argument("--json", help="also write a JSON report to this path")
    analyze.add_argument(
        "--fail-on-high",
        action="store_true",
        help="exit non-zero if any high-severity finding is reported",
    )
    analyze.set_defaults(func=cmd_analyze)

    synth = sub.add_parser("synth", help="generate the synthetic lab capture")
    synth.add_argument(
        "output", nargs="?", default="captures/lab-synthetic.pcap",
        help="path to write the pcap to",
    )
    synth.set_defaults(func=cmd_synth)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
