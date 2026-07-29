"""Robustness against the things real captures contain and synthetic ones do not.

Every test here corresponds to a defect found by running the analyzer against
an actual monitor-mode capture rather than the generated one. Radio is a
lossy medium: frames arrive truncated, with flipped bits, and clipped by the
adapter's snap length. A parser that assumes well-formed input works on a
capture it generated itself and falls over on the first real one.
"""

import struct

import pytest
from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    RadioTap,
)
from scapy.utils import wrpcap

from wifi.anomalies import MIN_BEACONS_FOR_A_FINDING, run_all_detectors
from wifi.capture import load_capture
from wifi.frames import TYPE_MANAGEMENT, FrameInfo


def _beacon(bssid: str, ssid: str = "RealNet"):
    return (
        RadioTap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                addr2=bssid, addr3=bssid)
        / Dot11Beacon(beacon_interval=100, cap=0x1101)
        / Dot11Elt(ID=0, info=ssid.encode())
        / Dot11Elt(ID=48, info=bytes.fromhex(
            "0100000fac040100000fac040100000fac020000"))
    )


def _write(packets, path):
    for index, packet in enumerate(packets):
        packet.time = 1_700_000_000.0 + index * 0.1
    wrpcap(str(path), packets)
    return str(path)


# --- structural transmitter validation -----------------------------------

@pytest.mark.parametrize(
    "addr2,valid",
    [
        ("02:00:00:aa:00:01", True),    # locally administered, individual
        ("bc:07:1d:7b:88:c7", True),    # ordinary manufacturer address
        ("01:00:5e:00:00:01", False),   # group bit set
        ("1f:8a:d7:84:a3:df", False),   # group bit set: seen in a real capture
        ("ff:ff:ff:ff:ff:ff", False),   # broadcast cannot transmit
        (None, True),                   # ACK and CTS carry no addr2
    ],
)
def test_transmitter_validity(addr2, valid):
    """A transmitter address must be an individual address, per IEEE 802.11."""
    frame = FrameInfo(
        index=0, timestamp=0.0, frame_type=TYPE_MANAGEMENT, subtype=8,
        type_name="management", subtype_name="beacon", addr2=addr2,
    )
    assert frame.transmitter_is_valid is valid


def test_malformed_address_string_is_not_valid():
    frame = FrameInfo(
        index=0, timestamp=0.0, frame_type=TYPE_MANAGEMENT, subtype=8,
        type_name="management", subtype_name="beacon", addr2="not-a-mac",
    )
    assert frame.transmitter_is_valid is False


def test_corrupt_beacon_does_not_invent_a_network(tmp_path):
    """The defect a real capture exposed: garbled beacons became 'networks'.

    A beacon whose transmitter address has the group bit set was corrupted
    in flight. Before this check, each one was reported as a brand new open
    access point with a garbage SSID -- 19 such findings in a two-minute
    capture, all of them noise.
    """
    packets = [_beacon("02:00:00:aa:00:01") for _ in range(4)]
    packets += [_beacon("1f:8a:d7:84:a3:df", "garbled") for _ in range(2)]
    capture = load_capture(_write(packets, tmp_path / "corrupt.pcap"))

    assert capture.suspect_frames == 2
    assert set(capture.networks) == {"02:00:00:aa:00:01"}
    # The frames are still counted -- they were genuinely received.
    assert len(capture.frames) == 6


def test_suspect_frames_are_counted_not_silently_dropped(tmp_path):
    packets = [_beacon("02:00:00:aa:00:01") for _ in range(3)]
    packets += [_beacon("03:00:00:bb:00:02") for _ in range(3)]
    capture = load_capture(_write(packets, tmp_path / "counted.pcap"))
    _, findings = _analyze(capture)
    excluded = [f for f in findings if "Low-confidence" in f.title]
    assert excluded, "exclusions must be reported, not hidden"
    assert "structurally invalid" in " ".join(excluded[0].evidence)


# --- malformed information elements ---------------------------------------

def test_truncated_information_element_does_not_abort_the_capture(tmp_path):
    """A beacon with an element whose length byte overruns the frame.

    Scapy represents this as a Dot11Elt with no `info` field, and reading
    the attribute raises. One such beacon previously killed the entire run.
    """
    good = _beacon("02:00:00:aa:00:01")
    broken = (
        RadioTap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                addr2="02:00:00:cc:00:03", addr3="02:00:00:cc:00:03")
        / Dot11Beacon(beacon_interval=100, cap=0x1101)
        # Element 0 promises 200 bytes of SSID and supplies three.
        / bytes([0, 200, 0x41, 0x42, 0x43])
    )
    path = _write([good, broken, good, good], tmp_path / "truncated.pcap")

    capture = load_capture(path)
    assert len(capture.frames) == 4
    # The well-formed network survives the bad frame in the middle.
    assert "02:00:00:aa:00:01" in capture.networks


def test_non_utf8_ssid_is_decoded_without_raising(tmp_path):
    """SSIDs are arbitrary bytes, not text."""
    packets = [
        RadioTap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                addr2="02:00:00:aa:00:01", addr3="02:00:00:aa:00:01")
        / Dot11Beacon(beacon_interval=100, cap=0x1101)
        / Dot11Elt(ID=0, info=b"\xff\xfe\x80 binary")
        for _ in range(2)
    ]
    capture = load_capture(_write(packets, tmp_path / "binary-ssid.pcap"))
    network = capture.networks["02:00:00:aa:00:01"]
    assert isinstance(network.ssid, str)


def test_empty_capture_is_handled(tmp_path):
    capture = load_capture(_write([], tmp_path / "empty.pcap"))
    assert capture.frames == []
    assert capture.duration == 0.0
    assert run_all_detectors(capture, []) == []


# --- evidence threshold ----------------------------------------------------

def _analyze(capture):
    from wifi.analyze import track_handshakes

    tracker = track_handshakes(capture)
    return tracker, run_all_detectors(capture, tracker.all())


def test_single_beacon_network_is_not_reported_as_a_finding(tmp_path):
    """One beacon is not evidence of a network; an AP beacons ~10x a second."""
    packets = [_beacon("02:00:00:aa:00:01") for _ in range(5)]
    packets += [_beacon("02:00:00:ff:00:09", "OneOff")]
    capture = load_capture(_write(packets, tmp_path / "threshold.pcap"))
    _, findings = _analyze(capture)

    reported = " ".join(f.detail for f in findings if "Weak" in f.title)
    assert "02:00:00:aa:00:01" in reported
    assert "02:00:00:ff:00:09" not in reported

    # ...but it is still accounted for.
    excluded = [f for f in findings if "Low-confidence" in f.title]
    assert excluded
    assert "02:00:00:ff:00:09" in " ".join(excluded[0].evidence)


def test_threshold_is_a_named_constant_not_a_magic_number():
    assert MIN_BEACONS_FOR_A_FINDING >= 2


def test_missing_ssid_is_labelled_rather_than_printed_as_none(tmp_path):
    """A network with no SSID element must not render as the string 'None'."""
    packets = [
        RadioTap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                addr2="02:00:00:aa:00:01", addr3="02:00:00:aa:00:01")
        / Dot11Beacon(beacon_interval=100, cap=0x1101)
        / Dot11Elt(ID=48, info=bytes.fromhex(
            "0100000fac040100000fac040100000fac020000"))
        for _ in range(3)
    ]
    capture = load_capture(_write(packets, tmp_path / "no-ssid.pcap"))
    _, findings = _analyze(capture)
    rendered = " ".join(f.detail for f in findings)
    assert '"None"' not in rendered
    assert "<no SSID element>" in rendered
