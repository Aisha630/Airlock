"""End-to-end analysis of the synthetic capture, against known ground truth.

`wifi/synth.py` builds the capture, so exactly what is in it is known. That
makes these real assertions rather than a smoke test: the expected counts,
networks, handshakes and findings below are the scenario the generator was
written to produce, and a regression in any parser shows up as a mismatch.
"""

import json

import pytest

from wifi.analyze import build_json, track_handshakes
from wifi.anomalies import run_all_detectors
from wifi.capture import load_capture
from wifi.synth import (
    AP_EVIL_TWIN,
    AP_LEGACY,
    AP_WPA2,
    AP_WPA3,
    PMKID,
    SSID_WPA2,
    STA_ONE,
    STA_TWO,
    write_capture,
)


@pytest.fixture(scope="module")
def capture(tmp_path_factory):
    path = tmp_path_factory.mktemp("captures") / "lab.pcap"
    write_capture(str(path))
    return load_capture(str(path))


@pytest.fixture(scope="module")
def analysis(capture):
    tracker = track_handshakes(capture)
    return tracker, run_all_detectors(capture, tracker.all())


def test_capture_parses_without_errors(capture):
    assert capture.parse_errors == []
    assert len(capture.frames) > 100
    assert capture.duration > 1.0


def test_all_three_frame_classes_are_present(capture):
    """The core requirement: management, control and data are told apart."""
    classes = {frame.type_name for frame in capture.frames}
    assert {"management", "control", "data"} <= classes


def test_frame_counts_match_the_generated_scenario(capture):
    by_type = {}
    for frame in capture.frames:
        by_type[frame.type_name] = by_type.get(frame.type_name, 0) + 1
    assert by_type["management"] == 66
    assert by_type["control"] == 41
    assert by_type["data"] == 32
    assert sum(by_type.values()) == 139


def test_expected_subtypes_are_recognised(capture):
    subtypes = {frame.subtype_name for frame in capture.frames}
    assert {"beacon", "probe-request", "probe-response", "authentication",
            "assoc-request", "assoc-response", "deauthentication"} <= subtypes
    assert {"ack", "rts", "cts", "block-ack"} <= subtypes
    assert {"data", "qos-data"} <= subtypes


def test_four_networks_are_discovered(capture):
    assert set(capture.networks) == {AP_WPA2, AP_WPA3, AP_LEGACY, AP_EVIL_TWIN}


def test_security_generations_are_identified(capture):
    assert capture.networks[AP_WPA2].security == "WPA2-Personal (PSK)"
    assert capture.networks[AP_WPA3].security == "WPA3-Personal (SAE)"
    assert capture.networks[AP_EVIL_TWIN].security == "Open (no RSN element)"
    assert "TKIP" in capture.networks[AP_LEGACY].rsn.pairwise_ciphers


def test_mfp_state_is_read_per_network(capture):
    assert capture.networks[AP_WPA3].rsn.mfp_required
    assert not capture.networks[AP_WPA2].rsn.mfp_capable


def test_channels_come_from_the_ds_parameter_element(capture):
    assert capture.networks[AP_WPA2].channel == 6
    assert capture.networks[AP_WPA3].channel == 36
    assert capture.networks[AP_LEGACY].channel == 11


def test_stations_are_attributed_to_their_network(capture):
    assert STA_ONE in capture.networks[AP_WPA2].clients
    assert STA_TWO in capture.networks[AP_WPA3].clients


def test_radiotap_metadata_is_read(capture):
    beacons = [f for f in capture.frames if f.subtype_name == "beacon"]
    assert all(f.signal_dbm is not None for f in beacons)
    assert all(-90 < f.signal_dbm < 0 for f in beacons)


def test_sae_authentication_is_distinguished_from_open_system(capture):
    """WPA3 authenticates with Dragonfly; WPA2-PSK's Open System does nothing."""
    algorithms = {
        f.extra.get("auth_algorithm")
        for f in capture.frames
        if f.subtype_name == "authentication"
    }
    assert algorithms == {"open-system", "SAE"}


def test_protected_bit_is_read_on_data_frames(capture):
    data_frames = [f for f in capture.frames if f.is_data]
    assert any(f.protected for f in data_frames)
    # The EAPOL handshake frames precede key installation, so they are not
    # protected. If every data frame looked protected, the bit is being faked.
    assert any(not f.protected for f in data_frames)


def test_both_four_way_handshakes_are_reconstructed(analysis):
    tracker, _ = analysis
    handshakes = tracker.all()
    assert len(handshakes) == 2
    for handshake in handshakes:
        assert handshake.complete
        assert handshake.observed == [1, 2, 3, 4]
        assert handshake.ap == AP_WPA2
        assert handshake.station == STA_ONE
        assert handshake.anonce and handshake.snonce


def test_pmkid_is_recovered_from_the_first_handshake(analysis):
    tracker, _ = analysis
    assert tracker.all()[0].pmkid == PMKID
    assert tracker.all()[1].pmkid is None


def test_deauth_flood_is_detected(analysis):
    _, findings = analysis
    floods = [f for f in findings if "flood" in f.title.lower()]
    assert floods, "the deauthentication flood was not detected"
    assert all(f.severity == "high" for f in floods)
    assert any("forgeable" in " ".join(f.evidence) for f in floods)


def test_evil_twin_is_detected(analysis):
    _, findings = analysis
    twins = [f for f in findings if "evil twin" in f.title.lower()]
    assert len(twins) == 1
    assert SSID_WPA2 in twins[0].detail
    assert AP_EVIL_TWIN in " ".join(twins[0].evidence)


def test_missing_mfp_is_reported(analysis):
    _, findings = analysis
    assert any("MFP" in f.title or "MFP" in f.detail for f in findings)


def test_wpa3_network_raises_no_configuration_findings(analysis):
    """The control: a correctly configured network must stay quiet.

    A detector that flags everything is useless, so the WPA3 AP -- SAE,
    CCMP, MFP required -- must produce no weak-configuration finding.
    """
    _, findings = analysis
    configuration_findings = [
        f for f in findings if f.title.startswith("Weak configuration")
    ]
    assert configuration_findings
    assert all(AP_WPA3 not in f.detail for f in configuration_findings)


def test_every_finding_is_actionable(analysis):
    _, findings = analysis
    for finding in findings:
        assert finding.severity in {"high", "medium", "low", "info"}
        assert finding.detail and finding.title
        assert finding.render()


def test_findings_are_sorted_by_severity(analysis):
    from wifi.anomalies import SEVERITY_ORDER

    _, findings = analysis
    ranks = [SEVERITY_ORDER[f.severity] for f in findings]
    assert ranks == sorted(ranks)


def test_json_report_is_serialisable_and_complete(capture, analysis):
    tracker, findings = analysis
    report = json.loads(json.dumps(build_json(capture, tracker, findings)))
    assert report["capture"]["frames"] == 139
    assert set(report["frame_classes"]) == {"management", "control", "data"}
    assert len(report["networks"]) == 4
    assert len(report["handshakes"]) == 2
    assert report["handshakes"][0]["pmkid"] == PMKID.hex()
    assert report["findings"]
