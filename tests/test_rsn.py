"""RSN element parsing: generations, ciphers, MFP bits, and malformed input."""

import pytest

from wifi.rsn import (
    RSNParseError,
    build_rsn_element,
    parse_rsn_element,
    parse_wpa1_element,
)


def test_wpa2_psk():
    info = parse_rsn_element(build_rsn_element(akm_suites=(2,)))
    assert info.generation == "WPA2-Personal (PSK)"
    assert info.group_cipher == "CCMP-128"
    assert info.pairwise_ciphers == ["CCMP-128"]
    assert info.akm_suites == ["PSK"]
    assert info.mfp_state == "not supported"


def test_wpa3_sae_with_mfp_required():
    info = parse_rsn_element(
        build_rsn_element(
            akm_suites=(8,), mfp_capable=True, mfp_required=True, group_mgmt_cipher=6
        )
    )
    assert info.generation == "WPA3-Personal (SAE)"
    assert info.mfp_required and info.mfp_capable
    assert info.mfp_state == "required"
    assert info.group_mgmt_cipher == "BIP-CMAC-128"
    # A correctly configured WPA3 network should raise no findings at all.
    assert info.weaknesses() == []


def test_transition_mode_is_flagged_as_a_downgrade_path():
    info = parse_rsn_element(build_rsn_element(akm_suites=(8, 2), mfp_capable=True))
    assert info.generation == "WPA3/WPA2 transition mode"
    assert any("downgrade" in w for w in info.weaknesses())


def test_enterprise_is_recognised():
    info = parse_rsn_element(build_rsn_element(akm_suites=(1,)))
    assert "802.1X" in info.generation


def test_owe_is_recognised():
    info = parse_rsn_element(build_rsn_element(akm_suites=(18,), mfp_capable=True))
    assert info.generation.startswith("OWE")


def test_tkip_is_reported_as_broken():
    info = parse_rsn_element(
        build_rsn_element(group_cipher=2, pairwise_ciphers=(2, 4))
    )
    assert "TKIP" in info.pairwise_ciphers
    assert any("TKIP" in w and "broken" in w for w in info.weaknesses())


@pytest.mark.parametrize(
    "capabilities,capable,required",
    [(0x0000, False, False), (0x0080, True, False),
     (0x00C0, True, True), (0x0040, False, True)],
)
def test_mfp_bits_are_read_from_the_right_positions(capabilities, capable, required):
    """MFPR is bit 6 and MFPC is bit 7; swapping them inverts the finding."""
    body = build_rsn_element(
        mfp_capable=bool(capabilities & 0x0080),
        mfp_required=bool(capabilities & 0x0040),
    )
    info = parse_rsn_element(body)
    assert info.raw_capabilities == capabilities
    assert info.mfp_capable is capable
    assert info.mfp_required is required


def test_missing_mfp_is_a_finding():
    info = parse_rsn_element(build_rsn_element(akm_suites=(2,)))
    assert any("management frame protection" in w for w in info.weaknesses())


def test_optional_mfp_is_still_a_finding():
    info = parse_rsn_element(build_rsn_element(akm_suites=(2,), mfp_capable=True))
    assert any("optional" in w for w in info.weaknesses())


def test_build_and_parse_round_trip():
    """The encoder and decoder are checked against each other."""
    body = build_rsn_element(
        group_cipher=9, pairwise_ciphers=(9, 4), akm_suites=(8, 2),
        mfp_capable=True, mfp_required=True, group_mgmt_cipher=12,
    )
    info = parse_rsn_element(body)
    assert info.group_cipher == "GCMP-256"
    assert info.pairwise_ciphers == ["GCMP-256", "CCMP-128"]
    assert info.akm_suites == ["SAE", "PSK"]
    assert info.group_mgmt_cipher == "BIP-GMAC-256"


def test_truncated_element_raises_rather_than_inventing_defaults():
    """Silently defaulting a cut-off element would fabricate a finding."""
    with pytest.raises(RSNParseError):
        parse_rsn_element(b"\x01")
    body = build_rsn_element(pairwise_ciphers=(4, 4))
    with pytest.raises(RSNParseError):
        parse_rsn_element(body[:10])  # promises two ciphers, supplies part of one


def test_partial_element_stops_cleanly_at_a_field_boundary():
    """An element that simply ends early is legal: later fields are optional."""
    body = build_rsn_element(akm_suites=(2,))
    info = parse_rsn_element(body[:6])
    assert info.group_cipher == "CCMP-128"
    assert info.pairwise_ciphers == []
    assert info.mfp_capable is False


def test_unknown_suite_types_are_reported_not_dropped():
    body = build_rsn_element(akm_suites=(99,))
    info = parse_rsn_element(body)
    assert info.akm_suites == ["unknown-99"]
    assert info.generation == "unknown"


def test_wpa1_vendor_element():
    # Microsoft OUI, type 1, version 1, TKIP group and pairwise, PSK AKM.
    body = (b"\x00\x50\xf2\x01" + b"\x01\x00"
            + b"\x00\x50\xf2\x02"
            + b"\x01\x00" + b"\x00\x50\xf2\x02"
            + b"\x01\x00" + b"\x00\x50\xf2\x02")
    info = parse_wpa1_element(body)
    assert info is not None
    assert info.is_wpa1
    assert info.generation == "WPA1-Personal (PSK)"
    assert any("WPA1" in w for w in info.weaknesses())


def test_non_wpa_vendor_element_is_ignored():
    """Most vendor elements are not WPA1 and must not be misread as security."""
    assert parse_wpa1_element(b"\x00\x50\xf2\x02\x01\x01") is None  # WMM
    assert parse_wpa1_element(b"\x00\x11\x22\x01\x01\x00") is None
    assert parse_wpa1_element(b"\x00") is None
