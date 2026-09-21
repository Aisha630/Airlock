"""Parser for the RSN and legacy WPA information elements.

An access point advertises what it will accept in the RSN element (id 48) of
its beacons and probe responses, in the clear. Reading it tells you the
generation of the network (WPA2 / WPA3 / transition mode), the ciphers, and
crucially whether management frames are protected -- which decides whether
the deauthentication attack in `anomalies.py` would work against it.

Parsed by hand from the byte layout in IEEE 802.11-2020 Section 9.4.2.24
rather than via a library helper, because the field this analyzer most cares
about -- the two MFP bits in RSN Capabilities -- is exactly the sort of
detail that a convenience wrapper hides.
"""

import struct
from dataclasses import dataclass, field

RSN_ELEMENT_ID = 48
VENDOR_ELEMENT_ID = 221

# The OUI that prefixes every standard cipher and AKM suite selector.
OUI_IEEE = b"\x00\x0f\xac"
# Legacy WPA1 used Microsoft's OUI with type 1 in a vendor-specific element.
OUI_MICROSOFT = b"\x00\x50\xf2"

CIPHER_SUITES = {
    0: "use-group-cipher",
    1: "WEP-40",
    2: "TKIP",
    4: "CCMP-128",
    5: "WEP-104",
    6: "BIP-CMAC-128",
    8: "GCMP-128",
    9: "GCMP-256",
    10: "CCMP-256",
    11: "BIP-GMAC-128",
    12: "BIP-GMAC-256",
    13: "BIP-CMAC-256",
}

AKM_SUITES = {
    1: "802.1X",
    2: "PSK",
    3: "FT-802.1X",
    4: "FT-PSK",
    5: "802.1X-SHA256",
    6: "PSK-SHA256",
    8: "SAE",
    9: "FT-SAE",
    11: "802.1X-SUITE-B",
    12: "802.1X-SUITE-B-192",
    18: "OWE",
    24: "PSK-SHA384",
}

# Ciphers no network should still be offering. Presence is a finding.
BROKEN_CIPHERS = {"WEP-40", "WEP-104", "TKIP"}

# AKMs that establish the PMK with a password-authenticated key exchange
# (SAE, the Dragonfly handshake) rather than by hashing the passphrase.
SAE_AKMS = {"SAE", "FT-SAE"}


class RSNParseError(Exception):
    """Raised when an element is truncated or internally inconsistent."""


def _suite_name(suite: bytes, table: dict[int, str]) -> str:
    """Decode a 4-byte suite selector: 3-byte OUI plus a 1-byte type."""
    if len(suite) != 4:
        raise RSNParseError("suite selector must be 4 bytes")
    oui, suite_type = suite[:3], suite[3]
    if oui == OUI_IEEE:
        return table.get(suite_type, f"unknown-{suite_type}")
    if oui == OUI_MICROSOFT:
        return table.get(suite_type, f"wpa1-unknown-{suite_type}")
    return f"vendor-{oui.hex()}-{suite_type}"


@dataclass
class RSNInfo:
    """Security capabilities advertised by an access point."""

    version: int = 1
    group_cipher: str = "unknown"
    pairwise_ciphers: list[str] = field(default_factory=list)
    akm_suites: list[str] = field(default_factory=list)
    mfp_capable: bool = False
    mfp_required: bool = False
    pmkids: int = 0
    group_mgmt_cipher: str | None = None
    raw_capabilities: int = 0
    is_wpa1: bool = False

    @property
    def generation(self) -> str:
        """Name the security generation from the AKM list.

        Transition mode -- SAE and PSK offered together -- is called out
        separately because it is a real downgrade exposure: a client that
        supports both can be pushed onto the PSK path, where the passphrase
        is open to the offline dictionary attack that SAE was designed to
        remove.
        """
        akms = set(self.akm_suites)
        has_sae = bool(akms & SAE_AKMS)
        has_psk = bool(akms & {"PSK", "FT-PSK", "PSK-SHA256", "PSK-SHA384"})
        has_enterprise = bool(
            akms & {"802.1X", "FT-802.1X", "802.1X-SHA256",
                    "802.1X-SUITE-B", "802.1X-SUITE-B-192"}
        )
        if "OWE" in akms:
            return "OWE (opportunistic wireless encryption)"
        if has_sae and has_psk:
            return "WPA3/WPA2 transition mode"
        if has_sae:
            return "WPA3-Personal (SAE)"
        if has_enterprise:
            return "WPA2/WPA3-Enterprise (802.1X)"
        if has_psk:
            return "WPA1-Personal (PSK)" if self.is_wpa1 else "WPA2-Personal (PSK)"
        return "unknown"

    @property
    def mfp_state(self) -> str:
        """Summarise the two MFP bits into one readable state."""
        if self.mfp_required:
            return "required"
        if self.mfp_capable:
            return "capable but optional"
        return "not supported"

    def weaknesses(self) -> list[str]:
        """Findings a reviewer should act on, worst first."""
        issues = []
        offered = set(self.pairwise_ciphers) | {self.group_cipher}
        for cipher in sorted(offered & BROKEN_CIPHERS):
            issues.append(
                f"{cipher} is offered; it is cryptographically broken and its "
                f"presence in the group cipher weakens every client"
                if cipher == self.group_cipher
                else f"{cipher} is offered as a pairwise cipher and is broken"
            )
        if not self.mfp_capable:
            issues.append(
                "management frame protection is not supported, so "
                "deauthentication and disassociation frames are forgeable"
            )
        elif not self.mfp_required:
            issues.append(
                "management frame protection is optional, so a client that "
                "does not negotiate it stays exposed to forged deauths"
            )
        if self.generation == "WPA3/WPA2 transition mode":
            issues.append(
                "transition mode allows a downgrade from SAE to PSK, which "
                "re-exposes the passphrase to offline dictionary attack"
            )
        if self.is_wpa1:
            issues.append("legacy WPA1 element present; WPA1 is deprecated")
        return issues


def parse_rsn_element(data: bytes) -> RSNInfo:
    """Parse the body of an RSN element (element id 48).

    Every field after the version is optional and the element simply ends
    where the AP stopped writing, so each read is guarded by a length check.
    A truncated element is a parse error, not a silent default: quietly
    treating a cut-off element as "no MFP" would invent a finding.
    """
    if len(data) < 2:
        raise RSNParseError("RSN element too short for a version field")
    info = RSNInfo()
    (info.version,) = struct.unpack("<H", data[:2])
    offset = 2

    if len(data) >= offset + 4:
        info.group_cipher = _suite_name(data[offset : offset + 4], CIPHER_SUITES)
        offset += 4

    if len(data) >= offset + 2:
        (count,) = struct.unpack("<H", data[offset : offset + 2])
        offset += 2
        for _ in range(count):
            if len(data) < offset + 4:
                raise RSNParseError("pairwise cipher list truncated")
            info.pairwise_ciphers.append(
                _suite_name(data[offset : offset + 4], CIPHER_SUITES)
            )
            offset += 4

    if len(data) >= offset + 2:
        (count,) = struct.unpack("<H", data[offset : offset + 2])
        offset += 2
        for _ in range(count):
            if len(data) < offset + 4:
                raise RSNParseError("AKM suite list truncated")
            info.akm_suites.append(_suite_name(data[offset : offset + 4], AKM_SUITES))
            offset += 4

    if len(data) >= offset + 2:
        (capabilities,) = struct.unpack("<H", data[offset : offset + 2])
        offset += 2
        info.raw_capabilities = capabilities
        # IEEE 802.11-2020 Figure 9-257: bit 6 MFPR, bit 7 MFPC.
        info.mfp_required = bool(capabilities & (1 << 6))
        info.mfp_capable = bool(capabilities & (1 << 7))

    if len(data) >= offset + 2:
        (pmkid_count,) = struct.unpack("<H", data[offset : offset + 2])
        offset += 2
        info.pmkids = pmkid_count
        offset += 16 * pmkid_count

    # The group management cipher only appears when MFP is in use.
    if len(data) >= offset + 4:
        info.group_mgmt_cipher = _suite_name(
            data[offset : offset + 4], CIPHER_SUITES
        )

    return info


def parse_wpa1_element(data: bytes) -> RSNInfo | None:
    """Parse a vendor-specific element, returning info only for legacy WPA1.

    WPA1 predates the RSN element, so it was carried in a vendor element with
    Microsoft's OUI and type 1. The body layout matches RSN but with a
    different OUI on the suite selectors and no capabilities field.
    """
    if len(data) < 6 or data[:3] != OUI_MICROSOFT or data[3] != 1:
        return None
    info = RSNInfo(is_wpa1=True)
    (info.version,) = struct.unpack("<H", data[4:6])
    offset = 6

    if len(data) >= offset + 4:
        info.group_cipher = _suite_name(data[offset : offset + 4], CIPHER_SUITES)
        offset += 4
    if len(data) >= offset + 2:
        (count,) = struct.unpack("<H", data[offset : offset + 2])
        offset += 2
        for _ in range(count):
            if len(data) < offset + 4:
                break
            info.pairwise_ciphers.append(
                _suite_name(data[offset : offset + 4], CIPHER_SUITES)
            )
            offset += 4
    if len(data) >= offset + 2:
        (count,) = struct.unpack("<H", data[offset : offset + 2])
        offset += 2
        for _ in range(count):
            if len(data) < offset + 4:
                break
            info.akm_suites.append(_suite_name(data[offset : offset + 4], AKM_SUITES))
            offset += 4
    return info


def build_rsn_element(
    group_cipher: int = 4,
    pairwise_ciphers: tuple[int, ...] = (4,),
    akm_suites: tuple[int, ...] = (2,),
    mfp_capable: bool = False,
    mfp_required: bool = False,
    group_mgmt_cipher: int | None = None,
) -> bytes:
    """Build an RSN element body. Used by `synth.py` to generate beacons.

    Having the encoder next to the decoder keeps the two honest: the round
    trip is asserted in `tests/test_rsn.py`.
    """
    body = struct.pack("<H", 1)
    body += OUI_IEEE + bytes([group_cipher])
    body += struct.pack("<H", len(pairwise_ciphers))
    for cipher in pairwise_ciphers:
        body += OUI_IEEE + bytes([cipher])
    body += struct.pack("<H", len(akm_suites))
    for akm in akm_suites:
        body += OUI_IEEE + bytes([akm])
    capabilities = 0
    if mfp_required:
        capabilities |= 1 << 6
    if mfp_capable:
        capabilities |= 1 << 7
    body += struct.pack("<H", capabilities)
    if group_mgmt_cipher is not None:
        body += struct.pack("<H", 0)  # PMKID count
        body += OUI_IEEE + bytes([group_mgmt_cipher])
    return body
