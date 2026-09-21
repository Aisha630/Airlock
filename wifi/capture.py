"""Read a pcap of 802.11 frames into `FrameInfo` records.

Scapy is used for the link-layer dissection only -- pulling the Frame
Control bits, the address fields and the information elements out of the
bytes. Everything this analyzer reasons about (classification, RSN
capabilities, handshake state, anomalies) is implemented in this package.
"""

import warnings
from dataclasses import dataclass, field

# Scapy imports its TLS layer at startup, which pulls in a deprecated
# finite-field DH helper from `cryptography` and prints a warning that has
# nothing to do with this tool. Silenced at the import, not globally.
warnings.filterwarnings(
    "ignore", message=".*Diffie-Hellman.*", module="scapy.*"
)
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from scapy.all import PcapReader  # type: ignore[import-untyped]
from scapy.layers.dot11 import (  # type: ignore[import-untyped]
    Dot11,
    Dot11AssoReq,
    Dot11AssoResp,
    Dot11Auth,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Disas,
    Dot11Elt,
    Dot11ProbeReq,
    Dot11ProbeResp,
    Dot11ReassoReq,
    RadioTap,
)
from scapy.layers.eap import EAPOL  # type: ignore[import-untyped]

from .eapol import EapolKeyFrame, EapolParseError, parse_eapol_key
from .frames import TYPE_NAMES, FrameInfo, subtype_name
from .rsn import RSNInfo, RSNParseError, parse_rsn_element, parse_wpa1_element

ELEMENT_SSID = 0
ELEMENT_DS_PARAMETER = 3
ELEMENT_RSN = 48
ELEMENT_VENDOR = 221


@dataclass
class Network:
    """An access point seen in the capture, and what it advertises."""

    bssid: str
    ssid: str | None = None
    channel: int | None = None
    rsn: RSNInfo | None = None
    beacon_count: int = 0
    probe_response_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    clients: set[str] = field(default_factory=set)

    @property
    def security(self) -> str:
        if self.rsn is None:
            return "Open (no RSN element)"
        return self.rsn.generation


@dataclass
class Capture:
    """Everything parsed out of one pcap file."""

    path: str
    frames: list[FrameInfo] = field(default_factory=list)
    networks: dict[str, Network] = field(default_factory=dict)
    eapol_frames: list[tuple[FrameInfo, EapolKeyFrame]] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    suspect_frames: int = 0

    @property
    def duration(self) -> float:
        if len(self.frames) < 2:
            return 0.0
        return self.frames[-1].timestamp - self.frames[0].timestamp


def _mac(value) -> str | None:
    """Normalise a scapy address field to lowercase hex, or None."""
    if value is None:
        return None
    return str(value).lower()


def _decode_ssid(raw: bytes) -> str:
    """Decode an SSID, which is arbitrary bytes and not necessarily UTF-8.

    A zero-length SSID means a wildcard probe request or a hidden network;
    both are reported explicitly rather than as an empty string, so the
    report never looks like a parse failure.
    """
    if not raw:
        return "<wildcard/hidden>"
    return raw.decode("utf-8", errors="replace")


def _walk_elements(packet):
    """Yield (element_id, body) for every information element in a frame.

    Defensive by necessity. Information elements come off the air from
    devices this tool does not control, and real captures contain plenty
    that are truncated mid-element, carry a length byte that overruns the
    frame, or were clipped by the capturing adapter's snap length. Scapy
    represents those as a `Dot11Elt` with no `info` field at all, and simply
    reading the attribute raises.

    A frame parser that crashes on malformed input is a denial of service on
    itself: one bad beacon from any device in range would otherwise abort the
    analysis of an entire capture. So a broken element ends the walk for that
    frame and leaves the elements already parsed intact.
    """
    element = packet.getlayer(Dot11Elt)
    while element is not None:
        try:
            element_id = int(element.ID)
            info = element.info
        except (ValueError, AttributeError, TypeError):
            return
        yield element_id, bytes(info) if info else b""
        try:
            element = element.payload.getlayer(Dot11Elt)
        except (ValueError, AttributeError, TypeError):
            return


def _radiotap_metadata(packet) -> tuple[int | None, int | None]:
    """Pull signal strength and channel from the radiotap header, if present.

    Radiotap is added by the capturing adapter, not by 802.11, so these
    fields are best-effort: some drivers omit them entirely.
    """
    signal = None
    channel = None
    if not packet.haslayer(RadioTap):
        return signal, channel
    radiotap = packet.getlayer(RadioTap)
    value = getattr(radiotap, "dBm_AntSignal", None)
    if value is not None:
        signal = int(value)
    frequency = getattr(radiotap, "ChannelFrequency", None)
    if frequency:
        channel = _frequency_to_channel(int(frequency))
    return signal, channel


def _frequency_to_channel(mhz: int) -> int | None:
    """Convert a centre frequency to a channel number (2.4 and 5 GHz)."""
    if mhz == 2484:
        return 14
    if 2412 <= mhz <= 2472:
        return (mhz - 2412) // 5 + 1
    if 5000 <= mhz <= 5900:
        return (mhz - 5000) // 5
    return None


def _extract_security(packet, network: Network, errors: list[str]) -> None:
    """Read RSN / WPA1 elements from a beacon or probe response."""
    for element_id, body in _walk_elements(packet):
        if element_id == ELEMENT_RSN:
            try:
                network.rsn = parse_rsn_element(body)
            except RSNParseError as exc:
                errors.append(f"{network.bssid}: bad RSN element: {exc}")
        elif element_id == ELEMENT_VENDOR and network.rsn is None:
            # Only fall back to WPA1 when there is no RSN element; an AP
            # running both advertises RSN, and that is the one in force.
            try:
                wpa1 = parse_wpa1_element(body)
            except RSNParseError as exc:
                errors.append(f"{network.bssid}: bad WPA element: {exc}")
                continue
            if wpa1 is not None:
                network.rsn = wpa1


def load_capture(path: str) -> Capture:
    """Parse a pcap file into frames, networks, and EAPOL exchanges.

    Frames are streamed rather than read into memory at once: a few minutes
    of monitor-mode capture on a busy channel runs to tens of megabytes, and
    there is no reason to hold all of it.

    Each frame is parsed inside its own error boundary. One unparseable
    frame is recorded in `parse_errors` and the run continues; anything else
    would let a single malformed transmission from any device in range
    destroy the analysis of the whole capture.
    """
    capture = Capture(path=path)

    with PcapReader(path) as reader:
        for index, packet in enumerate(reader):
            try:
                _load_frame(packet, index, capture)
            except Exception as exc:  # noqa: BLE001 -- boundary is the point
                capture.parse_errors.append(
                    f"frame {index}: {type(exc).__name__}: {exc}"
                )

    _attribute_clients(capture)
    return capture


def _load_frame(packet, index: int, capture: Capture) -> None:
    """Parse one frame into the capture. Raises on anything unexpected."""
    if not packet.haslayer(Dot11):
        return
    dot11 = packet.getlayer(Dot11)
    frame_type = int(dot11.type)
    subtype = int(dot11.subtype)
    signal, channel = _radiotap_metadata(packet)

    info = FrameInfo(
        index=index,
        timestamp=float(packet.time),
        frame_type=frame_type,
        subtype=subtype,
        type_name=TYPE_NAMES.get(frame_type, f"type-{frame_type}"),
        subtype_name=subtype_name(frame_type, subtype),
        addr1=_mac(getattr(dot11, "addr1", None)),
        addr2=_mac(getattr(dot11, "addr2", None)),
        addr3=_mac(getattr(dot11, "addr3", None)),
        to_ds=bool(dot11.FCfield & 0x01),
        from_ds=bool(dot11.FCfield & 0x02),
        retry=bool(dot11.FCfield & 0x08),
        protected=bool(dot11.FCfield & 0x40),
        length=len(packet),
        signal_dbm=signal,
        channel=channel,
    )

    # For infrastructure traffic addr3 is the BSSID, except when both DS
    # bits are set (a mesh/WDS frame), where there is no single BSSID.
    if info.to_ds and not info.from_ds:
        info.bssid = info.addr1
    elif info.from_ds and not info.to_ds:
        info.bssid = info.addr2
    elif not info.to_ds and not info.from_ds:
        info.bssid = info.addr3

    # A frame with an impossible transmitter address was corrupted in the
    # air or by the adapter. It is still counted in the frame totals -- it
    # was genuinely received -- but it must not be allowed to invent a
    # network, because a garbled beacon otherwise appears as a brand new
    # access point with a garbage SSID and gets reported as a finding.
    info.suspect = not info.transmitter_is_valid
    if info.suspect:
        capture.suspect_frames += 1
    else:
        _classify_management(packet, info, capture)
        _classify_eapol(packet, info, capture)

    capture.frames.append(info)


def _classify_management(packet, info: FrameInfo, capture: Capture) -> None:
    """Pull SSID, security info and reason/status codes from mgmt frames."""
    if not info.is_management:
        return

    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        bssid = info.addr3 or info.addr2
        if bssid is None:
            return
        network = capture.networks.setdefault(bssid, Network(bssid=bssid))
        if network.beacon_count == 0 and network.probe_response_count == 0:
            network.first_seen = info.timestamp
        network.last_seen = info.timestamp
        if packet.haslayer(Dot11Beacon):
            network.beacon_count += 1
        else:
            network.probe_response_count += 1

        for element_id, body in _walk_elements(packet):
            if element_id == ELEMENT_SSID:
                network.ssid = _decode_ssid(body)
                info.ssid = network.ssid
            elif element_id == ELEMENT_DS_PARAMETER and body:
                network.channel = body[0]
                if info.channel is None:
                    info.channel = body[0]
        _extract_security(packet, network, capture.parse_errors)

    elif packet.haslayer(Dot11ProbeReq) or packet.haslayer(Dot11AssoReq) or packet.haslayer(Dot11ReassoReq):
        for element_id, body in _walk_elements(packet):
            if element_id == ELEMENT_SSID:
                info.ssid = _decode_ssid(body)
                break

    if packet.haslayer(Dot11Deauth):
        info.reason_code = int(packet.getlayer(Dot11Deauth).reason)
    elif packet.haslayer(Dot11Disas):
        info.reason_code = int(packet.getlayer(Dot11Disas).reason)

    if packet.haslayer(Dot11Auth):
        auth = packet.getlayer(Dot11Auth)
        info.status_code = int(auth.status)
        # Algorithm 3 is SAE: a WPA3 network authenticating with Dragonfly.
        algorithm = int(auth.algo)
        info.extra["auth_algorithm"] = {
            0: "open-system",
            1: "shared-key",
            2: "fast-bss-transition",
            3: "SAE",
        }.get(algorithm, f"algorithm-{algorithm}")
        info.extra["auth_seq"] = int(auth.seqnum)
    elif packet.haslayer(Dot11AssoResp):
        info.status_code = int(packet.getlayer(Dot11AssoResp).status)


def _classify_eapol(packet, info: FrameInfo, capture: Capture) -> None:
    """Parse any EAPOL-Key frame carried in a data frame."""
    if not packet.haslayer(EAPOL):
        return
    payload = bytes(packet.getlayer(EAPOL))
    try:
        key_frame = parse_eapol_key(payload)
    except EapolParseError as exc:
        capture.parse_errors.append(f"frame {info.index}: {exc}")
        return
    info.extra["eapol_message"] = key_frame.message_number()
    capture.eapol_frames.append((info, key_frame))


def _attribute_clients(capture: Capture) -> None:
    """Associate stations with the BSSID they are talking through."""
    for info in capture.frames:
        if info.bssid not in capture.networks:
            continue
        network = capture.networks[info.bssid]
        for address in (info.addr1, info.addr2):
            if address and address != network.bssid and not address.startswith("ff:"):
                network.clients.add(address)
