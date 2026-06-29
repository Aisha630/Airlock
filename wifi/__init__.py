"""802.11 capture analysis for Airlock.

Parses frame metadata from a pcap, classifies management / control / data
frames, reads the security capabilities advertised in beacons, tracks WPA2
four-way handshakes, and flags anomalies. Header metadata only -- no attempt
is made to decrypt payloads.
"""

__version__ = "1.0.0"
