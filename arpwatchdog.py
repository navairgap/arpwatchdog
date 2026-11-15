#!/usr/bin/env python3
"""Offline parser and change tracker for passive Ethernet/IPv4 ARP observations.

Input frames are supplied by the operator; this program never sends ARP probes.
"""
from __future__ import annotations

import datetime as _dt
import json
import math
import sys
from collections import OrderedDict
from dataclasses import dataclass

SCHEMA_VERSION = 1


def canonical_mac(mac: str) -> str:
    """Normalize a MAC address to six lowercase colon-separated octets."""
    if not isinstance(mac, str):
        raise ValueError("MAC address must be a string")
    cleaned = mac.strip().lower().replace("-", ":")
    if len(cleaned) != 17 or cleaned.count(":") != 5:
        raise ValueError(f"invalid MAC address: {mac!r}")
    octets = cleaned.split(":")
    for octet in octets:
        if len(octet) != 2 or any(c not in "0123456789abcdef" for c in octet):
            raise ValueError(f"invalid MAC address: {mac!r}")
    return cleaned


def canonical_ip(ip: str) -> str:
    """Validate and return a canonical dotted-quad IPv4 address string."""
    if not isinstance(ip, str):
        raise ValueError("IPv4 address must be a string")
    parts = ip.strip().split(".")
    if len(parts) != 4:
        raise ValueError(f"invalid IPv4 address: {ip!r}")
    for part in parts:
        if not part.isdigit() or (len(part) > 1 and part[0] == "0"):
            raise ValueError(f"invalid IPv4 address: {ip!r}")
        if not 0 <= int(part) <= 255:
            raise ValueError(f"invalid IPv4 address: {ip!r}")
    return ".".join(parts)


def rfc3339(timestamp: float) -> str:
    """Render a Unix epoch timestamp as a UTC RFC 3339 string."""
    if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
        raise ValueError("timestamp must be numeric")
    if not math.isfinite(timestamp) or timestamp < 0:
        raise ValueError("timestamp must be finite and not negative")
    moment = _dt.datetime.fromtimestamp(timestamp, tz=_dt.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S") + f".{moment.microsecond // 1000:03d}Z"


def make_event(kind: str, **fields: object) -> dict[str, object]:
    """Build a schema v1 event envelope with the required fixed fields."""
    if not kind or not isinstance(kind, str):
        raise ValueError("event kind must be a non-empty string")
    event: dict[str, object] = {"schema_version": SCHEMA_VERSION, "event": kind}
    event.update(fields)
    return event


@dataclass(frozen=True)
class Observation:
    interface: str
    timestamp: float
    ip: str
    mac: str


def parse_frame(frame: bytes, interface: str, timestamp: float) -> Observation | None:
    """Parse one Ethernet ARP frame, including up to two VLAN tags."""
    if not isinstance(frame, bytes) or len(frame) < 14:
        raise ValueError("frame is shorter than an Ethernet header")
    if not isinstance(interface, str) or not interface or len(interface) > 15:
        raise ValueError("interface must contain 1 to 15 characters")
    if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
        raise ValueError("timestamp must be numeric")
    if not math.isfinite(timestamp) or timestamp < 0:
        raise ValueError("timestamp must be finite and not negative")

    offset = 14
    ethertype = int.from_bytes(frame[12:14], "big")
    vlan_count = 0
    while ethertype in (0x8100, 0x88A8):
        vlan_count += 1
        if vlan_count > 2:
            raise ValueError("more than two nested VLAN tags are unsupported")
        if len(frame) < offset + 4:
            raise ValueError("truncated VLAN header")
        ethertype = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
    if ethertype != 0x0806:
        return None

    if len(frame) < offset + 28:
        raise ValueError("truncated Ethernet/IPv4 ARP payload")
    arp = frame[offset:]
    hardware = int.from_bytes(arp[0:2], "big")
    protocol = int.from_bytes(arp[2:4], "big")
    hardware_len, protocol_len = arp[4], arp[5]
    operation = int.from_bytes(arp[6:8], "big")
    if (hardware, protocol, hardware_len, protocol_len) != (1, 0x0800, 6, 4):
        return None
    if operation not in (1, 2):
        return None

    sender_mac = ":".join(f"{byte:02x}" for byte in arp[8:14])
    sender_ip = ".".join(str(byte) for byte in arp[14:18])
    # RFC 5227 address probes use 0.0.0.0 and do not claim ownership.
    if sender_ip == "0.0.0.0":
        return None
    return Observation(interface, float(timestamp), sender_ip, sender_mac)


class Tracker:
    """Bounded IP-to-MAC history; changes are observations, not attack verdicts."""

    def __init__(self, max_entries: int = 4096) -> None:
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError("max_entries must be a positive integer")
        self.max_entries = max_entries
        self._seen: OrderedDict[str, Observation] = OrderedDict()

    def observe(self, item: Observation) -> dict[str, object] | None:
        item = Observation(
            item.interface, item.timestamp, canonical_ip(item.ip), canonical_mac(item.mac)
        )
        previous = self._seen.get(item.ip)
        self._seen[item.ip] = item
        self._seen.move_to_end(item.ip)
        while len(self._seen) > self.max_entries:
            self._seen.popitem(last=False)
        if previous is None:
            return None
        if previous.mac == item.mac:
            return None
        return make_event(
            "mapping_changed",
            ip=item.ip,
            previous_mac=previous.mac,
            current_mac=item.mac,
            previous_interface=previous.interface,
            interface=item.interface,
            first_seen=rfc3339(previous.timestamp),
            first_seen_epoch=previous.timestamp,
            observed_at=rfc3339(item.timestamp),
            observed_at_epoch=item.timestamp,
            assessment="investigate; a mapping change alone is not proof of spoofing",
        )


def main() -> int:
    """Read JSONL records with interface, timestamp and frame_hex from stdin."""
    tracker = Tracker()
    for line_number, line in enumerate(sys.stdin, 1):
        try:
            record = json.loads(line)
            frame = bytes.fromhex(record["frame_hex"])
            item = parse_frame(frame, record["interface"], record["timestamp"])
            if item is not None:
                event = tracker.observe(item)
                if event is not None:
                    print(json.dumps(event, sort_keys=True))
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            print(f"arpwatchdog: line {line_number}: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
