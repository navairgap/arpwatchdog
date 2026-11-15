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
from collections.abc import Iterable
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


def detect_default_gateways(path: str = "/proc/net/route") -> list[str]:
    """Read the Linux routing table and return the IPv4 default gateway addresses."""
    try:
        with open(path, "r", encoding="ascii") as handle:
            rows = handle.readlines()[1:]
    except OSError:
        return []
    gateways: list[str] = []
    for row in rows:
        fields = row.split()
        if len(fields) < 3 or fields[1] != "00000000":
            continue
        raw = fields[2]
        if len(raw) != 8:
            continue
        address = bytes(int(raw[index:index + 2], 16) for index in (6, 4, 2, 0))
        if any(address):
            gateways.append(".".join(str(byte) for byte in address))
    return gateways


@dataclass(frozen=True)
class Observation:
    interface: str
    timestamp: float
    ip: str
    mac: str
    operation: int = 2
    kind: str = "arp_reply"
    target_ip: str = ""
    target_mac: str = ""


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
    target_mac = ":".join(f"{byte:02x}" for byte in arp[18:24])
    target_ip = ".".join(str(byte) for byte in arp[24:28])
    # RFC 5227 address probes use 0.0.0.0 and do not claim ownership.
    if sender_ip == "0.0.0.0":
        return None
    # RFC 5227 section 3: announcements repeat the sender address in the
    # target fields; spoofing tools and address changes both use them.
    if sender_ip == target_ip:
        kind = "gratuitous_arp"
    elif operation == 2:
        kind = "arp_reply"
    else:
        kind = "arp_request"
    return Observation(
        interface, float(timestamp), sender_ip, sender_mac,
        operation=operation, kind=kind, target_ip=target_ip, target_mac=target_mac,
    )


def load_baseline(path: str) -> "tuple[dict[str, str], list[str]]":
    """Read an arpwatch-style arp.dat baseline; returns (entries, problems).

    Accepted line shapes: `mac ip`, or the extended `mac ip interface time`
    form written by modern arpwatch. Malformed lines are skipped and reported.
    """
    entries: dict[str, str] = {}
    problems: list[str] = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError as exc:
        return entries, [str(exc)]
    for line_number, line in enumerate(lines, 1):
        parts = line.split()
        if not parts:
            continue
        try:
            mac = canonical_mac(parts[0])
            ip = canonical_ip(parts[1])
        except (ValueError, IndexError) as exc:
            problems.append(f"line {line_number}: {exc}")
            continue
        if ip in entries and entries[ip] != mac:
            problems.append(f"line {line_number}: duplicate claim for {ip}")
            continue
        entries[ip] = mac
    return entries, problems


def save_baseline(path: str, entries: "dict[str, str]") -> None:
    """Write a classic `mac ip` arp.dat baseline file."""
    with open(path, "w", encoding="utf-8") as handle:
        for ip, mac in sorted(entries.items(), key=lambda kv: (ip_to_int(kv[0]))):
            handle.write(f"{mac} {ip}\n")


class Suppressor:
    """Bounded per-(event, ip) alert deduplication with a configurable window."""

    def __init__(
        self,
        window: float = 60.0,
        max_entries: int = 1024,
        per_kind: "dict[str, float] | None" = None,
    ) -> None:
        if isinstance(window, bool) or not isinstance(window, (int, float)) \
                or not math.isfinite(window) or window < 0:
            raise ValueError("window must be a non-negative finite number")
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError("max_entries must be a positive integer")
        self.window = float(window)
        self.max_entries = max_entries
        self.per_kind = dict(per_kind or {})
        self._last: OrderedDict[tuple[str, str], float] = OrderedDict()

    def allow(self, event: dict[str, object]) -> bool:
        """Return True the first time a (kind, ip) alert is seen inside a window."""
        key = (str(event.get("event")), str(event.get("ip")))
        now = float(event.get("observed_at_epoch") or 0.0)
        last = self._last.get(key)
        self._last[key] = now
        self._last.move_to_end(key)
        while len(self._last) > self.max_entries:
            self._last.popitem(last=False)
        kind_window = self.per_kind.get(key[0], self.window)
        if last is not None and now - last < kind_window:
            return False
        return True


def ip_to_int(ip: str) -> int:
    """Convert a canonical dotted-quad IPv4 string to its integer value."""
    value = 0
    for part in canonical_ip(ip).split("."):
        value = (value << 8) | int(part)
    return value


class IpFilter:
    """Match IPv4 addresses against configured ignore CIDR ranges."""

    def __init__(self, ranges: "Iterable[str]" = ()) -> None:
        self._networks: list[tuple[int, int]] = []
        for entry in ranges or ():
            self.add(entry)

    def add(self, entry: str) -> None:
        """Add one CIDR range (a bare address is treated as /32)."""
        if not isinstance(entry, str) or not entry.strip():
            raise ValueError("ignore entries must be non-empty strings")
        text = entry.strip()
        if "/" in text:
            address, prefix_text = text.split("/", 1)
            prefix = int(prefix_text)
        else:
            address, prefix = text, 32
        if not 0 <= prefix <= 32:
            raise ValueError(f"prefix length out of range: {entry!r}")
        network = ip_to_int(address)
        if prefix:
            mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
            network &= mask
        else:
            mask = 0
        self._networks.append((network, mask))

    def matches(self, ip: str) -> bool:
        """Return True when ip falls inside any configured ignore range."""
        value = ip_to_int(ip)
        return any(value & mask == network for network, mask in self._networks)

    def __len__(self) -> int:
        return len(self._networks)


class Tracker:
    """Bounded IP-to-MAC history; changes are observations, not attack verdicts."""

    def __init__(
        self,
        max_entries: int = 4096,
        report_new_hosts: bool = True,
        flip_flop_window: float = 300.0,
        flip_flop_changes: int = 3,
        gateways: "Iterable[str]" = (),
    ) -> None:
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError("max_entries must be a positive integer")
        if isinstance(flip_flop_window, bool) or not isinstance(flip_flop_window, (int, float)) \
                or not math.isfinite(flip_flop_window) or flip_flop_window <= 0:
            raise ValueError("flip_flop_window must be a positive finite number")
        if isinstance(flip_flop_changes, bool) or not isinstance(flip_flop_changes, int) \
                or flip_flop_changes < 2:
            raise ValueError("flip_flop_changes must be an integer of at least 2")
        self.max_entries = max_entries
        self.report_new_hosts = report_new_hosts
        self.flip_flop_window = float(flip_flop_window)
        self.flip_flop_changes = flip_flop_changes
        self.gateways: set[str] = {canonical_ip(ip) for ip in gateways}
        self._seen: OrderedDict[str, Observation] = OrderedDict()
        # ip -> [(timestamp, mac), ...] for recent mapping changes, oldest first
        self._changes: OrderedDict[str, list[tuple[float, str]]] = OrderedDict()

    def set_gateways(self, gateways: "Iterable[str]") -> None:
        """Replace the watched gateway set; addresses are canonicalized first."""
        self.gateways = {canonical_ip(ip) for ip in gateways}

    def seed_baseline(self, entries: "dict[str, str]", timestamp: float = 0.0) -> None:
        """Pre-load known IP/MAC pairs so known hosts do not alert as new."""
        for ip, mac in entries.items():
            canonical = Observation("baseline", timestamp, canonical_ip(ip), canonical_mac(mac))
            if canonical.ip in self._seen:
                continue
            self._seen[canonical.ip] = canonical
        self._prune()

    def export_baseline(self) -> "dict[str, str]":
        """Return the current learned IP/MAC map for persistence."""
        return {item.ip: item.mac for item in self._seen.values()}

    def _prune(self) -> None:
        while len(self._seen) > self.max_entries:
            self._seen.popitem(last=False)

    def observe(self, item: Observation) -> dict[str, object] | None:
        item = Observation(
            item.interface, item.timestamp, canonical_ip(item.ip), canonical_mac(item.mac),
            operation=item.operation, kind=item.kind,
            target_ip=item.target_ip, target_mac=item.target_mac,
        )
        previous = self._seen.get(item.ip)
        self._seen[item.ip] = item
        self._seen.move_to_end(item.ip)
        self._prune()
        if previous is None:
            if self.report_new_hosts:
                event = make_event(
                    "new_host",
                    ip=item.ip,
                    mac=item.mac,
                    interface=item.interface,
                    packet_kind=item.kind,
                    gateway=item.ip in self.gateways,
                    observed_at=rfc3339(item.timestamp),
                    observed_at_epoch=item.timestamp,
                    assessment="first observation of this address; normal on startup "
                               "or after a baseline reset",
                )
                if item.ip in self.gateways:
                    event["assessment"] = "first observation of a watched gateway; " \
                                          "confirm this matches the real router"
                return event
            return None
        if previous.mac == item.mac:
            return None
        self._record_change(item)
        flip_flop = self._detect_flip_flop(item)
        kind = "gateway_mac_changed" if item.ip in self.gateways else "mapping_changed"
        assessment = (
            "a gateway MAC change is the classic ARP spoofing indicator; verify the "
            "real router MAC from the device itself before assuming an attack"
            if kind == "gateway_mac_changed"
            else "investigate; a mapping change alone is not proof of spoofing"
        )
        return make_event(
            kind,
            ip=item.ip,
            previous_mac=previous.mac,
            current_mac=item.mac,
            previous_interface=previous.interface,
            interface=item.interface,
            first_seen=rfc3339(previous.timestamp),
            first_seen_epoch=previous.timestamp,
            observed_at=rfc3339(item.timestamp),
            observed_at_epoch=item.timestamp,
            flip_flop=flip_flop,
            assessment=assessment,
        )

    def _record_change(self, item: Observation) -> None:
        """Remember one MAC transition for the flip-flop detector."""
        history = self._changes.get(item.ip)
        if history is None:
            history = []
            self._changes[item.ip] = history
        history.append((item.timestamp, item.mac))
        history[:] = [
            (ts, mac) for ts, mac in history
            if ts >= item.timestamp - self.flip_flop_window
        ]

    def _detect_flip_flop(self, item: Observation) -> dict[str, object] | None:
        """Flag rapid alternation between MACs for one address within a window."""
        history = self._changes.get(item.ip, [])
        mac_counts: OrderedDict[str, int] = OrderedDict()
        for _, mac in history:
            mac_counts[mac] = mac_counts.get(mac, 0) + 1
        if len(history) != self.flip_flop_changes or len(mac_counts) < 2:
            return None
        return {
            "changes": len(history),
            "window_seconds": self.flip_flop_window,
            "macs": dict(mac_counts),
            "note": "rapid MAC alternation; consistent with ARP spoofing but also "
                    "with aggressive failover or NIC teaming",
        }


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
