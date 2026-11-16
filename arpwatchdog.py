#!/usr/bin/env python3
"""Offline parser and change tracker for passive Ethernet/IPv4 ARP observations.

Input frames are supplied by the operator; this program never sends ARP probes.
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import math
import sys
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass

SCHEMA_VERSION = 1
__version__ = "1.0.0"


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


def canonical_address(ip: str) -> str:
    """Canonicalize either an IPv4 or an IPv6 address string."""
    if isinstance(ip, str) and ":" in ip:
        return str(ipaddress.IPv6Address(ip))
    return canonical_ip(ip)


def ip_sort_key(ip: str) -> "tuple":
    """A total sort order across IPv4 and IPv6 addresses."""
    try:
        return (0, f"{ip_to_int(ip):010d}", "")
    except ValueError:
        return (1, "0", ipaddress.IPv6Address(ip).packed)


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


# Small offline OUI table for well-known vendors (mostly virtualization, whose
# MACs are worth flagging when they claim physical-network identities).
VENDOR_OUIS = {
    "00:00:0c": "Cisco",
    "00:05:69": "VMware",
    "00:0c:29": "VMware",
    "00:1c:42": "Parallels",
    "00:15:5d": "Microsoft Hyper-V",
    "00:50:56": "VMware",
    "00:e0:4c": "Realtek",
    "08:00:27": "VirtualBox",
    "3c:5a:b4": "Google",
    "52:54:00": "QEMU/KVM",
    "ac:de:48": "Apple",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "f8:bc:12": "Raspberry Pi",
}


def vendor_for(mac: str) -> "str | None":
    """Return the vendor for a MAC's OUI, or None when unknown."""
    try:
        canonical = canonical_mac(mac)
    except ValueError:
        return None
    return VENDOR_OUIS.get(canonical[:8])


def classify_arp(sender_ip: str, target_ip: str, operation: int) -> str:
    """Name the packet kind; announcements repeat the sender address (RFC 5227)."""
    if sender_ip == target_ip:
        return "gratuitous_arp"
    return "arp_reply" if operation == 2 else "arp_request"


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
    return Observation(
        interface, float(timestamp), sender_ip, sender_mac,
        operation=operation,
        kind=classify_arp(sender_ip, target_ip, operation),
        target_ip=target_ip, target_mac=target_mac,
    )


def observation_from_scapy_packet(packet: object, interface: str) -> "Observation | None":
    """Convert one captured scapy packet into an Observation (receive only).

    Handles IPv4 ARP and IPv6 Neighbor Discovery NS/NA with link-layer options.
    """
    try:
        from scapy.layers.l2 import ARP, Ether  # noqa: PLC0415 - optional dependency
    except ImportError:  # pragma: no cover - exercised only without scapy
        raise RuntimeError(
            "live capture requires scapy (pip install scapy); "
            "use replay mode to process saved JSONL instead"
        ) from None
    timestamp = float(packet.time)
    ether_layer = packet.getlayer(Ether)
    arp_item = _arp_observation(packet, timestamp, interface, ether_layer)
    if arp_item is not None:
        return arp_item
    dhcp_item = _dhcp_observation(packet, timestamp, interface, ether_layer)
    if dhcp_item is not None:
        return dhcp_item
    return _nd_observation(packet, timestamp, interface, ether_layer)


def _dhcp_observation(packet: object, timestamp: float, interface: str,
                      ether_layer: "object | None") -> "Observation | None":
    """DHCP ACKs passively confirm a lease: yiaddr -> client MAC."""
    try:
        from scapy.layers.dhcp import BOOTP, DHCP  # noqa: PLC0415 - optional dependency
    except ImportError:  # pragma: no cover - exercised only without scapy
        return None
    bootp_layer = packet.getlayer(BOOTP)
    dhcp_layer = packet.getlayer(DHCP)
    if bootp_layer is None or dhcp_layer is None:
        return None
    message_type = None
    for option in dhcp_layer.options:
        if isinstance(option, tuple) and option[0] == "message-type":
            message_type = option[1]
            break
    if message_type != 5:  # DHCPACK only; OFFER/NAK do not confirm a lease
        return None
    yiaddr = str(bootp_layer.yiaddr)
    if yiaddr in ("0.0.0.0", ""):
        return None
    chaddr = bytes(bootp_layer.chaddr or b"")
    if len(chaddr) < 6:
        return None
    sender_mac = canonical_mac(chaddr[:6].hex(":"))
    return Observation(
        interface, timestamp, canonical_ip(yiaddr), sender_mac,
        operation=0, kind="dhcp_ack",
        target_ip=canonical_ip(str(bootp_layer.siaddr) or "0.0.0.0"),
        target_mac="",
    )


def _arp_observation(packet: object, timestamp: float, interface: str,
                     ether_layer: "object | None") -> "Observation | None":
    from scapy.layers.l2 import ARP  # noqa: PLC0415 - optional dependency
    arp_layer = packet.getlayer(ARP)
    if arp_layer is None:
        return None
    sender_ip = str(arp_layer.psrc)
    if sender_ip == "0.0.0.0":
        return None
    operation = int(arp_layer.op)
    if operation not in (1, 2):
        return None
    sender_mac = canonical_mac(str(arp_layer.hwsrc))
    target_ip = str(arp_layer.pdst)
    target_mac = canonical_mac(str(ether_layer.dst)) if ether_layer is not None else ""
    return Observation(
        interface, timestamp, canonical_ip(sender_ip), sender_mac,
        operation=operation,
        kind=classify_arp(sender_ip, target_ip, operation),
        target_ip=canonical_ip(target_ip), target_mac=target_mac,
    )


def _nd_observation(packet: object, timestamp: float, interface: str,
                    ether_layer: "object | None") -> "Observation | None":
    """IPv6 Neighbor Discovery: NS claims src->SLLA, NA claims tgt->TLLA."""
    try:
        # noqa: PLC0415 - optional dependency
        from scapy.layers.inet6 import (  # noqa: PLC0415
            ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr,
        )
    except ImportError:  # pragma: no cover - exercised only without scapy
        return None
    ns_layer = packet.getlayer(ICMPv6ND_NS)
    na_layer = packet.getlayer(ICMPv6ND_NA)
    if ns_layer is None and na_layer is None:
        return None
    ip6_layer = packet.getlayer("IPv6")
    if ip6_layer is None:
        return None
    sender_ip = str(ip6_layer.src)
    if sender_ip == "::":
        return None  # RFC 4862 duplicate-address probes do not claim ownership
    if ns_layer is not None:
        option = packet.getlayer(ICMPv6NDOptSrcLLAddr)
        sender_mac = canonical_mac(str(option.lladdr)) if option is not None else \
            (canonical_mac(str(ether_layer.src)) if ether_layer is not None else None)
        kind = "nd_neighbor_solicitation"
        operation = 135
        target_ip = str(ns_layer.tgt)
    else:
        option = packet.getlayer(ICMPv6NDOptDstLLAddr)
        sender_mac = canonical_mac(str(option.lladdr)) if option is not None else \
            (canonical_mac(str(ether_layer.src)) if ether_layer is not None else None)
        kind = "nd_neighbor_advertisement"
        operation = 136
        target_ip = str(na_layer.tgt)
        sender_ip = target_ip  # the advertisement claims the target address
    if sender_mac is None:
        return None
    target_mac = canonical_mac(str(ether_layer.dst)) if ether_layer is not None else ""
    return Observation(
        interface, timestamp, canonical_address(sender_ip), sender_mac,
        operation=operation, kind=kind,
        target_ip=canonical_address(target_ip), target_mac=target_mac,
    )


class ScapySource:
    """Passive live ARP capture; never transmits packets or probes."""

    def __init__(self, interface: str, chunk_seconds: float = 1.0) -> None:
        if not interface:
            raise ValueError("an interface name is required for live capture")
        self.interface = interface
        self.chunk_seconds = chunk_seconds

    def observations(self):
        """Yield Observations forever, one sniff chunk at a time."""
        try:
            from scapy.all import sniff  # noqa: PLC0415 - optional dependency
        except ImportError as exc:
            raise RuntimeError(
                "live capture requires scapy (pip install scapy); "
                "use replay mode to process saved JSONL instead"
            ) from exc
        pending: list[object] = []
        while True:
            del pending[:]
            sniff(
                iface=self.interface,
                filter="arp",
                store=False,
                timeout=self.chunk_seconds,
                prn=pending.append,
            )
            for packet in pending:
                try:
                    item = observation_from_scapy_packet(packet, self.interface)
                except ValueError:
                    continue
                if item is not None:
                    yield item


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
        for ip, mac in sorted(entries.items(), key=lambda kv: ip_sort_key(kv[0])):
            handle.write(f"{mac} {ip}\n")


def save_state(path: str, entries: "dict[str, str]", gateways: "Iterable[str]" = ()) -> None:
    """Atomically persist learned mappings and watched gateways as JSON."""
    import os
    import time

    payload = {
        "schema_version": SCHEMA_VERSION,
        "saved_at": rfc3339(time.time()),
        "entries": {ip: mac for ip, mac in entries.items()},
        "gateways": sorted(gateways),
    }
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True)
        handle.write("\n")
    os.replace(tmp_path, path)


def load_state(path: str) -> "tuple[dict[str, str], list[str], list[str]]":
    """Restore persisted state; returns (entries, gateways, problems)."""
    problems: list[str] = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except FileNotFoundError:
        return {}, [], problems
    except (OSError, json.JSONDecodeError) as exc:
        return {}, [], [str(exc)]
    entries: dict[str, str] = {}
    for ip, mac in (payload.get("entries") or {}).items():
        try:
            entries[canonical_ip(ip)] = canonical_mac(mac)
        except ValueError as exc:
            problems.append(str(exc))
    gateways: list[str] = []
    for ip in payload.get("gateways") or []:
        try:
            gateways.append(canonical_ip(ip))
        except ValueError as exc:
            problems.append(str(exc))
    return entries, gateways, problems


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
        """Return True when this alert should be emitted.

        Only emitted alerts restart the window. Flip-flop evidence is never
        suppressed: it is the actionable spoofing signature and it is rare.
        """
        key = (str(event.get("event")), str(event.get("ip")))
        now = float(event.get("observed_at_epoch") or 0.0)
        kind_window = self.per_kind.get(key[0], self.window)
        last = self._last.get(key)
        if last is not None and now - last < kind_window and not event.get("flip_flop"):
            return False
        self._last[key] = now
        self._last.move_to_end(key)
        while len(self._last) > self.max_entries:
            self._last.popitem(last=False)
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
        """Return True when ip falls inside any configured ignore range.

        IPv6 addresses never match IPv4 CIDR ignore ranges and are not an error.
        """
        try:
            value = ip_to_int(ip)
        except ValueError:
            return False
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
        self.gateways: set[str] = {canonical_address(ip) for ip in gateways}
        self._seen: OrderedDict[str, Observation] = OrderedDict()
        self._first_seen: OrderedDict[str, float] = OrderedDict()
        # ip -> [(timestamp, mac), ...] for recent mapping changes, oldest first
        self._changes: OrderedDict[str, list[tuple[float, str]]] = OrderedDict()

    def set_gateways(self, gateways: "Iterable[str]") -> None:
        """Replace the watched gateway set; addresses are canonicalized first."""
        self.gateways = {canonical_address(ip) for ip in gateways}

    def seed_baseline(self, entries: "dict[str, str]", timestamp: float = 0.0) -> None:
        """Pre-load known IP/MAC pairs so known hosts do not alert as new."""
        for ip, mac in entries.items():
            canonical = Observation("baseline", timestamp, canonical_address(ip), canonical_mac(mac))
            if canonical.ip in self._seen:
                continue
            self._seen[canonical.ip] = canonical
            self._first_seen[canonical.ip] = timestamp
        self._prune()

    def export_baseline(self) -> "dict[str, str]":
        """Return the current learned IP/MAC map for persistence."""
        return {item.ip: item.mac for item in self._seen.values()}

    def host_records(self) -> "list[dict[str, object]]":
        """Return the tracked inventory with first/last seen and change counts."""
        records = []
        for item in self._seen.values():
            first = self._first_seen.get(item.ip, item.timestamp)
            records.append({
                "ip": item.ip,
                "mac": item.mac,
                "vendor": vendor_for(item.mac),
                "interface": item.interface,
                "first_seen": rfc3339(first),
                "first_seen_epoch": first,
                "last_seen": rfc3339(item.timestamp),
                "last_seen_epoch": item.timestamp,
                "recent_changes": len(self._changes.get(item.ip, [])),
            })
        return records

    def _prune(self) -> None:
        while len(self._seen) > self.max_entries:
            oldest = self._seen.popitem(last=False)[0]
            self._first_seen.pop(oldest, None)

    def observe(self, item: Observation) -> dict[str, object] | None:
        item = Observation(
            item.interface, item.timestamp, canonical_address(item.ip), canonical_mac(item.mac),
            operation=item.operation, kind=item.kind,
            target_ip=item.target_ip, target_mac=item.target_mac,
        )
        previous = self._seen.get(item.ip)
        self._seen[item.ip] = item
        self._seen.move_to_end(item.ip)
        self._first_seen.setdefault(item.ip, item.timestamp)
        self._prune()
        if previous is None:
            if self.report_new_hosts:
                event = make_event(
                    "new_host",
                    ip=item.ip,
                    mac=item.mac,
                    vendor=vendor_for(item.mac),
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
        conflict = self._detect_conflict(item)
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
            vendor=vendor_for(item.mac),
            previous_interface=previous.interface,
            interface=item.interface,
            first_seen=rfc3339(previous.timestamp),
            first_seen_epoch=previous.timestamp,
            observed_at=rfc3339(item.timestamp),
            observed_at_epoch=item.timestamp,
            flip_flop=flip_flop,
            ip_conflict=conflict,
            assessment=assessment,
        )

    def _record_change(self, item: Observation) -> None:
        """Remember one MAC transition for the flip-flop and conflict detectors."""
        history = self._changes.get(item.ip)
        if history is None:
            history = []
            self._changes[item.ip] = history
        history.append((item.timestamp, item.mac))
        history[:] = [
            (ts, mac) for ts, mac in history
            if ts >= item.timestamp - self.flip_flop_window
        ]

    def _detect_conflict(self, item: Observation) -> "dict[str, object] | None":
        """Flag a second MAC claiming the same address inside the flip window.

        One MAC change can be a normal replacement; a second different MAC
        inside the window means two devices are actively claiming the address.
        """
        history = self._changes.get(item.ip, [])
        older = history[:-1] if history else []
        if not older:
            return None
        macs = [mac for _, mac in older if mac != item.mac]
        if not macs:
            return None
        return {
            "macs": sorted(set(macs) | {item.mac}),
            "note": "more than one hardware address claimed this IP inside the "
                    "conflict window; two devices are using the same address",
        }

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


def format_event_text(event: "dict") -> str:
    """One-line human-readable alert rendering."""
    parts = [
        event.get("observed_at") or "",
        str(event.get("event")).upper(),
        f"ip={event.get('ip')}",
    ]
    if "mac" in event:
        parts.append(f"mac={event['mac']}")
    if "previous_mac" in event:
        parts.append(f"was={event['previous_mac']}")
        parts.append(f"now={event['current_mac']}")
    if "interface" in event:
        parts.append(f"iface={event['interface']}")
    assessment = event.get("assessment")
    if assessment:
        parts.append(f"-- {assessment}")
    return "[" + " ".join(parts) + "]"


CSV_COLUMNS = ("event", "ip", "mac", "previous_mac", "current_mac", "interface", "observed_at")


def format_event_csv(event: "dict") -> str:
    """One-line CSV alert rendering with a fixed column set."""
    import csv as _csv
    import io as _io

    buffer = _io.StringIO()
    writer = _csv.writer(buffer, lineterminator="\n")
    writer.writerow([event.get(column, "") for column in CSV_COLUMNS])
    return buffer.getvalue().rstrip("\n")


def make_sink(format_name: str, stream: "object" = None) -> "callable":
    """Build an event sink that writes the chosen format to a stream."""
    import sys as _sys

    stream = stream if stream is not None else _sys.stdout
    formatters = {
        "json": lambda event: json.dumps(event, sort_keys=True) + "\n",
        "text": lambda event: format_event_text(event) + "\n",
        "csv": lambda event: format_event_csv(event) + "\n",
    }
    if format_name not in formatters:
        raise ValueError(f"unknown output format: {format_name}")
    formatter = formatters[format_name]

    def sink(event: "dict") -> None:
        stream.write(formatter(event))
        stream.flush()

    return sink


class FileSink:
    """Append formatted alerts to a file, one event per line."""

    def __init__(self, path: str, format_name: str = "json") -> None:
        formatters = {
            "json": lambda event: json.dumps(event, sort_keys=True) + "\n",
            "text": lambda event: format_event_text(event) + "\n",
            "csv": lambda event: format_event_csv(event) + "\n",
        }
        if format_name not in formatters:
            raise ValueError(f"unknown alert-file format: {format_name}")
        self._render = formatters[format_name]
        self._stream = open(path, "a", encoding="utf-8")

    def __call__(self, event: "dict") -> None:
        self._stream.write(self._render(event))
        self._stream.flush()

    def close(self) -> None:
        self._stream.close()


class SyslogSink:
    """Emit alerts to the system logger with event-specific priorities."""

    PRIORITY_BY_EVENT = {
        "new_host": 4,              # LOG_WARNING
        "mapping_changed": 4,       # LOG_WARNING
        "gateway_mac_changed": 2,   # LOG_CRIT
        "flip_flop": 2,             # LOG_CRIT
    }

    def __init__(self, ident: str = "arpwatchdog") -> None:
        import syslog as _syslog
        self._syslog = _syslog
        self._syslog.openlog(ident)

    def __call__(self, event: "dict") -> None:
        priority = self.PRIORITY_BY_EVENT.get(str(event.get("event")), 5)  # 5=LOG_NOTICE
        self._syslog.syslog(priority, format_event_text(event))


class WebhookSink:
    """POST each alert as JSON to an HTTPS/HTTP endpoint; failures never raise."""

    def __init__(self, url: str, timeout: float = 5.0) -> None:
        if not url.lower().startswith(("http://", "https://")):
            raise ValueError("webhook URL must start with http:// or https://")
        self.url = url
        self.timeout = timeout
        self.failures = 0
        self.delivered = 0

    def __call__(self, event: "dict") -> None:
        import urllib.request
        payload = json.dumps(event, sort_keys=True).encode("utf-8")
        request = urllib.request.Request(
            self.url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if 200 <= response.status < 300:
                    self.delivered += 1
                else:
                    self.failures += 1
        except OSError as exc:
            self.failures += 1
            print(f"arpwatchdog: webhook delivery failed: {exc}", file=sys.stderr)


def severity_for(event: "dict") -> str:
    """Assign an operator-facing severity; signals, not verdicts."""
    if event.get("flip_flop"):
        return "critical"
    kind = str(event.get("event"))
    if kind == "gateway_mac_changed":
        return "critical"
    if kind == "mapping_changed":
        return "warning"
    return "info"


def multi_sink(*sinks: "callable") -> "callable":
    """Dispatch one event to every configured sink."""

    def sink(event: "dict") -> None:
        for target in sinks:
            target(event)

    return sink


class Stats:
    """Bounded counters describing one monitor run."""

    def __init__(self) -> None:
        self.records = 0
        self.non_arp = 0
        self.arp_observations = 0
        self.malformed = 0
        self.alerts: "dict[str, int]" = {}
        self.critical = 0
        self.suppressed = 0
        self.ignored_by_filter = 0

    def count_alert(self, kind: str, severity: str = "info") -> None:
        self.alerts[kind] = self.alerts.get(kind, 0) + 1
        if severity == "critical":
            self.critical += 1

    def summary(self) -> "dict[str, object]":
        return {
            "records_read": self.records,
            "arp_observations": self.arp_observations,
            "non_arp_frames": self.non_arp,
            "malformed": self.malformed,
            "alerts": dict(sorted(self.alerts.items())),
            "suppressed": self.suppressed,
            "ignored_by_filter": self.ignored_by_filter,
        }

    def line(self) -> str:
        parts = [f"{name}={value}" for name, value in self.summary().items()]
        return "stats: " + " ".join(parts)


class PcapSource:
    """Replay ARP observations from a saved pcap/pcapng capture (read-only)."""

    def __init__(self, path: str, interface: "str | None" = None) -> None:
        if not path:
            raise ValueError("a capture path is required for pcap replay")
        self.path = path
        self.interface = interface or "pcap"

    def observations(self):
        """Yield Observations from the capture, in order."""
        try:
            from scapy.utils import PcapReader  # noqa: PLC0415 - optional dependency
        except ImportError as exc:
            raise RuntimeError(
                "pcap replay requires scapy (pip install scapy); "
                "use replay mode to process saved JSONL instead"
            ) from exc
        with PcapReader(self.path) as reader:
            for packet in reader:
                try:
                    item = observation_from_scapy_packet(packet, self.interface)
                except ValueError:
                    continue
                if item is not None:
                    yield item


def render_inventory_markdown(records: "list[dict[str, object]]") -> str:
    """Render the tracked inventory as a markdown table."""
    lines = [
        "| ip | mac | vendor | interface | first seen | last seen | changes |",
        "|---|---|---|---|---|---|---|",
    ]
    for record in records:
        lines.append(
            f"| {record['ip']} | {record['mac']} | {record.get('vendor') or ''} "
            f"| {record['interface']} | {record['first_seen']} "
            f"| {record['last_seen']} | {record['recent_changes']} |"
        )
    return "\n".join(lines) + "\n"


def render_inventory_html(records: "list[dict[str, object]]") -> str:
    """Render the tracked inventory as a standalone HTML page."""
    import html as _html

    def esc(value: object) -> str:
        return _html.escape(str(value))

    rows = []
    for record in records:
        rows.append(
            f"<tr><td>{esc(record['ip'])}</td><td>{esc(record['mac'])}</td>"
            f"<td>{esc(record.get('vendor') or '')}</td>"
            f"<td>{esc(record['interface'])}</td>"
            f"<td>{esc(record['first_seen'])}</td>"
            f"<td>{esc(record['last_seen'])}</td>"
            f"<td>{esc(record['recent_changes'])}</td></tr>"
        )
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        "<title>arpwatchdog inventory</title>\n"
        "<style>body{font-family:sans-serif;margin:2rem}"
        "table{border-collapse:collapse}th,td{border:1px solid #999;"
        "padding:.25rem .5rem;text-align:left}th{background:#eee}</style>\n"
        "</head>\n<body>\n<h1>arpwatchdog inventory</h1>\n"
        "<table>\n<tr><th>ip</th><th>mac</th><th>vendor</th><th>interface</th>"
        "<th>first seen</th><th>last seen</th><th>changes</th></tr>\n"
        + "\n".join(rows) +
        "\n</table>\n</body>\n</html>\n"
    )


def render_metrics(stats: "Stats", tracked_hosts: int) -> str:
    """Render run statistics in Prometheus text exposition format."""
    lines = [
        "# HELP arpwatchdog_observations_total ARP/ND/DHCP observations processed.",
        "# TYPE arpwatchdog_observations_total counter",
        f"arpwatchdog_observations_total {stats.arp_observations}",
        "# HELP arpwatchdog_alerts_total Alerts emitted by event kind.",
        "# TYPE arpwatchdog_alerts_total counter",
    ]
    for kind, count in sorted(stats.alerts.items()):
        lines.append(f'arpwatchdog_alerts_total{{event="{kind}"}} {count}')
    lines += [
        "# HELP arpwatchdog_tracked_hosts Addresses currently tracked.",
        "# TYPE arpwatchdog_tracked_hosts gauge",
        f"arpwatchdog_tracked_hosts {tracked_hosts}",
        "# HELP arpwatchdog_suppressed_total Alerts suppressed by deduplication.",
        "# TYPE arpwatchdog_suppressed_total counter",
        f"arpwatchdog_suppressed_total {stats.suppressed}",
        "# HELP arpwatchdog_ignored_by_filter_total Events dropped by ignore rules.",
        "# TYPE arpwatchdog_ignored_by_filter_total counter",
        f"arpwatchdog_ignored_by_filter_total {stats.ignored_by_filter}",
    ]
    return "\n".join(lines) + "\n"


def save_metrics(path: str, stats: "Stats", tracked_hosts: int) -> None:
    """Atomically write the current metrics snapshot to path."""
    import os
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        handle.write(render_metrics(stats, tracked_hosts))
    os.replace(tmp_path, path)


class MetricsServer:
    """Serve the current metrics snapshot over HTTP (opt-in, local)."""

    def __init__(self, provider: "callable", host: str = "127.0.0.1", port: int = 9835) -> None:
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path not in ("/metrics", "/"):
                    self.send_error(404)
                    return
                body = outer._provider().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: object) -> None:
                pass

        self._provider = provider
        self._threading = threading
        self._server = ThreadingHTTPServer((host, port), Handler)
        self._thread = None

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    def start(self) -> None:
        self._thread = self._threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


class PeriodicReporter:
    """Run a callback on an interval until stopped (used for live summaries)."""

    def __init__(self, interval: float, action: "callable") -> None:
        import threading
        if isinstance(interval, bool) or not isinstance(interval, (int, float)) \
                or not math.isfinite(interval) or interval <= 0:
            raise ValueError("stats interval must be a positive finite number")
        self.interval = float(interval)
        self.action = action
        self._threading = threading
        self._event = threading.Event()
        self._thread = None

    def start(self) -> None:
        def loop() -> None:
            while not self._event.wait(self.interval):
                try:
                    self.action()
                except Exception as exc:  # never kill the reporter thread
                    print(f"arpwatchdog: stats interval: {exc}", file=sys.stderr)

        self._thread = self._threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)


class StopFlag:
    """A simple cooperative stop request shared with signal handlers."""

    def __init__(self) -> None:
        self.stop = False

    def request(self, *_args: object) -> None:
        self.stop = True


class Monitor:
    """Wires a packet source into detections, filters, suppression and output."""

    def __init__(
        self,
        tracker: Tracker,
        suppressor: "Suppressor | None" = None,
        ip_filter: "IpFilter | None" = None,
        sink: "callable | None" = None,
        stats: "Stats | None" = None,
    ) -> None:
        self.tracker = tracker
        self.suppressor = suppressor
        self.ip_filter = ip_filter
        self.sink = sink or _print_event
        self.stats = stats or Stats()

    def handle_observation(self, item: Observation) -> "dict | None":
        """Run one observation through detections and the alert pipeline."""
        self.stats.arp_observations += 1
        event = self.tracker.observe(item)
        if event is None:
            return None
        if self.ip_filter is not None and self.ip_filter.matches(str(event["ip"])):
            self.stats.ignored_by_filter += 1
            return None
        if self.suppressor is not None and not self.suppressor.allow(event):
            self.stats.suppressed += 1
            return None
        event["severity"] = severity_for(event)
        self.stats.count_alert(str(event.get("event")), str(event["severity"]))
        self.sink(event)
        return event

    def run_jsonl(self, stream: "object") -> int:
        """Read JSONL records with interface, timestamp and frame_hex."""
        problems = 0
        for line_number, line in enumerate(stream, 1):
            self.stats.records += 1
            try:
                record = json.loads(line)
                frame = bytes.fromhex(record["frame_hex"])
                item = parse_frame(frame, record["interface"], record["timestamp"])
                if item is None:
                    self.stats.non_arp += 1
                else:
                    self.handle_observation(item)
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                problems += 1
                self.stats.malformed += 1
                print(f"arpwatchdog: line {line_number}: {exc}", file=sys.stderr)
        return problems

    def run_live(self, interface: str, stop: "StopFlag | None" = None) -> None:
        """Capture passively from an interface until interrupted or stopped."""
        source = ScapySource(interface)
        try:
            for item in source.observations():
                if stop is not None and stop.stop:
                    break
                self.handle_observation(item)
        except KeyboardInterrupt:
            pass

    def run_pcap(self, path: str, interface: "str | None" = None) -> None:
        """Replay a saved capture through the pipeline."""
        source = PcapSource(path, interface)
        for item in source.observations():
            self.handle_observation(item)


def _print_event(event: "dict") -> None:
    print(json.dumps(event, sort_keys=True))


CONFIG_KEYS = frozenset({
    "interface", "replay", "baseline", "state", "gateway", "ignore",
    "no-new-hosts", "no-suppress", "suppress-window", "flip-window",
    "flip-changes", "max-entries", "format", "alert-file", "syslog",
    "webhook", "quiet", "stats",
})
CONFIG_ALIASES = {"gateways": "gateway"}


def load_config(path: str) -> "dict[str, object]":
    """Load a TOML config; recognized keys become CLI defaults."""
    import tomllib

    with open(path, "rb") as handle:
        data = tomllib.load(handle)
    if "arpwatchdog" in data and isinstance(data["arpwatchdog"], dict):
        data = data["arpwatchdog"]
    resolved: dict[str, object] = {}
    for key, value in data.items():
        key = CONFIG_ALIASES.get(key, key)
        if key not in CONFIG_KEYS:
            raise ValueError(f"unknown configuration key: {key!r}")
        resolved[key.replace("-", "_")] = value
    return resolved


def build_parser() -> "object":
    import argparse

    parser = argparse.ArgumentParser(
        prog="arpwatchdog",
        description="Passive ARP spoofing detector: watches IP/MAC changes, "
                    "flip-flops and gateway moves. Never sends probes.",
    )
    parser.add_argument("-i", "--interface", metavar="IFACE",
                        help="capture ARP live on this interface (requires scapy)")
    parser.add_argument("-r", "--replay", metavar="FILE", default=None,
                        help="replay JSONL records from FILE ('-' or omitted reads stdin)")
    parser.add_argument("-p", "--pcap", metavar="FILE", default=None,
                        help="replay ARP observations from a saved pcap/pcapng capture "
                             "(requires scapy)")
    parser.add_argument("-f", "--baseline", metavar="FILE",
                        help="load an arp.dat-style baseline (mac ip per line)")
    parser.add_argument("--state", metavar="FILE",
                        help="load and periodically save learned state as JSON")
    parser.add_argument("--gateway", action="append", default=[], metavar="IP",
                        help="watch this gateway (repeatable; auto-detected in live mode)")
    parser.add_argument("--ignore", action="append", default=[], metavar="CIDR",
                        help="ignore events for this CIDR range (repeatable)")
    parser.add_argument("--no-new-hosts", action="store_true",
                        help="do not emit new_host events")
    parser.add_argument("--no-suppress", action="store_true",
                        help="emit every event without deduplication")
    parser.add_argument("--suppress-window", type=float, default=60.0, metavar="SEC",
                        help="alert deduplication window in seconds (default 60)")
    parser.add_argument("--flip-window", type=float, default=300.0, metavar="SEC",
                        help="flip-flop detection window in seconds (default 300)")
    parser.add_argument("--flip-changes", type=int, default=3, metavar="N",
                        help="MAC changes within the window that flag a flip-flop (default 3)")
    parser.add_argument("--max-entries", type=int, default=4096, metavar="N",
                        help="maximum tracked IP addresses (default 4096)")
    parser.add_argument("--format", choices=("json", "text", "csv"), default="json",
                        help="alert output format (default json)")
    parser.add_argument("--alert-file", metavar="FILE",
                        help="also append alerts to FILE")
    parser.add_argument("--syslog", action="store_true",
                        help="also send alerts to the system logger")
    parser.add_argument("--webhook", metavar="URL",
                        help="also POST JSON alerts to this URL")
    parser.add_argument("--quiet", action="store_true",
                        help="do not print alerts to stdout")
    parser.add_argument("--stats", action="store_true",
                        help="print a run summary to stderr when processing ends")
    parser.add_argument("--metrics-file", metavar="PATH",
                        help="write Prometheus metrics to PATH when processing ends")
    parser.add_argument("--metrics-serve", metavar="[HOST:]PORT",
                        help="serve metrics over HTTP on this address "
                             "(default host 127.0.0.1; only scrape from trusted networks)")
    parser.add_argument("--stats-interval", type=float, default=0.0, metavar="SEC",
                        help="print stats and refresh --metrics-file every SEC seconds "
                             "during live capture")
    parser.add_argument("--fail-on", choices=("none", "critical"), default="none",
                        help="exit with code 3 when a critical alert is emitted "
                             "(useful in CI pipelines)")
    parser.add_argument("--dry-run", action="store_true",
                        help="process input and count events but emit no alerts "
                             "(stdout, files, syslog and webhooks stay silent)")
    parser.add_argument("--config", metavar="FILE.toml",
                        help="read default options from a TOML file; "
                             "command-line flags override it")
    parser.add_argument("--list", action="store_true",
                        help="print the learned IP/MAC table after processing and exit")
    parser.add_argument("--export", nargs=2, metavar=("FORMAT", "FILE"),
                        help="export the learned table as json or csv")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: "list[str] | None" = None) -> int:
    parser = build_parser()
    options = parser.parse_args(argv)
    if options.config:
        try:
            parser.set_defaults(**load_config(options.config))
        except (OSError, ValueError) as exc:
            print(f"arpwatchdog: config: {exc}", file=sys.stderr)
            return 2
        options = parser.parse_args(argv)

    try:
        tracker = Tracker(
            max_entries=options.max_entries,
            report_new_hosts=not options.no_new_hosts,
            flip_flop_window=options.flip_window,
            flip_flop_changes=options.flip_changes,
        )
        if options.baseline:
            entries, problems = load_baseline(options.baseline)
            tracker.seed_baseline(entries)
            for problem in problems:
                print(f"arpwatchdog: baseline: {problem}", file=sys.stderr)
        state_entries, state_gateways, state_problems = {}, [], []
        if options.state:
            state_entries, state_gateways, state_problems = load_state(options.state)
            tracker.seed_baseline(state_entries)
            for problem in state_problems:
                print(f"arpwatchdog: state: {problem}", file=sys.stderr)
        gateways = set(options.gateway) | set(state_gateways)
        if not gateways and options.interface:
            gateways = set(detect_default_gateways())
        if gateways:
            tracker.set_gateways(gateways)
        suppressor = None if options.no_suppress else Suppressor(options.suppress_window)
        ip_filter = IpFilter(options.ignore)
        sinks: "list[callable]" = []
        if options.dry_run:
            sinks = []  # counters still run; nothing is emitted anywhere
        elif not options.quiet:
            sinks.append(make_sink(options.format))
        if options.alert_file and not options.dry_run:
            file_sink = FileSink(options.alert_file, options.format)
            sinks.append(file_sink)
        if options.syslog and not options.dry_run:
            sinks.append(SyslogSink())
        if options.webhook and not options.dry_run:
            sinks.append(WebhookSink(options.webhook))
        monitor = Monitor(
            tracker, suppressor=suppressor, ip_filter=ip_filter,
            sink=multi_sink(*sinks), stats=Stats(),
        )
    except ValueError as exc:
        print(f"arpwatchdog: {exc}", file=sys.stderr)
        return 2

    metrics_server = None
    if options.metrics_serve:
        host, _, port_text = options.metrics_serve.partition(":")
        if not port_text:
            host, port_text = "127.0.0.1", host
        try:
            metrics_server = MetricsServer(
                lambda: render_metrics(monitor.stats, len(tracker.export_baseline())),
                host=host or "127.0.0.1", port=int(port_text),
            )
            metrics_server.start()
        except (OSError, ValueError) as exc:
            print(f"arpwatchdog: metrics server: {exc}", file=sys.stderr)
            return 2

    if options.interface:
        import signal
        stop = StopFlag()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, stop.request)
            except (OSError, ValueError):  # pragma: no cover - platform limits
                pass

        def report_periodically() -> None:
            print(monitor.stats.line(), file=sys.stderr)
            if options.metrics_file:
                save_metrics(options.metrics_file, monitor.stats,
                             len(tracker.export_baseline()))

        reporter = None
        if options.stats_interval > 0:
            reporter = PeriodicReporter(options.stats_interval, report_periodically)
            reporter.start()
        monitor.run_live(options.interface, stop)
        if reporter is not None:
            reporter.stop()
        print("arpwatchdog: stopped", file=sys.stderr)
    elif options.pcap:
        monitor.run_pcap(options.pcap, options.interface or None)
    else:
        if options.replay in (None, "-"):
            stream = sys.stdin
        else:
            try:
                stream = open(options.replay, "r", encoding="utf-8")
            except OSError as exc:
                print(f"arpwatchdog: cannot open replay file: {exc}", file=sys.stderr)
                return 2
        try:
            problems = monitor.run_jsonl(stream)
        finally:
            if stream is not sys.stdin:
                stream.close()
        if problems:
            print(f"arpwatchdog: {problems} malformed input line(s)", file=sys.stderr)

    if metrics_server is not None:
        metrics_server.shutdown()
    if options.stats:
        print(monitor.stats.line(), file=sys.stderr)
    if options.metrics_file:
        save_metrics(options.metrics_file, monitor.stats, len(tracker.export_baseline()))

    if options.state:
        save_state(options.state, tracker.export_baseline(), tracker.gateways)
    if options.list:
        for ip, mac in sorted(
            tracker.export_baseline().items(), key=lambda kv: ip_sort_key(kv[0])
        ):
            print(f"{mac}  {ip}")
    if options.export:
        export_format, export_path = options.export
        if export_format not in ("json", "csv", "html", "md"):
            parser.error("export format must be json, csv, html or md")
        records = sorted(tracker.host_records(), key=lambda record: ip_sort_key(str(record["ip"])))
        writers = {
            "json": lambda handle: (
                json.dump(tracker.export_baseline(), handle, sort_keys=True, indent=2),
                handle.write("\n"),
            ),
            "csv": lambda handle: (
                handle.write("ip,mac\n"),
                [handle.write(f"{entry['ip']},{entry['mac']}\n") for entry in records],
            ),
            "html": lambda handle: handle.write(render_inventory_html(records)),
            "md": lambda handle: handle.write(render_inventory_markdown(records)),
        }
        with open(export_path, "w", encoding="utf-8", newline="") as handle:
            writers[export_format](handle)
    if options.fail_on == "critical" and monitor.stats.critical > 0:
        print(f"arpwatchdog: {monitor.stats.critical} critical alert(s) emitted",
              file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
