# Changelog

## 1.0.0 — 2026-11-15

First complete release.

### Added
- Passive live capture via scapy (`--interface`) with default-gateway
  auto-detection from `/proc/net/route`; offline JSONL replay is unchanged.
- Detections: `new_host`, `mapping_changed`, `gateway_mac_changed`, and
  flip-flop (rapid MAC alternation) evidence with `critical` severity.
- Gratuitous ARP announcement classification (RFC 5227).
- Address canonicalization (MAC forms collapse to one representation).
- Schema v1 events: RFC 3339 timestamps, severity, assessment text.
- Alert sinks: stdout, file, syslog, webhook; output formats json/text/csv.
- arp.dat-compatible baseline load/save and seeding.
- Atomic JSON state persistence across restarts.
- CIDR ignore filters and bounded per-(event, ip) alert suppression windows;
  flip-flop evidence is never suppressed.
- Runtime statistics counters and `--stats` summary.
- TOML configuration files (`--config`); example config and systemd unit.
- Packaging (`pyproject.toml`, console entry point) and GitHub Actions CI.
- End-to-end incident replay tests; 69 tests total.
