# Changelog

## 1.5.0 — 2026-11-20

### Added
- IPv6 default-gateway auto-detection from `/proc/net/ipv6_route`: live mode
  now watches IPv6 gateways too, so ND-driven gateway MAC changes raise the
  dedicated `gateway_mac_changed` event.
- DHCP-aware baseline expiry: a DHCPACK reassigning a lease to a different
  MAC expires the old mapping (including its flip-flop/conflict evidence)
  and emits an informational `dhcp_reassignment` event instead of
  `mapping_changed`. Use `--no-dhcp-expire` for the legacy behavior.
- `--sd-notify`: systemd readiness (`READY=1`), watchdog petting at half of
  `$WATCHDOG_USEC`, and `STOPPING=1` on shutdown; sends are best-effort.
  The hardened unit in `deploy/` is now `Type=notify` with `WatchdogSec=30`.
- `--tui`: a live terminal dashboard during capture (stats, watched
  gateways, alerts by kind, newest alerts severity-colored); press q to
  quit. The row renderer is pure and unit-tested without a terminal.

### Docs
- README tables, the man page, shell completions, and the event-schema
  baseline-lifecycle note cover the new events and flags.

## 1.1.0 — 2026-11-16

### Added
- Duplicate-IP claim evidence (`ip_conflict`) on mapping-change events.
- Host inventory records with first/last seen, used by new report exports
  (`--export html|md` alongside json/csv), including vendor labels from a
  built-in virtualization OUI table.
- pcap/pcapng capture replay (`--pcap`).
- Passive IPv6 Neighbor Discovery (NS/NA) observations alongside ARP.
- Passive DHCP ACK lease observations (`kind: dhcp_ack`).
- Graceful shutdown: SIGTERM/SIGINT stop capture and save state.
- Prometheus metrics: atomic snapshots (`--metrics-file`) and an opt-in
  local HTTP endpoint (`--metrics-serve`).
- Periodic summaries during live capture (`--stats-interval`).
- CI exit policy (`--fail-on critical` exits 3) and silent processing
  (`--dry-run`), pipeline decision logging (`--debug`).
- Size-rotated alert files (`--alert-max-bytes`).
- Shell completions (bash, zsh), man page, Dockerfile and Makefile.

### Fixed
- Live capture now admits IPv6 neighbor discovery and DHCP into its BPF
  filter (previously ARP-only, so ND/DHCP observations never reached live
  mode).
- DHCP ACKs with an unset next-server field are no longer dropped.
- Corrupt state files with the wrong JSON types are reported instead of
  raising; IPv6 gateways survive state round trips.
- `--pcap` and `--replay` together is now a usage error instead of silently
  preferring pcap; missing captures and capture errors exit 2 with a clear
  message instead of a traceback.
- Full flake8 pass (zero findings) and modernized annotations.

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
