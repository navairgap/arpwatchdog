# arpwatchdog

**A passive ARP spoofing detector for local networks.**

arpwatchdog watches address-resolution traffic on your network and alerts the
moment something looks wrong: an IP that suddenly claims a different MAC, a
gateway whose hardware address moved, or two devices fighting over one
address — the classic signatures of ARP poisoning and man-in-the-middle
attacks.

It is strictly passive. It listens; it never sends ARP probes, scans hosts,
or injects packets.

```console
$ sudo arpwatchdog --interface eth0
[2026-11-16T10:14:03.512Z] [GATEWAY_MAC_CHANGED] ip=192.0.2.1 was=02:00:00:00:00:01 now=02:00:00:aa:bb:cc iface=eth0
```

---

## Why

On an Ethernet network, devices announce their IP-to-MAC bindings over ARP —
and any device can announce anything. A laptop that claims to be the router
receives your traffic. Detecting that requires watching for binding changes
and acting on them quickly.

arpwatchdog does exactly that: it observes ARP (and IPv6 neighbor discovery
and DHCP ACKs) on the wire, compares every claim against what it has seen
before, and emits an alert the moment a binding shifts.

## What it detects

| Alert | Severity | What it means |
|---|---|---|
| `new_host` | info | An address was claimed for the first time. Expected at startup. |
| `mapping_changed` | warning | An IP now claims a different MAC. Investigate. |
| `gateway_mac_changed` | critical | Your watched gateway changed hardware address — the classic ARP-poisoning signature. |
| flip-flop evidence | critical | One IP switched between MACs repeatedly inside the detection window. |
| `ip_conflict` | evidence | Two different MACs claimed the same IP inside the window. |

Every alert carries RFC 3339 UTC timestamps, the old and new MACs, the
interface, the packet kind that triggered it, a vendor name when the OUI is
known, and a short human-readable assessment. Severity is a signal to
investigate, not a verdict — DHCP renewals, router failover, and virtual
machines cause legitimate changes too.

## Quick start

```console
# Install (live capture needs scapy)
$ pip install 'arpwatchdog[live]'

# Monitor your network: alerts go to stdout, gateway auto-detected
$ sudo arpwatchdog --interface eth0

# Audit a saved capture instead of a live network
$ arpwatchdog --pcap suspicious.pcap
$ arpwatchdog --replay capture.jsonl --format text
```

No installation needed when run from a checkout: `sudo python3 arpwatchdog.py -i eth0`.

### Alerting somewhere useful

```console
# Syslog + webhook, quiet console
$ sudo arpwatchdog -i eth0 --syslog --webhook https://alerts.example.internal/hook --quiet

# Rotating alert file with a 10-minute deduplication window
$ sudo arpwatchdog -i eth0 --alert-file /var/log/arpwatchdog.log --alert-max-bytes 5000000 \
      --suppress-window 600

# Prometheus metrics on localhost:9835, refreshed every 30 s
$ sudo arpwatchdog -i eth0 --metrics-serve 9835 --stats-interval 30
```

### In CI pipelines

Replay a capture and fail the build when a critical signature fired:

```console
$ arpwatchdog --pcap evidence.pcap --fail-on critical && echo "clean"
```

## How it works

```
packets ──► parsers ──► tracker ──► detections ──► filters ──► suppression ──► sinks
(ARP/ND/DHCP)         (per-IP      (new host,     (CIDR        (dedup        (stdout, file,
                       history)     changes,       ignore)       window)       syslog, webhook,
                                    flip-flops)                                metrics, reports)
```

- **Parsers** turn ARP frames, IPv6 neighbor discovery NS/NA, and DHCP ACKs
  into observations. RFC 5227 probes (`0.0.0.0` / `::` senders) do not claim
  ownership and are skipped.
- **The tracker** keeps a bounded per-IP history (default 4096 hosts).
- **Detections** compare each claim with that history and assign severity.
- **Suppression** deduplicates repeated alerts per `(event, ip)` window.
  Flip-flop evidence is never suppressed: it is rare and actionable.
- **Sinks** deliver alerts in `json`, `text`, or `csv` — to stdout, a
  size-rotated file, syslog, or a webhook.

## Reference

### Input modes (choose one)

| Flag | Purpose |
|---|---|
| `-i, --interface IFACE` | Live capture (requires scapy and `CAP_NET_RAW`). |
| `-r, --replay FILE` | Replay JSONL frame records; `-` reads stdin. |
| `-p, --pcap FILE` | Replay a saved pcap/pcapng capture. |

JSONL record shape:

```json
{"interface": "eth0", "timestamp": 1730000000.5, "frame_hex": "001122...0806..."}
```

### Tuning

| Flag | Default | Purpose |
|---|---|---|
| `--gateway IP` | auto (live) | Watch these addresses as gateways (repeatable). |
| `--ignore CIDR` | — | Never alert for these ranges (repeatable). |
| `--suppress-window SEC` | 60 | Alert deduplication window. |
| `--flip-window SEC` | 300 | Flip-flop detection window. |
| `--flip-changes N` | 3 | MAC changes inside the window that flag a flip-flop. |
| `--baseline FILE` | — | arpwatch `arp.dat` file of known `mac ip` pairs. |
| `--state FILE` | — | Persist learned mappings across restarts (atomic JSON). |
| `--no-new-hosts` | off | Silence `new_host` events. |
| `--dry-run` | off | Count events, emit nothing. |
| `--debug` | off | Log pipeline decisions to stderr. |
| `--config FILE.toml` | — | Default options from TOML; flags override. |

A config file mirrors the long flags:

```toml
gateway = ["192.168.1.1"]
ignore = ["10.10.0.0/16"]
format = "json"
syslog = true
```

See [examples/arpwatchdog.toml](examples/arpwatchdog.toml) for an annotated
version and [deploy/](deploy/) for a hardened systemd unit.

### Reports and metrics

| Flag | Output |
|---|---|
| `--list` | Learned IP/MAC table to stdout. |
| `--export {json,csv,html,md} FILE` | Full inventory with first/last seen, vendor, change counts. |
| `--stats` | Run summary to stderr. |
| `--metrics-file PATH` | Prometheus snapshot, written atomically. |
| `--metrics-serve [HOST:]PORT` | Prometheus HTTP endpoint (opt-in, binds 127.0.0.1). |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, no critical alerts (or `--fail-on none`). |
| 2 | Usage or configuration error. |
| 3 | Critical alert(s) emitted and `--fail-on critical` was set. |

## Permissions

Live capture needs raw-socket access. Prefer the narrow capability over
running as root:

```console
# Allow the interpreter in your venv to capture, nothing more
$ sudo setcap cap_net_raw=eip /path/to/venv/bin/python3
```

The tool only reads. It never configures the network, and it never sends.

## Comparison with similar tools

| Tool | What arpwatchdog does differently |
|---|---|
| [arpwatch](https://en.wikipedia.org/wiki/Arpwatch) | Keeps arpwatch's baseline format and alert model; adds severity scores, JSON events, flip-flop evidence, and webhook/metrics output. |
| [AddrWatch](https://github.com/fln/addrwatch) / [ArpObserver](https://github.com/cgzones/arpobserver) | Those log pairings; arpwatchdog is built for *alerting*, with suppression windows and severities. |
| bettercap `net.recon` | Implements only the passive detection side of an offensive toolkit — arpwatchdog sends nothing. |
| [XArp](https://www.xarp.org/) / [Phantom](https://github.com/CyberRoute/phantom) / [shARP](https://github.com/europa502/shARP) | Headless and passive, suited to servers, containers, and CI. |

## Development

```console
$ make test     # 119 tests, no network or privileges needed
$ make lint     # flake8, zero findings
```

Design notes live in [docs/](docs/): the event schema, passive-input
contract, alert suppression, VLAN identity, and false-positive triage.

## Safety and limitations

- Passive capture only — there is no send/probe/poison code path by design.
- Test only on networks you own or are authorized to monitor.
- IPv4 ARP, IPv6 neighbor discovery, and DHCP over Ethernet; no Wi-Fi-specific
  frame types.
- Alerts carry metadata only — never packet payloads.

## License

MIT. See [LICENSE](LICENSE).
