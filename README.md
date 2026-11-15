# arpwatchdog

A passive ARP spoofing detector for local networks. It watches IP-to-MAC
mapping changes, rapid MAC flip-flops, and gateway MAC moves — the classic
signatures of ARP poisoning / MITM attacks — and alerts in real time.

**It never sends packets.** No ARP probes, no scanning, no injection. It only
listens to ARP traffic that is already on the wire.

```
{"event": "gateway_mac_changed", "ip": "192.168.1.1", "previous_mac": "02:00:00:00:00:01",
 "current_mac": "02:00:00:aa:bb:cc", "interface": "eth0", "severity": "critical", ...}
```

## Features

- **Detections** — new hosts, IP/MAC mapping changes, gateway MAC changes,
  rapid flip-flops (possible spoofing), gratuitous ARP announcements, with
  `info` / `warning` / `critical` severity on every event.
- **Live capture** — passive sniffing via scapy (`--interface`), auto-detects
  your default gateway from the routing table.
- **Offline replay** — feed JSONL frame records from stdin or a file
  (`--replay`), ideal for CI, forensics and air-gapped review.
- **Baselines** — arpwatch `arp.dat` compatible (`--baseline`), so known
  hosts do not alert as new.
- **State** — learned mappings survive restarts (`--state`), atomic writes.
- **Alert sinks** — stdout, file, syslog, and webhooks (`--alert-file`,
  `--syslog`, `--webhook`), in `json`, `text` or `csv` formats.
- **Tuning** — CIDR ignore lists, per-alert suppression windows, bounded
  memory everywhere, TOML config files, run statistics.

## Quick start

```console
$ pip install 'arpwatchdog[live]'      # live capture needs scapy
$ sudo -E arpwatchdog --interface eth0                       # monitor + auto gateway
$ sudo -E arpwatchdog -i eth0 --gateway 192.168.1.1          # explicit gateway
$ arpwatchdog --replay capture.jsonl --format text           # replay offline
$ cat capture.jsonl | arpwatchdog                            # stdin works too
```

Run from the repository without installing:

```console
$ sudo -E python3 arpwatchdog.py --interface eth0
```

Useful combinations:

```console
# Alert to syslog + webhook, keep stdout quiet
$ sudo -E arpwatchdog -i eth0 --syslog --webhook https://alerts.example/hook --quiet

# Ignore lab ranges, deduplicate alerts for 10 minutes, load a baseline
$ arpwatchdog -r capture.jsonl --ignore 10.10.0.0/16 --suppress-window 600 \
      --baseline arp.dat

# Persist state and print a run summary
$ sudo -E arpwatchdog -i eth0 --state /var/lib/arpwatchdog/state.json --stats

# Export the learned table
$ arpwatchdog -r capture.jsonl --export csv hosts.csv --list
```

## What it detects

| Event | Severity | Meaning |
|---|---|---|
| `new_host` | info | First time an address was claimed. Normal at startup. |
| `mapping_changed` | warning | An IP now claims a different MAC. Investigate. |
| `gateway_mac_changed` | critical | The watched gateway MAC moved — the classic poisoning signature. |
| `mapping_changed` + `flip_flop` | critical | Rapid MAC alternation for one IP — active spoofing or aggressive failover. |

Events carry RFC 3339 UTC timestamps, both interfaces, old and new MACs, the
packet kind that triggered the alert, and a short assessment. Flip-flop
evidence bypasses alert suppression; everything else is deduplicated per
`(event, ip)` window.

**A change is a signal, not a verdict.** DHCP renewals, router failover,
virtualization, and NIC teaming produce legitimate changes. The events exist
to focus your investigation.

## Permissions

Live capture needs raw socket access. Prefer the narrow capability over
running as root:

```console
# Linux: allow raw capture for the interpreter only
# sudo setcap cap_net_raw=eip /usr/bin/python3.x   # or use a venv interpreter
```

macOS/BSD users can run with BPF device permissions. The tool only *reads*;
it never configures the network.

## Configuration

Command-line flags override a TOML file (`--config examples/arpwatchdog.toml`):

```toml
gateway = ["192.168.1.1"]
ignore = ["10.10.0.0/16"]
suppress-window = 60.0
flip-window = 300.0
flip-changes = 3
format = "json"
# syslog = true
# webhook = "https://alerts.example.internal/hook"
```

See [examples/arpwatchdog.toml](examples/arpwatchdog.toml) and
[deploy/](deploy/) for a systemd unit.

## Input format (replay mode)

One JSON object per line:

```json
{"interface": "eth0", "timestamp": 1730000000.5, "frame_hex": "001122...0806..."}
```

`frame_hex` is a complete Ethernet frame. Ethernet/IPv4 ARP with up to two
VLAN tags is parsed; non-ARP frames and RFC 5227 probes (0.0.0.0 senders) are
counted and ignored; malformed records produce stderr diagnostics without
stopping the run.

## Comparison with similar tools

- **arpwatch** — the classic; arpwatchdog keeps its baseline format and
  new-host/changed-MAC model, adds flip-flop severities, JSON events, and
  webhook output.
- **AddrWatch / ArpObserver** — similar passive pairing loggers; arpwatchdog
  focuses on *alerting* with tunable suppression rather than logging.
- **bettercap `net.recon`** — an offensive toolkit's passive ARP monitor;
  arpwatchdog implements only the detection side and sends nothing.
- **XArp / Phantom / shARP** — GUI or active-scanning detectors; arpwatchdog
  stays passive and headless for servers and CI.

## Development

```console
$ python3 -m unittest discover -v       # 69 tests, no network needed
$ flake8 arpwatchdog.py test_arpwatchdog.py --max-line-length=110
```

Design notes live in [docs/](docs/): event schema, passive-input contract,
alert suppression, VLAN identity, false-positive triage.

## Safety and limitations

- Passive capture only; the code contains no send/probe/poison paths by design.
- Test only on networks you own or are authorized to monitor.
- IPv4 ARP over Ethernet only (IPv6 ND is out of scope today).
- Do not collect or transmit unrelated packet payloads — events carry metadata
  only, never payload bytes.

## License

MIT. See [LICENSE](LICENSE).
