# arpwatchdog

Standalone ARP-spoofing detector with instant desktop alerts

> 🚧 **Status: planning** — architecture and README first, code next.

## Why

ARP spoofing is the classic LAN attack: someone claims your gateway's MAC and reads all your traffic. Arpwatchdog watches the ARP table for duplicate or changing gateway MACs and screams the moment something looks wrong.

## Planned features

- Track gateway MAC over time; alert on any change
- Detect duplicate IP-MAC claims on the LAN
- Passive listening mode — never sends a single packet
- One-command install + systemd service

## Stack

`python` `scapy` `linux`

## Notes

Companion to SentinelWiFi's rogue-DHCP check; same ethics.

## License

MIT, see [LICENSE](LICENSE).

---
maintained · verified 2026-09-30
---
maintained · verified 2026-10-01
---
maintained · verified 2026-10-02

## Alert channels

Alerts print to stdout by default. Set `WATCHDOG_NOTIFY=webhook:https://…` to POST new-device events as JSON, or `WATCHDOG_NOTIFY=syslog` to route through the system logger. Multiple channels are comma-separated.
