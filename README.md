# arpwatchdog

A planned passive monitor for unexpected ARP and gateway-MAC changes on a local network.

> **Status: design stage.** This repository currently contains documentation only; packet capture and alerting are not implemented yet.

## Goal

Help an administrator notice suspicious local-network changes, such as a gateway MAC address changing unexpectedly or conflicting IP-to-MAC observations.

## Intended behavior

- Observe ARP traffic on an interface selected by the operator.
- Maintain a small local history of IP/MAC observations.
- Compare gateway observations with a configured or learned baseline.
- Report changes with timestamps and enough context to investigate.
- Offer stdout output first; other alert channels can follow once the event format stabilizes.

## Safety and limitations

- Passive capture must not generate ARP probes or modify network configuration.
- Packet capture requires appropriate permissions; prefer the narrowest capability supported by the platform instead of running the whole program as root.
- A MAC change is a signal to investigate, not proof of an attack. DHCP renewals, failover, virtualization, and legitimate hardware changes can produce similar events.
- Do not collect or transmit unrelated packet payloads.
- Test only on networks you own or are authorized to monitor.

## Planned milestones

- [ ] Specify the event schema and baseline format.
- [ ] Add parser tests from synthetic ARP fixtures.
- [ ] Implement passive capture behind an interface that can be mocked.
- [ ] Add duplicate-claim and gateway-change detection.
- [ ] Document permissions, exclusions, and alert tuning.

## License

MIT. See [LICENSE](LICENSE).
