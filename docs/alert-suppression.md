# Alert deduplication and cooldown (proposed)

Alert suppression should reduce repeated notifications without discarding the underlying observations. Keep raw observations, derived signals, and emitted alerts as separate records.

## Deduplication key

Build a stable key from the observation type, interface, protocol address, previous hardware address, and newly observed hardware address. Include VLAN context when available. Normalize MAC addresses to one canonical representation before building the key.

Do not use vendor names or a hostname as identity fields: both may be missing or inaccurate. A vendor lookup is supporting context only.

## Cooldown behavior

- A repeated matching signal inside the cooldown may update its last-seen time and count without emitting another notification.
- Preserve every observation needed for an operator to review the timeline, subject to the configured retention limit.
- Emit a new alert when the cooldown expires and the changed mapping is still observed.
- A materially different mapping or interface must not be hidden by an earlier alert.
- Keep the cooldown bounded and configurable; never suppress observations indefinitely.

Use a monotonic clock for elapsed cooldown calculations and UTC wall-clock timestamps for records. An injected clock should make boundary tests deterministic.

## Operator review

An alert should explain the evidence and list plausible benign causes such as router failover, interface replacement, virtual machines, or DHCP changes. Do not label a device malicious from one mapping change or a vendor database result.

## Required tests

Cover exact cooldown boundaries, repeated observations, changed interface/VLAN context, clock movement, state cleanup, and independent alerts for distinct mapping changes. Tests must not transmit ARP packets.