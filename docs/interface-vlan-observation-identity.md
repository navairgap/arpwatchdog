# Interface and VLAN identity for ARP observations (proposed)

ArpWatchdog is in the design stage. This contract defines how observations
should be scoped so that mappings from distinct broadcast domains are not
accidentally merged.

## Observation context

An IP-to-MAC observation is meaningful only within its network context. The
local identity key for a sender mapping should include:

- the selected capture interface;
- the VLAN tag stack, when present and supported;
- the sender protocol address (IPv4 in the initial schema);
- the sender hardware address as the observed value, not as a trusted identity.

Do not merge observations solely because two interfaces see the same IPv4
address. The address may legitimately be reused on separate VLANs, bridges,
containers, or test networks.

## VLAN representation

Represent VLAN context explicitly:

- Untagged frames use a distinct `untagged` value.
- A tagged frame records the full supported tag stack in wire order, including
  VLAN identifiers and tag protocol identifiers.
- Preserve stacked tags where the capture adapter exposes them; do not flatten
  a QinQ stack into one guessed VLAN.
- If the capture adapter cannot determine VLAN context, represent it as
  `unknown`, not as untagged.
- Validate VLAN identifier ranges before emitting an observation.

A missing tag must never be interpreted as permission to merge the record with
a tagged observation.

## Baseline and gateway scope

A learned gateway mapping belongs to one interface/VLAN context. Configuration
should allow an operator to identify the expected gateway per context. A
gateway change on one VLAN must not silently alter the baseline for another.

If the interface name changes after a device rename, do not migrate trust
automatically. Require an explicit operator review or a separately defined
stable interface identifier. Keep the original capture name as observation
metadata for investigation.

## Detection and reporting

Reports should show the interface and VLAN context beside both the previous
and newly observed mapping. If context is unknown, lower confidence and label
the limitation instead of presenting a cross-network comparison as certain.

A change remains an observation, not proof of spoofing. Router failover,
virtualization, DHCP changes, and legitimate interface replacement remain
possible explanations.

## Fixture cases

Use synthetic Ethernet/ARP frames to cover:

- identical sender IPs on two different interfaces;
- the same IP on two VLAN identifiers;
- untagged versus unknown VLAN context;
- single-tag and stacked-tag frames;
- truncated VLAN headers and unsupported tag formats;
- gateway changes scoped to one interface/VLAN only.

Tests must use the parser and mock capture adapter, without sending ARP traffic
or requiring root privileges.
