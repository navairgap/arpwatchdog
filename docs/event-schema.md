# ARP observation event schema (draft v1)

This schema is a proposed boundary between passive packet capture, detection rules, and output. The monitor is still in design stage; this file does not imply packet capture exists.

## JSON example

```json
{
  "schema_version": 1,
  "observed_at": "2026-10-20T12:00:00Z",
  "interface": "eth0",
  "kind": "arp_reply",
  "sender_ip": "192.0.2.1",
  "sender_mac": "02:00:00:00:00:01",
  "target_ip": "192.0.2.20",
  "target_mac": "02:00:00:00:00:20",
  "tags": []
}
```

## Contract

- Emit one JSON object per observation; timestamps are UTC RFC 3339.
- Normalize MAC addresses to six lowercase, colon-separated octets before comparison.
- Preserve IPv4 addresses in canonical dotted-decimal form.
- `kind` is an enum such as `arp_request`, `arp_reply`, or `gratuitous_arp`; unknown packet types should be counted or skipped explicitly, not guessed.
- Never include unrelated packet payloads or credentials in events.
- Malformed packets should produce a bounded diagnostic counter; they must not crash the capture loop.

## Repeated observations and validation

- Validate IPv4 fields as addresses and MAC fields as exactly six hexadecimal octets before emitting an event.
- Canonicalize MAC casing before deduplication, so `aa:bb:cc:dd:ee:ff` and `AA:BB:CC:DD:EE:FF` are not treated as different devices.
- Repeated packets are separate observations, not automatically separate alerts. Detection rules should track first-seen and last-seen times and apply a documented aggregation window.
- The observation interface is part of event context: the same sender seen on different interfaces must not be merged without an explicit policy.

## Detection guidance

A MAC change is an observation, not a verdict. Detection output should include the baseline and new values, first/last seen times, and the rule that triggered. DHCP, failover, virtualization, and legitimate device replacement can cause changes.

## Baseline lifecycle

A learned IP-to-MAC mapping should have an explicit observation window and last-seen timestamp. Expired entries should become unknown rather than remain trusted indefinitely. A new mapping should be compared against a stable, recently observed baseline; do not alert on a single packet during startup without enough context to distinguish an incomplete learning period from a change. Keep the baseline local and make any manual trust override explicit and auditable.

## Tests

Use synthetic packet fixtures to cover truncated headers, invalid address lengths, duplicate observations, MAC normalization, and gateway changes. Unit tests must not require root privileges or a live interface.

## Event identity and ordering

If events are persisted or exported, assign a stable local event identifier and retain the capture sequence separately from wall-clock time. Timestamps can collide or move backward when a system clock is adjusted; use the sequence number to preserve observation order within one capture session. Do not use the sender IP/MAC pair as a unique event ID because repeated observations are meaningful evidence. On export, preserve the capture-session identifier so events from separate interfaces or sessions are not accidentally merged.


## VLAN visibility and observation identity

When the capture source exposes VLAN headers, preserve the observed tag identifiers and their outer-to-inner order in the event context. Include the interface on every observation; do not merge otherwise identical IP/MAC pairs across interfaces or known VLAN contexts.

Some capture drivers remove VLAN tags before delivering packets. In that case, record the VLAN visibility as unavailable rather than claiming the frame was untagged. Baseline keys and alert comparisons must use only context that was actually observed or explicitly configured. Tests should cover tagged frames, untagged frames, and captures where VLAN metadata is unavailable.
