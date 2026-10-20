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

## Detection guidance

A MAC change is an observation, not a verdict. Detection output should include the baseline and new values, first/last seen times, and the rule that triggered. DHCP, failover, virtualization, and legitimate device replacement can cause changes.

## Tests

Use synthetic packet fixtures to cover truncated headers, invalid address lengths, duplicate observations, MAC normalization, and gateway changes. Unit tests must not require root privileges or a live interface.
