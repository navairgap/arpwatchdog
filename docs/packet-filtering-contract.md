# Passive ARP capture contract (proposed)

ArpWatchdog is intended to observe local ARP behavior without generating traffic. A future capture adapter should make that boundary explicit and independently testable.

## Capture scope

- Capture ARP frames only on the operator-selected interface.
- Do not send ARP requests, gratuitous ARP announcements, probes, or packet replays.
- Do not enable promiscuous mode unless a documented platform requirement makes it necessary and the operator opts in.
- Do not retain unrelated Ethernet or IP payloads.
- Keep packet capture behind a narrow adapter so parser and state-machine tests can use synthetic frames without elevated permissions.

If VLAN-tagged traffic is supported, parse only enough link-layer metadata to identify the encapsulated ARP frame and preserve the VLAN identifier as context. Do not assume that observations from different VLANs belong to the same broadcast domain.

## Parser boundaries

Validate minimum Ethernet and ARP header lengths before reading fields. Accept only supported hardware/protocol address sizes and the expected Ethernet/IPv4 ARP protocol tuple in the initial implementation. Ignore unsupported formats with a counted diagnostic rather than indexing into a short frame.

Preserve sender and target protocol addresses, sender hardware address, operation, interface, and observation timestamp. Treat every address as data, not as proof of device identity.

## Permission model

Prefer the narrowest capture capability available on the target platform. Do not run unrelated application logic as root just because packet capture needs privilege. Document how to inspect and revoke any configured capability.

## Verification

Test valid requests and replies, gratuitous ARP, truncated frames, unsupported hardware lengths, VLAN-tagged frames if supported, and packets captured on multiple interfaces. Verify through a mock adapter that the program never calls a packet-send method.