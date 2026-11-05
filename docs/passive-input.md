# Passive ARP input

The first implementation is intentionally offline: it accepts one Ethernet
frame per JSONL input record and never opens a raw socket or transmits probes.

Each input line has this shape:

```json
{"interface":"eth0","timestamp":1730000000.5,"frame_hex":"00112233445566778899aabb0806..."}
```

`frame_hex` is the complete Ethernet frame in hexadecimal.
The parser accepts Ethernet/IPv4 ARP and up to two 802.1Q/802.1ad VLAN tags.
Unsupported hardware/protocol combinations and non-ARP frames are ignored;
truncated ARP frames are reported to stderr.

A mapping change event includes the old and new MAC, interface names, and
timestamps. It is deliberately phrased as an observation: DHCP renewals,
router failover, virtual machines, and hardware replacement can all change a
legitimate mapping. Preserve the evidence and investigate before drawing a
conclusion.

For capture collection, use an approved passive capture workflow on an
interface you administer. Do not add ARP probes, poisoning, or packet
injection to this tool.
