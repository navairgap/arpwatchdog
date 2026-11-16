# Passive input

The tool is passive by contract: every input path is read-only. It never
opens a raw socket for sending, never transmits probes, and never injects
packets. Three input channels exist:

1. JSONL replay (`--replay`): one Ethernet frame per record, offline.
2. Capture replay (`--pcap`): saved pcap/pcapng files, offline.
3. Live capture (`--interface`): scapy sniffing with an `arp` BPF filter.

## Observed protocols

- Ethernet/IPv4 ARP with up to two 802.1Q/802.1ad VLAN tags; RFC 5227 probes
  (0.0.0.0 senders) do not claim ownership and are skipped.
- IPv6 Neighbor Discovery NS/NA with link-layer address options; the
  unspecified source `::` is treated as a probe and skipped.
- DHCP ACKs, which confirm a lease mapping (`kind: dhcp_ack`).

A mapping change event includes the old and new MAC, interface names, and
timestamps. It is deliberately phrased as an observation: DHCP renewals,
router failover, virtual machines, and hardware replacement can all change a
legitimate mapping. Preserve the evidence and investigate before drawing a
conclusion.

Do not add ARP probes, poisoning, or packet injection to this tool.
