# false positive triage

When an IP-to-MAC mapping changes, compare interface, VLAN context where available, timestamp, and recent observations before classifying it. Router failover, interface replacement, virtual machines, and DHCP changes can be benign explanations. Preserve raw observations for review, but avoid retaining more traffic metadata than needed. A changed mapping alone is not proof of malicious activity.
