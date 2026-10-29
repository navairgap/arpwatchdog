# false positive triage

When an IP-to-MAC mapping changes, compare interface, VLAN context where available, timestamp, and recent observations before classifying it. Router failover, interface replacement, virtual machines, and DHCP changes can be benign explanations. Preserve raw observations for review, but avoid retaining more traffic metadata than needed. A changed mapping alone is not proof of malicious activity.

## Evidence thresholds

Keep the observation, suspicion signal, and alert decision as separate records. A single changed mapping can raise a low-confidence signal, while repeated conflicting replies from the same interface within the configured observation window may raise confidence. Do not label a device malicious from MAC-vendor lookup alone. Include the observations that triggered an alert and the benign explanations checked so an operator can reproduce the decision.
