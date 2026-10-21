# observation state machine

Suggested states: Unknown, Observed, Stable, Changed, and Conflict. Include interface and timestamp in each observation. Treat gratuitous ARP as evidence, not proof of spoofing. Make gateway identity explicitly configured or label it learned. Suppress duplicate alerts with a bounded cooldown while preserving observations. This monitor is passive: it must not send ARP probes or modify network configuration.
