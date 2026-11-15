# Deployment notes

## systemd

```console
# pip install 'arpwatchdog[live]'       # system or dedicated venv
# cp examples/arpwatchdog.toml /etc/arpwatchdog.toml   # adjust gateways/ignore
# systemctl edit --full arpwatchdog     # set --interface and config path
# systemctl enable --now arpwatchdog
# journalctl -u arpwatchdog -f          # alerts go to syslog via --syslog
```

The unit runs as a dynamic unprivileged user holding only `CAP_NET_RAW`,
which is enough for passive ARP capture — no root, no shell.

## Baseline

Create the initial baseline after a clean scan of your network (for example
from a trusted replay capture):

```console
# arpwatchdog -r clean-capture.jsonl --list > /var/lib/arpwatchdog/arp.dat
# systemctl restart arpwatchdog
```

## Alert routing

- `--syslog` routes events into journald/rsyslog with `LOG_CRIT` for
  gateway changes and flip-flops.
- `--webhook https://...` POSTs each event as JSON; failures are counted and
  logged, never fatal.
- `--alert-file /var/log/arpwatchdog.log` appends machine-readable events.

## Updating the tool

State (`--state`) is versioned JSON; a newer release reads older state files.
Delete `/var/lib/arpwatchdog/state.json` to reset learning entirely.
