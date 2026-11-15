import json
import sys
import unittest

from arpwatchdog import (
    SCHEMA_VERSION,
    IpFilter,
    main,
    Observation,
    ScapySource,
    Suppressor,
    Tracker,
    canonical_ip,
    canonical_mac,
    detect_default_gateways,
    format_event_csv,
    format_event_text,
    load_baseline,
    load_state,
    make_sink,
    observation_from_scapy_packet,
    parse_frame,
    save_baseline,
    save_state,
    rfc3339,
)


def arp_frame(sender_mac, sender_ip, vlan=False, gratuitous=False, request=False):
    mac = bytes.fromhex(sender_mac.replace(":", ""))
    ip = bytes(int(part) for part in sender_ip.split("."))
    target_ip = ip if gratuitous else bytes((192, 0, 2, 1))
    ethernet = b"\x00" * 6 + b"\x00" * 6
    if vlan:
        ethernet += b"\x81\x00\x00\x07\x08\x06"
    else:
        ethernet += b"\x08\x06"
    operation = b"\x00\x01" if request else b"\x00\x02"
    payload = (
        b"\x00\x01" + b"\x08\x00" + b"\x06\x04" + operation
        + mac + ip + b"\x00" * 6 + target_ip
    )
    return ethernet + payload


class ArpParserTests(unittest.TestCase):
    def test_parses_ipv4_arp_reply(self):
        item = parse_frame(
            arp_frame("02:00:00:00:00:01", "192.0.2.10"),
            "eth0", 10.0,
        )
        self.assertEqual(item.interface, "eth0")
        self.assertEqual(item.timestamp, 10.0)
        self.assertEqual(item.ip, "192.0.2.10")
        self.assertEqual(item.mac, "02:00:00:00:00:01")
        self.assertEqual(item.kind, "arp_reply")
        self.assertEqual(item.operation, 2)
        self.assertEqual(item.target_ip, "192.0.2.1")

    def test_classifies_gratuitous_announcements(self):
        item = parse_frame(
            arp_frame("02:00:00:00:00:07", "192.0.2.7", gratuitous=True),
            "eth0", 12,
        )
        self.assertEqual(item.kind, "gratuitous_arp")
        self.assertEqual(item.target_ip, "192.0.2.7")

    def test_parses_single_vlan_tag(self):
        item = parse_frame(
            arp_frame("02:00:00:00:00:01", "192.0.2.10", vlan=True),
            "enp3s0", 11,
        )
        self.assertEqual(item.ip, "192.0.2.10")

    def test_ignores_arp_probe_and_non_arp_frames(self):
        self.assertIsNone(parse_frame(
            arp_frame("02:00:00:00:00:01", "0.0.0.0"), "eth0", 1
        ))
        self.assertIsNone(parse_frame(b"\x00" * 12 + b"\x08\x00" + b"\x00" * 50, "eth0", 1))

    def test_rejects_truncated_frame_and_bad_timestamp(self):
        with self.assertRaises(ValueError):
            parse_frame(b"short", "eth0", 1)
        with self.assertRaises(ValueError):
            parse_frame(arp_frame("02:00:00:00:00:01", "192.0.2.1"), "eth0", float("nan"))


class CanonicalizationTests(unittest.TestCase):
    def test_mac_forms_normalize_to_one_representation(self):
        self.assertEqual(canonical_mac("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(canonical_mac("aa-bb-cc-dd-ee-ff"), "aa:bb:cc:dd:ee:ff")
        with self.assertRaises(ValueError):
            canonical_mac("aa:bb:cc:dd:ee")
        with self.assertRaises(ValueError):
            canonical_mac("zz:bb:cc:dd:ee:ff")

    def test_ip_rejects_leading_zero_and_out_of_range_octets(self):
        self.assertEqual(canonical_ip("192.0.2.1"), "192.0.2.1")
        with self.assertRaises(ValueError):
            canonical_ip("192.0.2.256")
        with self.assertRaises(ValueError):
            canonical_ip("010.0.2.1")
        with self.assertRaises(ValueError):
            canonical_ip("192.0.2")

    def test_rfc3339_is_utc_with_milliseconds(self):
        self.assertEqual(rfc3339(1730000000.5), "2024-10-27T03:33:20.500Z")

    def test_events_carry_schema_version_and_rfc3339_times(self):
        tracker = Tracker()
        tracker.observe(Observation("eth0", 1, "192.0.2.10", "02:00:00:00:00:01"))
        event = tracker.observe(Observation("eth0", 2.25, "192.0.2.10", "02:00:00:00:00:02"))
        self.assertEqual(event["schema_version"], SCHEMA_VERSION)
        self.assertEqual(event["observed_at"], "1970-01-01T00:00:02.250Z")
        self.assertEqual(event["observed_at_epoch"], 2.25)
        self.assertEqual(event["first_seen"], "1970-01-01T00:00:01.000Z")


class TrackerTests(unittest.TestCase):
    def test_reports_new_host_then_change(self):
        tracker = Tracker()
        first = Observation("eth0", 1, "192.0.2.10", "02:00:00:00:00:01")
        same = Observation("eth0", 2, "192.0.2.10", "02:00:00:00:00:01")
        changed = Observation("wlan0", 3, "192.0.2.10", "02:00:00:00:00:02")
        new_host = tracker.observe(first)
        self.assertEqual(new_host["event"], "new_host")
        self.assertEqual(new_host["ip"], "192.0.2.10")
        self.assertIsNone(tracker.observe(same))
        event = tracker.observe(changed)
        self.assertEqual(event["event"], "mapping_changed")
        self.assertEqual(event["previous_interface"], "eth0")
        self.assertIn("not proof", event["assessment"])

    def test_new_hosts_can_be_disabled(self):
        tracker = Tracker(report_new_hosts=False)
        self.assertIsNone(tracker.observe(Observation("eth0", 1, "192.0.2.10", "02:00:00:00:00:01")))

    def test_history_is_bounded(self):
        tracker = Tracker(max_entries=2, report_new_hosts=False)
        for index in range(3):
            tracker.observe(Observation("eth0", index, f"192.0.2.{index + 1}", "02:00:00:00:00:01"))
        self.assertEqual(len(tracker._seen), 2)


class FlipFlopTests(unittest.TestCase):
    MAC_A = "02:00:00:00:00:01"
    MAC_B = "02:00:00:00:00:02"

    def feed(self, tracker, sequence):
        events = []
        for step, (ts, mac) in enumerate(sequence, 1):
            event = tracker.observe(Observation("eth0", ts, "192.0.2.10", mac))
            if event and event["event"] != "new_host":
                events.append(event)
        return events

    def test_flags_alternation_between_two_macs(self):
        tracker = Tracker(report_new_hosts=True, flip_flop_changes=3)
        sequence = [(10, self.MAC_A), (20, self.MAC_B), (30, self.MAC_A), (40, self.MAC_B)]
        events = self.feed(tracker, sequence)
        self.assertEqual(len(events), 3)  # new_host suppressed, 3 mapping changes
        flips = [event for event in events if event.get("flip_flop")]
        self.assertEqual(len(flips), 1)
        self.assertEqual(flips[0]["flip_flop"]["changes"], 3)
        self.assertEqual(
            flips[0]["flip_flop"]["macs"], {self.MAC_A: 1, self.MAC_B: 2}
        )

    def test_changes_outside_window_do_not_flip_flop(self):
        tracker = Tracker(report_new_hosts=False, flip_flop_window=10)
        sequence = [(0, self.MAC_A), (100, self.MAC_B), (200, self.MAC_A), (300, self.MAC_B)]
        events = self.feed(tracker, sequence)
        self.assertEqual(len(events), 3)
        self.assertTrue(all(not event.get("flip_flop") for event in events))

    def test_flip_flop_threshold_is_configurable(self):
        tracker = Tracker(report_new_hosts=False, flip_flop_changes=2, flip_flop_window=60)
        sequence = [(0, self.MAC_A), (10, self.MAC_B), (20, self.MAC_A)]
        events = self.feed(tracker, sequence)
        flips = [event for event in events if event.get("flip_flop")]
        self.assertEqual(len(flips), 1)
        self.assertEqual(flips[0]["flip_flop"]["changes"], 2)


class GatewayTests(unittest.TestCase):
    MAC_A = "02:00:00:00:00:01"
    MAC_B = "02:00:00:00:00:02"

    def test_gateway_change_raises_dedicated_event(self):
        tracker = Tracker(report_new_hosts=False, gateways=["192.0.2.1"])
        tracker.observe(Observation("eth0", 1, "192.0.2.1", self.MAC_A))
        event = tracker.observe(Observation("eth0", 2, "192.0.2.1", self.MAC_B))
        self.assertEqual(event["event"], "gateway_mac_changed")
        self.assertIn("classic ARP spoofing indicator", event["assessment"])

    def test_non_gateway_addresses_keep_mapping_changed(self):
        tracker = Tracker(report_new_hosts=False, gateways=["192.0.2.1"])
        tracker.observe(Observation("eth0", 1, "192.0.2.99", self.MAC_A))
        event = tracker.observe(Observation("eth0", 2, "192.0.2.99", self.MAC_B))
        self.assertEqual(event["event"], "mapping_changed")

    def test_new_host_event_flags_gateway(self):
        tracker = Tracker(report_new_hosts=True, gateways=["192.0.2.1"])
        event = tracker.observe(Observation("eth0", 1, "192.0.2.1", self.MAC_A))
        self.assertEqual(event["event"], "new_host")
        self.assertTrue(event["gateway"])

    def test_detect_default_gateways_parses_proc_route(self):
        import tempfile, os
        rows = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\n"
            "eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\n"
            "eth0\tC0A80200\t00000000\t0001\t0\t0\t100\tFFFFFF00\t0\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".route", delete=False) as handle:
            handle.write(rows)
            path = handle.name
        try:
            self.assertEqual(detect_default_gateways(path), ["192.168.2.1"])
        finally:
            os.unlink(path)

    def test_detect_default_gateways_missing_file_is_empty(self):
        self.assertEqual(detect_default_gateways("/nonexistent/route"), [])


class SuppressorTests(unittest.TestCase):
    @staticmethod
    def alert(kind="mapping_changed", ip="192.0.2.10", ts=100.0):
        return {"event": kind, "ip": ip, "observed_at_epoch": ts}

    def test_repeats_inside_window_are_suppressed(self):
        suppressor = Suppressor(window=60)
        self.assertTrue(suppressor.allow(self.alert(ts=100)))
        self.assertFalse(suppressor.allow(self.alert(ts=130)))
        self.assertTrue(suppressor.allow(self.alert(ts=191)))

    def test_different_kind_or_ip_are_independent(self):
        suppressor = Suppressor(window=60)
        self.assertTrue(suppressor.allow(self.alert(ts=100)))
        self.assertTrue(suppressor.allow(self.alert(ts=101, kind="new_host")))
        self.assertTrue(suppressor.allow(self.alert(ts=102, ip="192.0.2.11")))

    def test_per_kind_windows_override_the_default(self):
        suppressor = Suppressor(window=60, per_kind={"new_host": 0})
        self.assertTrue(suppressor.allow(self.alert(kind="new_host", ts=10)))
        self.assertTrue(suppressor.allow(self.alert(kind="new_host", ts=11)))

    def test_memory_is_bounded(self):
        suppressor = Suppressor(max_entries=2)
        for index in range(5):
            suppressor.allow(self.alert(ip=f"192.0.2.{index}", ts=index))
        self.assertEqual(len(suppressor._last), 2)


class IpFilterTests(unittest.TestCase):
    def test_cidr_ranges_match_and_reject(self):
        ip_filter = IpFilter(["10.0.0.0/8", "192.0.2.5"])
        self.assertTrue(ip_filter.matches("10.255.3.4"))
        self.assertTrue(ip_filter.matches("192.0.2.5"))
        self.assertFalse(ip_filter.matches("192.0.2.6"))
        self.assertFalse(ip_filter.matches("11.0.0.1"))

    def test_zero_prefix_ignores_everything(self):
        ip_filter = IpFilter(["0.0.0.0/0"])
        self.assertTrue(ip_filter.matches("203.0.113.9"))

    def test_bad_entries_are_rejected(self):
        with self.assertRaises(ValueError):
            IpFilter(["192.0.2.0/33"])
        with self.assertRaises(ValueError):
            IpFilter(["not-an-ip/8"])

    def test_empty_filter_matches_nothing(self):
        ip_filter = IpFilter()
        self.assertFalse(ip_filter.matches("192.0.2.1"))
        self.assertEqual(len(ip_filter), 0)


class BaselineTests(unittest.TestCase):
    def setUp(self):
        import os, tempfile
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "arp.dat")
        self.addCleanup(self.dir.cleanup)

    def test_load_classic_and_extended_lines(self):
        with open(self.path, "w") as handle:
            handle.write("02:00:00:00:00:01 192.0.2.10\n")
            handle.write("02:00:00:00:00:02 192.0.2.11 eth0 1730000000\n")
            handle.write("\n")
            handle.write("bogus line\n")
        entries, problems = load_baseline(self.path)
        self.assertEqual(entries, {
            "192.0.2.10": "02:00:00:00:00:01",
            "192.0.2.11": "02:00:00:00:00:02",
        })
        self.assertEqual(len(problems), 1)

    def test_load_missing_file_returns_problem(self):
        entries, problems = load_baseline("/nonexistent/arp.dat")
        self.assertEqual(entries, {})
        self.assertEqual(len(problems), 1)

    def test_seeded_baseline_suppresses_new_host_but_not_changes(self):
        tracker = Tracker()
        tracker.seed_baseline({"192.0.2.10": "02:00:00:00:00:01"})
        self.assertIsNone(tracker.observe(
            Observation("eth0", 10, "192.0.2.10", "02:00:00:00:00:01")
        ))
        event = tracker.observe(
            Observation("eth0", 11, "192.0.2.10", "02:00:00:00:00:02")
        )
        self.assertEqual(event["event"], "mapping_changed")
        self.assertEqual(event["previous_mac"], "02:00:00:00:00:01")

    def test_baseline_round_trip(self):
        tracker = Tracker()
        tracker.observe(Observation("eth0", 1, "192.0.2.20", "02:00:00:00:00:09"))
        save_baseline(self.path, tracker.export_baseline())
        entries, problems = load_baseline(self.path)
        self.assertEqual(problems, [])
        self.assertEqual(entries, {"192.0.2.20": "02:00:00:00:00:09"})


class StateTests(unittest.TestCase):
    def setUp(self):
        import os, tempfile
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "arpwatchdog.state.json")
        self.addCleanup(self.dir.cleanup)

    def test_state_round_trip(self):
        save_state(self.path, {"192.0.2.10": "02:00:00:00:00:01"}, gateways=["192.0.2.1"])
        entries, gateways, problems = load_state(self.path)
        self.assertEqual(problems, [])
        self.assertEqual(entries, {"192.0.2.10": "02:00:00:00:00:01"})
        self.assertEqual(gateways, ["192.0.2.1"])

    def test_missing_state_is_empty(self):
        entries, gateways, problems = load_state(self.path)
        self.assertEqual((entries, gateways, problems), ({}, [], []))

    def test_corrupt_state_reports_problem(self):
        with open(self.path, "w") as handle:
            handle.write("{not json")
        entries, gateways, problems = load_state(self.path)
        self.assertEqual((entries, gateways), ({}, []))
        self.assertEqual(len(problems), 1)

    def test_save_is_atomic_no_tmp_left_behind(self):
        import os
        save_state(self.path, {})
        self.assertFalse(os.path.exists(self.path + ".tmp"))
        self.assertTrue(os.path.exists(self.path))


class ScapySourceTests(unittest.TestCase):
    def build_packet(self, sender_mac, sender_ip, target_ip="192.0.2.1", gratuitous=False):
        from scapy.layers.l2 import ARP, Ether
        if gratuitous:
            target_ip = sender_ip
        return Ether(src=sender_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, hwsrc=sender_mac, psrc=sender_ip, pdst=target_ip,
        )

    def test_converts_reply_packet(self):
        packet = self.build_packet("02:00:00:00:00:01", "192.0.2.10")
        item = observation_from_scapy_packet(packet, "eth0")
        self.assertIsNotNone(item)
        self.assertEqual(item.ip, "192.0.2.10")
        self.assertEqual(item.mac, "02:00:00:00:00:01")
        self.assertEqual(item.kind, "arp_reply")

    def test_converts_gratuitous_packet(self):
        packet = self.build_packet("02:00:00:00:00:07", "192.0.2.7", gratuitous=True)
        item = observation_from_scapy_packet(packet, "eth0")
        self.assertEqual(item.kind, "gratuitous_arp")

    def test_filters_probes_and_non_arp(self):
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether
        self.assertIsNone(observation_from_scapy_packet(
            self.build_packet("02:00:00:00:00:01", "0.0.0.0"), "eth0"
        ))
        tcp_packet = Ether() / IP(src="192.0.2.10", dst="192.0.2.1") / TCP()
        self.assertIsNone(observation_from_scapy_packet(tcp_packet, "eth0"))

    def test_scapy_source_requires_interface(self):
        with self.assertRaises(ValueError):
            ScapySource("")


class CliTests(unittest.TestCase):
    MAC_A = "02:00:00:00:00:01"
    MAC_B = "02:00:00:00:00:02"

    def setUp(self):
        import io
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        self._saved = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = self.stdout, self.stderr
        self.addCleanup(self._restore)

    def _restore(self):
        sys.stdout, sys.stderr = self._saved

    @staticmethod
    def record(interface, ts, mac, ip):
        frame = arp_frame(mac, ip)
        import json as _json
        return _json.dumps({
            "interface": interface, "timestamp": ts,
            "frame_hex": frame.hex(),
        })

    def run_cli(self, argv, records):
        import io as _io
        stream = _io.StringIO("\n".join(records) + "\n")
        self.stdout.seek(0)
        self.stdout.truncate(0)
        self.stderr.seek(0)
        self.stderr.truncate(0)
        code = main_with_streams(argv, stream)
        return code, self.stdout.getvalue(), self.stderr.getvalue()

    def test_replay_emits_json_events(self):
        records = [
            self.record("eth0", 1, self.MAC_A, "192.0.2.10"),
            self.record("eth0", 2, self.MAC_B, "192.0.2.10"),
        ]
        code, out, err = self.run_cli(["--no-suppress"], records)
        self.assertEqual(code, 0)
        events = [json.loads(line) for line in out.strip().splitlines()]
        self.assertEqual([e["event"] for e in events], ["new_host", "mapping_changed"])

    def test_ignore_cidr_suppresses_events(self):
        records = [
            self.record("eth0", 1, self.MAC_A, "192.0.2.10"),
            self.record("eth0", 2, self.MAC_B, "192.0.2.10"),
        ]
        code, out, _err = self.run_cli(["--ignore", "192.0.2.0/24"], records)
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "")

    def test_suppression_deduplicates_repeats(self):
        records = [
            self.record("eth0", 1, self.MAC_A, "192.0.2.10"),
            self.record("eth0", 2, self.MAC_B, "192.0.2.10"),
            self.record("eth0", 3, self.MAC_A, "192.0.2.10"),
            self.record("eth0", 4, self.MAC_B, "192.0.2.10"),
        ]
        code, out, _err = self.run_cli(["--suppress-window", "600"], records)
        events = [json.loads(line) for line in out.strip().splitlines()]
        self.assertEqual([e["event"] for e in events], ["new_host", "mapping_changed"])

    def test_list_prints_learned_table(self):
        records = [self.record("eth0", 1, self.MAC_A, "192.0.2.10")]
        code, out, _err = self.run_cli(["--no-new-hosts", "--list"], records)
        self.assertIn("02:00:00:00:00:01  192.0.2.10", out)

    def test_state_round_trip_through_cli(self):
        import os, tempfile
        workdir = tempfile.TemporaryDirectory()
        self.addCleanup(workdir.cleanup)
        state_path = os.path.join(workdir.name, "state.json")
        records = [self.record("eth0", 1, self.MAC_A, "192.0.2.30")]
        self.run_cli(["--state", state_path], records)
        first, _gateways, _problems = load_state(state_path)
        self.assertEqual(first, {"192.0.2.30": self.MAC_A})
        # A second run over the same address must not emit new_host again.
        records = [self.record("eth0", 2, self.MAC_A, "192.0.2.30")]
        code, out, _err = self.run_cli(["--state", state_path], records)
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "")

    def test_missing_replay_file_returns_two(self):
        code, _out, err = self.run_cli(["--replay", "/nonexistent/file.jsonl"], [])
        self.assertEqual(code, 2)
        self.assertIn("cannot open replay file", err)

    def test_gateway_flag_raises_gateway_event(self):
        records = [
            self.record("eth0", 1, self.MAC_A, "192.0.2.1"),
            self.record("eth0", 2, self.MAC_B, "192.0.2.1"),
        ]
        code, out, _err = self.run_cli(["--gateway", "192.0.2.1"], records)
        events = [json.loads(line) for line in out.strip().splitlines()]
        self.assertEqual(events[-1]["event"], "gateway_mac_changed")


def main_with_streams(argv, stream):
    """Run main() with a substituted stdin stream for replay tests."""
    saved = sys.stdin
    sys.stdin = stream
    try:
        return main(argv)
    finally:
        sys.stdin = saved


class OutputFormatTests(unittest.TestCase):
    def test_text_includes_time_kind_and_assessment(self):
        event = {
            "event": "gateway_mac_changed", "ip": "192.0.2.1",
            "previous_mac": "02:00:00:00:00:01", "current_mac": "02:00:00:00:00:02",
            "interface": "eth0", "observed_at": "2024-10-27T03:33:20.500Z",
            "assessment": "a gateway MAC change is the classic ARP spoofing indicator",
        }
        line = format_event_text(event)
        self.assertIn("GATEWAY_MAC_CHANGED", line)
        self.assertIn("ip=192.0.2.1", line)
        self.assertIn("was=02:00:00:00:00:01", line)
        self.assertIn("now=02:00:00:00:00:02", line)
        self.assertIn("2024-10-27T03:33:20.500Z", line)

    def test_csv_has_fixed_columns_and_quoting(self):
        event = {"event": "mapping_changed", "ip": "192.0.2.1",
                 "current_mac": "02:00:00:00:00:02", "observed_at": "x"}
        self.assertEqual(format_event_csv(event),
                         "mapping_changed,192.0.2.1,,,02:00:00:00:00:02,,x")

    def test_make_sink_writes_to_stream(self):
        import io as _io
        stream = _io.StringIO()
        sink = make_sink("json", stream)
        sink({"event": "new_host", "ip": "192.0.2.9"})
        parsed = json.loads(stream.getvalue())
        self.assertEqual(parsed["event"], "new_host")

    def test_unknown_format_rejected(self):
        with self.assertRaises(ValueError):
            make_sink("yaml")


if __name__ == "__main__":
    unittest.main()
