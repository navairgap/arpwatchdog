import unittest

from arpwatchdog import (
    SCHEMA_VERSION,
    Observation,
    Tracker,
    canonical_ip,
    canonical_mac,
    detect_default_gateways,
    parse_frame,
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


if __name__ == "__main__":
    unittest.main()
