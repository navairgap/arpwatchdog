import unittest

from arpwatchdog import (
    SCHEMA_VERSION,
    Observation,
    Tracker,
    canonical_ip,
    canonical_mac,
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


if __name__ == "__main__":
    unittest.main()
