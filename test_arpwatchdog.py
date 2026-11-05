import unittest

from arpwatchdog import Observation, Tracker, parse_frame


def arp_frame(sender_mac, sender_ip, vlan=False):
    mac = bytes.fromhex(sender_mac.replace(":", ""))
    ip = bytes(int(part) for part in sender_ip.split("."))
    ethernet = b"\x00" * 6 + b"\x00" * 6
    if vlan:
        ethernet += b"\x81\x00\x00\x07\x08\x06"
    else:
        ethernet += b"\x08\x06"
    payload = (
        b"\x00\x01" + b"\x08\x00" + b"\x06\x04" + b"\x00\x02"
        + mac + ip + b"\x00" * 6 + bytes((192, 0, 2, 1))
    )
    return ethernet + payload


class ArpParserTests(unittest.TestCase):
    def test_parses_ipv4_arp_reply(self):
        item = parse_frame(
            arp_frame("02:00:00:00:00:01", "192.0.2.10"),
            "eth0", 10.0,
        )
        self.assertEqual(item, Observation("eth0", 10.0, "192.0.2.10", "02:00:00:00:00:01"))

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


class TrackerTests(unittest.TestCase):
    def test_only_emits_an_event_when_a_mac_changes(self):
        tracker = Tracker()
        first = Observation("eth0", 1, "192.0.2.10", "02:00:00:00:00:01")
        same = Observation("eth0", 2, "192.0.2.10", "02:00:00:00:00:01")
        changed = Observation("wlan0", 3, "192.0.2.10", "02:00:00:00:00:02")
        self.assertIsNone(tracker.observe(first))
        self.assertIsNone(tracker.observe(same))
        event = tracker.observe(changed)
        self.assertEqual(event["event"], "mapping_changed")
        self.assertEqual(event["previous_interface"], "eth0")
        self.assertIn("not proof", event["assessment"])

    def test_history_is_bounded(self):
        tracker = Tracker(max_entries=2)
        for index in range(3):
            tracker.observe(Observation("eth0", index, f"192.0.2.{index + 1}", "02:00:00:00:00:01"))
        self.assertEqual(len(tracker._seen), 2)


if __name__ == "__main__":
    unittest.main()
