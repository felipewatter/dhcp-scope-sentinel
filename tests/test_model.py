from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from dhcp_scope_sentinel.model import parse
from dhcp_scope_sentinel.parse import InputError, load

BASE = json.loads((Path(__file__).resolve().parents[1] / "examples/baseline.json").read_text())


class SnapshotSchemaTests(unittest.TestCase):
    def mutate(self, edit):
        value = copy.deepcopy(BASE)
        edit(value)
        return parse(value)

    def test_valid_example(self):
        snap = parse(BASE)
        self.assertEqual(len(snap.segments), 1)
        self.assertEqual(len(snap.segments[0].scopes), 2)
        self.assertEqual(len(snap.offers), 1)

    def test_input_immutable(self):
        before = copy.deepcopy(BASE)
        parse(BASE)
        self.assertEqual(BASE, before)

    def test_missing_schema(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x.pop("schema_version"))

    def test_unsupported_schema(self):
        for bad in (0, 2, "1", True, 1.0):
            with self.subTest(bad=bad), self.assertRaises(InputError):
                self.mutate(lambda x: x.__setitem__("schema_version", bad))

    def test_extra_root_key(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x.__setitem__("token", "secret"))

    def test_empty_segments(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x.__setitem__("segments", []))

    def test_bad_root_type(self):
        for bad in ([], None, "hello", 2):
            with self.subTest(bad=bad), self.assertRaises(InputError):
                parse(bad)

    def test_duplicate_segment_ids(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x["segments"].append(copy.deepcopy(x["segments"][0])))

    def test_duplicate_scope_ids(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x["segments"][0]["scopes"][1].__setitem__("id", "LAB-PRIMARY"))

    def test_duplicate_authorized_servers(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x["segments"][0]["authorized_servers"].append("10.20.0.2"))

    def test_empty_authorization(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x["segments"][0].__setitem__("authorized_servers", []))

    def test_duplicate_relay_ids(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x["segments"][0]["trusted_relays"].append("relay-campus-120"))

    def test_relay_requires_trust_list(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x["segments"][0].__setitem__("trusted_relays", []))

    def test_relay_type(self):
        for bad in ("yes", 1, [], None):
            with self.subTest(bad=bad), self.assertRaises(InputError):
                self.mutate(lambda x: x["segments"][0].__setitem__("require_relay", bad))

    def test_noncanonical_ipv4(self):
        for bad in ("10.020.120.1", "2001:db8::1", "999.1.1.1", "0.0.0.0", None):
            with self.subTest(bad=bad), self.assertRaises(InputError):
                self.mutate(lambda x: x["segments"][0].__setitem__("gateway", bad))

    def test_invalid_cidr(self):
        for bad in ("10.20.120.1/24", "10.20.120.0/31", "2001:db8::/64", "10.20.120.0/33"):
            with self.subTest(bad=bad), self.assertRaises(InputError):
                self.mutate(lambda x: x["segments"][0].__setitem__("network", bad))

    def test_bad_vlan(self):
        for bad in (0, 4095, -1, True, "120", 12.0):
            with self.subTest(bad=bad), self.assertRaises(InputError):
                self.mutate(lambda x: x["segments"][0].__setitem__("vlan", bad))

    def test_gateway_not_host(self):
        for bad in ("10.20.120.0", "10.20.120.255", "10.10.10.1"):
            with self.subTest(bad=bad), self.assertRaises(InputError):
                self.mutate(lambda x: x["segments"][0].__setitem__("gateway", bad))

    def test_invalid_pool_reverse(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x["segments"][0]["scopes"][0]["pools"].__setitem__(0, ["10.20.120.180", "10.20.120.100"]))

    def test_pool_outside_subnet(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x["segments"][0]["scopes"][0]["pools"].__setitem__(0, ["10.20.121.100", "10.20.121.180"]))

    def test_pool_no_reserved_boundary(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x["segments"][0]["scopes"][0]["pools"].__setitem__(0, ["10.20.120.0", "10.20.120.180"]))

    def test_invalid_exclusion(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x["segments"][0]["scopes"][0]["exclusions"].__setitem__(0, ["10.20.120.254", "10.20.120.4"]))

    def test_invalid_reservation(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x["segments"][0]["scopes"][0]["reservations"][0].__setitem__("ip", "10.20.121.8"))

    def test_scope_requires_capacity(self):
        def edit(x):
            s = x["segments"][0]["scopes"][0]
            s["pools"] = []
            s["reservations"] = []
        with self.assertRaises(InputError):
            self.mutate(edit)

    def test_bad_failover_group(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x["segments"][0]["scopes"][0].__setitem__("failover_group", "../x"))

    def test_bad_host_name(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x["segments"][0]["static_hosts"][0].__setitem__("asset", "hello world"))

    def test_duplicate_static_host(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x["segments"][0]["static_hosts"].append(copy.deepcopy(x["segments"][0]["static_hosts"][0])))

    def test_observation_references_existing_segment(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x["observations"][0].__setitem__("segment", "NOT-EXISTS"))

    def test_observation_rejects_unknown_key(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x["observations"][0].__setitem__("opaque", "raw"))

    def test_observation_missing_client(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x["observations"][0].pop("client_id"))

    def test_invalid_dns_array(self):
        with self.assertRaises(InputError):
            self.mutate(lambda x: x["segments"][0].__setitem__("dns_servers", "10.1.1.1"))

    def test_missing_optional_fields(self):
        def edit(x):
            seg = x["segments"][0]
            for key in ("trusted_relays", "require_relay", "static_hosts"):
                seg.pop(key)
            x.pop("observations")
        snap = self.mutate(edit)
        self.assertFalse(snap.segments[0].require_relay)
        self.assertEqual(snap.offers, ())


class ParsingSafetyTests(unittest.TestCase):
    def test_duplicate_json_keys(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "duplicate.json"
            target.write_text('{"schema_version":1,"schema_version":2}', encoding="utf-8")
            with self.assertRaises(InputError):
                load(target)

    def test_nan_and_infinity(self):
        import tempfile
        for bad in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as tmp:
                target = Path(tmp) / "bad.json"
                target.write_text('{"x":' + bad + '}', encoding="utf-8")
                with self.assertRaises(InputError):
                    load(target)

    def test_symlink_input(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real.json"
            real.write_text("{}")
            symlink = Path(tmp) / "link.json"
            try:
                symlink.symlink_to(real)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not permitted on this OS")
            with self.assertRaises(InputError):
                load(symlink)

    def test_missing_file(self):
        with self.assertRaises(InputError):
            load(Path("this-file-does-not-exist-certainly-31337.json"))

    def test_large_input(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "huge.json"
            target.write_text('{"s":"' + ('x' * 2_000_000) + '"}')
            with self.assertRaises(InputError):
                load(target)

    def test_deep_json(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "deep.json"
            target.write_text('{"x":' + '['*35 + '0' + ']'*35 + '}')
            with self.assertRaises(InputError):
                load(target)

    def test_extremely_nested_json_fails_closed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "recursive.json"
            target.write_text('{"x":' + '[' * 2000 + '0' + ']' * 2000 + '}')
            with self.assertRaises(InputError):
                load(target)

    def test_valid_bom(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "bom.json"
            target.write_bytes(b'\xef\xbb\xbf{}')
            self.assertEqual(load(target), {})

    def test_invalid_utf8(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "bad.json"
            target.write_bytes(b'\xff\xff\xff')
            with self.assertRaises(InputError):
                load(target)
