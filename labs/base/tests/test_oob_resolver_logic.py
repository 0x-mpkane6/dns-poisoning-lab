"""Unit tests for the OoB resolver logic.

Runs without Docker. Imports the resolver module from the OoB lab and exercises
its bailiwick-checking helpers and end-to-end record filtering. We rely only on
``dnslib`` (already a runtime dep of the lab) and ``unittest``.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path

from dnslib import A, DNSHeader, DNSRecord, DNSQuestion, NS, QTYPE, RR


HERE = Path(__file__).resolve().parent
RESOLVER_PATH = HERE.parent.parent / "oob" / "resolver" / "resolver.py"


def _load_resolver_module():
    spec = importlib.util.spec_from_file_location("oob_resolver", str(RESOLVER_PATH))
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class BailiwickTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_resolver_module()

    def test_zone_inference(self):
        self.assertEqual(self.mod.zone_from_qname("a.b.example.net."), "example.net")
        self.assertEqual(self.mod.zone_from_qname("EXAMPLE.NET"), "example.net")
        self.assertEqual(self.mod.zone_from_qname("bank.com"), "bank.com")

    def test_in_bailiwick(self):
        self.assertTrue(self.mod.is_within_bailiwick("victim.example.net.", "victim.example.net."))
        self.assertTrue(self.mod.is_within_bailiwick("ns1.example.net.", "victim.example.net."))
        self.assertTrue(self.mod.is_within_bailiwick("example.net.", "victim.example.net."))

    def test_out_of_bailiwick(self):
        self.assertFalse(self.mod.is_within_bailiwick("bank.com.", "victim.example.net."))
        self.assertFalse(self.mod.is_within_bailiwick("evil.com.", "victim.example.net."))
        self.assertFalse(self.mod.is_within_bailiwick("evilbank.com.", "victim.example.net."))


class ExtractRecordsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_resolver_module()

    def _make_response(self):
        request = DNSRecord.question("victim.example.net", "A")
        header = DNSHeader(id=request.header.id, qr=1, aa=1, ra=0, rd=1)
        response = DNSRecord(header, q=request.q)
        response.add_answer(RR("victim.example.net.", QTYPE.A, ttl=60, rdata=A("198.51.100.10")))
        response.add_auth(RR("example.net.", QTYPE.NS, ttl=300, rdata=NS("ns1.example.net.")))
        response.add_ar(RR("ns1.example.net.", QTYPE.A, ttl=300, rdata=A("10.20.0.100")))
        # Inject OoB poison in additional section.
        response.add_ar(RR("bank.com.", QTYPE.A, ttl=300, rdata=A("6.6.6.6")))
        return response

    def test_extract_named_records_includes_section(self):
        records = self.mod.extract_named_records(self._make_response())
        names = {(name, ip, section) for name, ip, _, section in records}
        self.assertIn(("victim.example.net", "198.51.100.10", "AN"), names)
        self.assertIn(("ns1.example.net", "10.20.0.100", "AR"), names)
        self.assertIn(("bank.com", "6.6.6.6", "AR"), names)


class FilteringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_resolver_module()

    def test_offenders_detected(self):
        offenders = []
        for rrname, ip, _ttl, section in [
            ("victim.example.net", "198.51.100.10", 60, "AN"),
            ("ns1.example.net", "10.20.0.100", 300, "AR"),
            ("bank.com", "6.6.6.6", 300, "AR"),
            ("evilbank.com", "9.9.9.9", 300, "AU"),
        ]:
            if not self.mod.is_within_bailiwick(rrname, "victim.example.net"):
                offenders.append((rrname, ip, section))
        self.assertEqual(len(offenders), 2)
        offender_names = {row[0] for row in offenders}
        self.assertEqual(offender_names, {"bank.com", "evilbank.com"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
