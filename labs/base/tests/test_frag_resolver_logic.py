"""Unit tests for the fragmentation lab resolver logic (sfrag/bfrag).

These tests cover the IPID parsing, FRAG1/FRAG2 marker detection, and Frag2Store
behavior of the SFrag resolver. The BFrag resolver implements the same helpers,
so we exercise the SFrag copy as the canonical reference.
"""

from __future__ import annotations

import importlib.util
import time
import unittest
from pathlib import Path

from dnslib import A, DNSHeader, DNSRecord, QTYPE, RR, TXT


HERE = Path(__file__).resolve().parent
RESOLVER_PATH = HERE.parent.parent / "sfrag" / "resolver" / "resolver.py"


def _load_resolver_module():
    spec = importlib.util.spec_from_file_location("sfrag_resolver", str(RESOLVER_PATH))
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class HelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_resolver_module()

    def test_parse_ipid(self):
        self.assertEqual(self.mod.parse_ipid(["TYPE=FRAG1;IPID=42"]), 42)
        self.assertEqual(self.mod.parse_ipid(["TYPE=FRAG2;IPID=777"]), 777)
        self.assertIsNone(self.mod.parse_ipid(["random text"]))

    def test_marker_detection(self):
        self.assertTrue(self.mod.is_frag1_marker(["TYPE=FRAG1;IPID=10"]))
        self.assertTrue(self.mod.is_frag2_marker("_frag2.example.net.", []))
        self.assertTrue(self.mod.is_frag2_marker("foo.example.net.", ["TYPE=FRAG2;IPID=10"]))
        self.assertFalse(self.mod.is_frag2_marker("foo.example.net.", ["TYPE=FRAG1;IPID=10"]))


class Frag2StoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_resolver_module()

    def test_put_and_get(self):
        store = self.mod.Frag2Store()
        store.put(123, "bank.com", "6.6.6.6", 300)
        self.assertEqual(store.get(123), ("bank.com", "6.6.6.6", 300))
        self.assertIsNone(store.get(999))

    def test_expiry(self):
        # Force the store TTL to a very small value to test expiration.
        original = self.mod.FRAG2_KEEP_SECONDS
        self.mod.FRAG2_KEEP_SECONDS = 0.05
        try:
            store = self.mod.Frag2Store()
            store.put(7, "bank.com", "6.6.6.6", 300)
            time.sleep(0.1)
            self.assertIsNone(store.get(7))
        finally:
            self.mod.FRAG2_KEEP_SECONDS = original


class HandleFrag2PacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_resolver_module()

    def _build_attacker_packet(self, ipid: int) -> DNSRecord:
        # Mimic what the spoof_sfrag.py attacker emits.
        request = DNSRecord.question("_frag2.example.net.", "TXT")
        header = DNSHeader(id=ipid, qr=1, aa=1, rd=1)
        response = DNSRecord(header, q=request.q)
        response.add_answer(RR("bank.com.", QTYPE.A, ttl=300, rdata=A("6.6.6.6")))
        response.add_ar(
            RR(
                "_fragmeta.example.net.",
                QTYPE.TXT,
                ttl=1,
                rdata=TXT(f"TYPE=FRAG2;IPID={ipid}"),
            )
        )
        return response

    def test_attacker_packet_captured(self):
        store = self.mod.Frag2Store()
        captured = self.mod.handle_frag2_packet(self._build_attacker_packet(42), store)
        self.assertTrue(captured)
        self.assertEqual(store.get(42), ("bank.com", "6.6.6.6", 300))


if __name__ == "__main__":
    unittest.main(verbosity=2)
