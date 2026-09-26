#!/usr/bin/env python3
"""
SecurePi Gateway - inspection gate tests (ENHANCEMENT-PLAN.md step 7.7,
"inspection must fail open").

The probe is tested against real sockets on 127.0.0.1 - a listener that
closes every connection at once (what a healthy transparent-mode proxy
does with a direct connection), a port nothing listens on, and a
listener that never accepts (a hung proxy: the kernel still completes
the TCP handshake, but nobody reads). The nft side is only tested
through its pure argv/JSON helpers, the same reason dns_failopen and
securepi-web-helper split theirs out: there is no nftables on the Mac.

Run via `make test`, or directly: python3 -m unittest tests.test_dpi_gate -v
"""

import os
import socket
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

import dpi_gate  # noqa: E402
import health  # noqa: E402


def _listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    return srv


class ProbeTests(unittest.TestCase):
    def test_a_proxy_that_closes_at_once_is_answering(self):
        srv = _listener()

        def close_everything():
            conn, _ = srv.accept()
            conn.close()
        threading.Thread(target=close_everything, daemon=True).start()
        try:
            self.assertEqual(dpi_gate.probe(srv.getsockname(), timeout=2), dpi_gate.ANSWERING)
        finally:
            srv.close()

    def test_nothing_listening_is_refused(self):
        srv = _listener()
        addr = srv.getsockname()
        srv.close()
        self.assertEqual(dpi_gate.probe(addr, timeout=2), dpi_gate.REFUSED)

    def test_a_listener_that_never_reads_is_silent(self):
        srv = _listener()   # listening, but accept() is never called
        try:
            started = time.time()
            self.assertEqual(dpi_gate.probe(srv.getsockname(), timeout=0.5), dpi_gate.SILENT)
            self.assertLess(time.time() - started, 3)
        finally:
            srv.close()


class NftHelperTests(unittest.TestCase):
    def test_open_and_close_touch_only_the_gate_set(self):
        self.assertEqual(dpi_gate._gate_argv("open"),
                         ["add", "element", "ip", "nat", "dpi_up", '{ "ap0" }'])
        self.assertEqual(dpi_gate._gate_argv("close"),
                         ["delete", "element", "ip", "nat", "dpi_up", '{ "ap0" }'])

    def test_unknown_verb_is_refused(self):
        with self.assertRaises(ValueError):
            dpi_gate._gate_argv("flush")

    def test_elements_parsed_from_nft_json(self):
        full = ('{"nftables": [{"metainfo": {}}, {"set": {"family": "ip", "name": "dpi_up",'
                ' "table": "nat", "type": "ifname", "handle": 9, "elem": ["ap0"]}}]}')
        empty = ('{"nftables": [{"metainfo": {}}, {"set": {"family": "ip", "name": "dpi_up",'
                 ' "table": "nat", "type": "ifname", "handle": 9}}]}')
        self.assertEqual(dpi_gate._elements_from_json(full), ["ap0"])
        self.assertEqual(dpi_gate._elements_from_json(empty), [])


class CheckDpiProxyTests(unittest.TestCase):
    """health.check_dpi_proxy's decisions, with systemctl, the probe and
    the gate replaced by stand-ins that record what was done."""

    def setUp(self):
        self._saved = (health._is_active, dpi_gate.probe, dpi_gate.is_open,
                       dpi_gate.open_gate, dpi_gate.close_gate)
        self.gate = {"open": True}
        self.actions = []
        dpi_gate.is_open = lambda: self.gate["open"]
        dpi_gate.open_gate = lambda: (self.actions.append("open"), self.gate.update(open=True))
        dpi_gate.close_gate = lambda: (self.actions.append("close"), self.gate.update(open=False))

    def tearDown(self):
        (health._is_active, dpi_gate.probe, dpi_gate.is_open,
         dpi_gate.open_gate, dpi_gate.close_gate) = self._saved

    def _incidents(self, conn):
        return conn.execute(
            "SELECT * FROM incidents WHERE signal_type='platform_dpi_unresponsive'").fetchall()

    def test_healthy_proxy_with_open_gate_changes_nothing(self):
        conn = fixtures.temp_db()
        health._is_active = lambda s: True
        dpi_gate.probe = lambda: dpi_gate.ANSWERING
        health.check_dpi_proxy(conn, time.time())
        self.assertEqual(self.actions, [])
        self.assertEqual(len(self._incidents(conn)), 0)

    def test_hung_proxy_closes_the_gate_and_raises_an_incident(self):
        conn = fixtures.temp_db()
        health._is_active = lambda s: True
        dpi_gate.probe = lambda: dpi_gate.SILENT
        health.check_dpi_proxy(conn, time.time())
        self.assertEqual(self.actions, ["close"])
        rows = self._incidents(conn)
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["device_id"])

    def test_one_slow_probe_is_retried_before_bypassing(self):
        conn = fixtures.temp_db()
        health._is_active = lambda s: True
        answers = iter([dpi_gate.SILENT, dpi_gate.ANSWERING])
        dpi_gate.probe = lambda: next(answers)
        health.check_dpi_proxy(conn, time.time())
        self.assertEqual(self.actions, [])
        self.assertEqual(len(self._incidents(conn)), 0)

    def test_gate_reopens_once_the_proxy_answers_again(self):
        conn = fixtures.temp_db()
        self.gate["open"] = False
        health._is_active = lambda s: True
        dpi_gate.probe = lambda: dpi_gate.ANSWERING
        health.check_dpi_proxy(conn, time.time())
        self.assertEqual(self.actions, ["open"])

    def test_stopped_proxy_leaves_the_gate_closed_without_probing(self):
        conn = fixtures.temp_db()
        health._is_active = lambda s: False
        dpi_gate.probe = lambda: self.fail("a stopped proxy must not be probed")
        health.check_dpi_proxy(conn, time.time())
        self.assertEqual(self.actions, ["close"])
        # "Service not running" is check_services' incident, not this one.
        self.assertEqual(len(self._incidents(conn)), 0)

    def test_unknown_systemctl_state_does_nothing(self):
        conn = fixtures.temp_db()
        health._is_active = lambda s: None
        dpi_gate.probe = lambda: self.fail("must not probe when systemctl couldn't be asked")
        health.check_dpi_proxy(conn, time.time())
        self.assertEqual(self.actions, [])


if __name__ == "__main__":
    unittest.main()
