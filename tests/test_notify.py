#!/usr/bin/env python3
"""
SecurePi Gateway - notification tests (ENHANCEMENT-PLAN.md step 4.5).

dispatch() runs against a real temp database with a fake sender that
records what would have been sent, so every rule (one per incident,
severity threshold, rate limit, quiet hours, digest, retry) is checked
without any network. build_request() is checked separately for the exact
HTTP request each channel type sends.

Run via `make test`, or directly: python3 -m unittest tests.test_notify -v
"""

import hashlib
import hmac
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

import notify  # noqa: E402
import settings  # noqa: E402

WEBHOOK = {"url": "http://192.0.2.10/hook", "secret": "s3cret-signing-key"}


class FakeSender:
    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail

    def __call__(self, kind, config, title, body, severity, event):
        if self.fail:
            raise notify.NotifyError("connection refused")
        self.sent.append({"kind": kind, "title": title, "body": body, "severity": severity, "event": event})


def add_incident(conn, severity="high", title="Port scan from kali", device_id=None, ts=None):
    ts = ts or time.time()
    cur = conn.execute(
        "INSERT INTO incidents (device_id, signal_type, severity, title, description, status, first_seen,"
        " last_seen, created_at, updated_at) VALUES (?, 'port_scan', ?, ?, 'touched 40 ports on 10.10.0.5',"
        " 'new', ?, ?, ?, ?)", (device_id, severity, title, ts, ts, ts, ts))
    conn.commit()
    return cur.lastrowid


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.conn = fixtures.temp_db()
        self.now = time.mktime((2026, 9, 26, 12, 0, 0, 0, 0, -1))
        self.ch = notify.add_channel(self.conn, "webhook", "Lab webhook", dict(WEBHOOK), "medium", now=self.now)
        notify.dispatch(self.conn, now=self.now, sender=FakeSender())  # first run sets the starting point

    def test_history_is_not_sent_when_a_channel_is_first_added(self):
        conn = fixtures.temp_db()
        add_incident(conn)
        notify.add_channel(conn, "webhook", "w", dict(WEBHOOK), now=self.now)
        s = FakeSender()
        notify.dispatch(conn, now=self.now, sender=s)
        self.assertEqual(s.sent, [])

    def test_one_notification_per_incident_not_one_per_cycle(self):
        iid = add_incident(self.conn)
        s = FakeSender()
        for i in range(5):
            # the signal keeps extending the same incident every cycle
            self.conn.execute("UPDATE incidents SET last_seen=?, updated_at=? WHERE id=?",
                              (self.now + i, self.now + i, iid))
            notify.dispatch(self.conn, now=self.now + i * 15, sender=s)
        self.assertEqual(len(s.sent), 1)
        self.assertIn("[HIGH] Port scan from kali", s.sent[0]["title"])

    def test_below_threshold_is_not_sent(self):
        add_incident(self.conn, severity="low")
        s = FakeSender()
        notify.dispatch(self.conn, now=self.now, sender=s)
        self.assertEqual(s.sent, [])

    def test_details_are_left_out_unless_the_channel_opts_in(self):
        add_incident(self.conn)
        s = FakeSender()
        notify.dispatch(self.conn, now=self.now, sender=s)
        self.assertNotIn("10.10.0.5", s.sent[0]["body"])
        self.assertIn("/incidents/", s.sent[0]["body"])

    def test_rate_limit_holds_the_overflow_for_the_digest(self):
        settings.set_value(self.conn, "notify_rate_limit_per_hour", 2)
        for i in range(5):
            add_incident(self.conn, title="incident %d" % i)
        s = FakeSender()
        out = notify.dispatch(self.conn, now=self.now, sender=s)
        self.assertEqual(out["sent"], 2)
        self.assertEqual(out["held"], 3)
        self.assertEqual(out["digests"], 1)       # sent straight away: no digest sent before
        digest = s.sent[-1]
        self.assertIn("digest: 3 incidents", digest["title"])
        statuses = [r[0] for r in self.conn.execute("SELECT status FROM notifications WHERE incident_id IS NOT NULL")]
        self.assertEqual(sorted(statuses), ["digested"] * 3 + ["sent"] * 2)

    def test_quiet_hours_hold_medium_but_send_high(self):
        settings.set_value(self.conn, "notify_quiet_hours_enabled", True)
        night = time.mktime((2026, 9, 26, 23, 30, 0, 0, 0, -1))
        add_incident(self.conn, severity="medium", title="medium one")
        add_incident(self.conn, severity="high", title="high one")
        s = FakeSender()
        notify.dispatch(self.conn, now=night, sender=s)
        self.assertEqual([m["title"] for m in s.sent], ["[HIGH] high one"])  # no digest during quiet hours
        morning = time.mktime((2026, 9, 27, 7, 5, 0, 0, 0, -1))
        notify.dispatch(self.conn, now=morning, sender=s)
        self.assertIn("digest: 1 incident", s.sent[-1]["title"])

    def test_a_failed_send_is_retried_and_recorded(self):
        add_incident(self.conn)
        notify.dispatch(self.conn, now=self.now, sender=FakeSender(fail=True))
        ch = self.conn.execute("SELECT last_error FROM notification_channels WHERE id=?", (self.ch,)).fetchone()
        self.assertIn("connection refused", ch["last_error"])
        s = FakeSender()
        notify.dispatch(self.conn, now=self.now + 60, sender=s)
        self.assertEqual(len(s.sent), 1)

    def test_disabled_channel_sends_nothing(self):
        notify.update_channel(self.conn, self.ch, enabled=False)
        add_incident(self.conn)
        s = FakeSender()
        notify.dispatch(self.conn, now=self.now, sender=s)
        self.assertEqual(s.sent, [])


class ChannelValidationTests(unittest.TestCase):
    def test_secrets_are_never_returned(self):
        conn = fixtures.temp_db()
        notify.add_channel(conn, "telegram", "phone", {"bot_token": "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw",
                                                       "chat_id": "42"})
        ch = notify.list_channels(conn)[0]
        self.assertNotIn("AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", json.dumps(ch))
        self.assertTrue(ch["config"]["bot_token"].endswith("Dsaw"))

    def test_bad_settings_are_refused_with_a_reason(self):
        bad = [
            ("ntfy", {"server": "ftp://x", "topic": "t"}),
            ("ntfy", {"server": "https://ntfy.sh", "topic": "has space"}),
            ("telegram", {"bot_token": "nope", "chat_id": "1"}),
            ("email", {"host": "smtp.x", "port": "99999", "security": "starttls", "sender": "a@b.c", "recipient": "d@e.f"}),
            ("email", {"host": "smtp.x", "port": 587, "security": "tls", "sender": "a@b.c", "recipient": "d@e.f"}),
            ("webhook", {"url": "javascript:alert(1)"}),
            ("pigeon", {}),
        ]
        for kind, cfg in bad:
            with self.assertRaises(notify.NotifyError, msg=(kind, cfg)):
                notify.validate_channel(kind, cfg)


class RequestShapeTests(unittest.TestCase):
    def test_webhook_is_signed_with_hmac_sha256(self):
        url, raw, headers = notify.build_request("webhook", WEBHOOK, "t", "b", "high", {"type": "test"})
        expected = hmac.new(WEBHOOK["secret"].encode(), raw, hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-SecurePi-Signature"], "sha256=" + expected)
        self.assertEqual(json.loads(raw)["severity"], "high")

    def test_ntfy_publishes_json_to_the_server_root(self):
        url, raw, headers = notify.build_request("ntfy", {"server": "https://ntfy.sh", "topic": "sp-lab", "token": "tk"},
                                                 "t", "b", "high", None)
        self.assertEqual(url, "https://ntfy.sh")
        body = json.loads(raw)
        self.assertEqual((body["topic"], body["priority"]), ("sp-lab", 5))
        self.assertEqual(headers["Authorization"], "Bearer tk")

    def test_telegram_uses_the_bot_api(self):
        url, raw, _ = notify.build_request("telegram", {"bot_token": "1:abc", "chat_id": "42"}, "t", "b", "low", None)
        self.assertEqual(url, "https://api.telegram.org/bot1:abc/sendMessage")
        self.assertEqual(json.loads(raw)["chat_id"], "42")

    def test_email_message(self):
        msg = notify.build_email({"sender": "gw@example.com", "recipient": "me@example.com"}, "Subject here", "Body")
        self.assertEqual(msg["Subject"], "Subject here")
        self.assertIn("Body", msg.get_content())


if __name__ == "__main__":
    unittest.main()
