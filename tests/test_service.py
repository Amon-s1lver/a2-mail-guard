import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
from unittest.mock import patch

from mailguard.evaluate import load_suite, read_outbox
from mailguard.live import live_case
from mailguard.service import MailService, Mode


PRINCIPAL = "agent-a"
RECIPIENT = "supervisor@course.test"
REPORT = "report-q4"
PAYLOAD = {"recipient": RECIPIENT, "report_id": REPORT, "request_id": "first"}


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "mail.sqlite3"
        self.service = MailService(self.path, Mode.AUTHORIZATION, clock=lambda: 1000)

    def grant(self):
        self.service.grant(PRINCIPAL, RECIPIENT, REPORT)

    def test_missing_and_expired_grants_leave_outbox_empty(self):
        self.assertEqual(self.service.send(PRINCIPAL, PAYLOAD)[0], 403)
        self.service.grant(PRINCIPAL, RECIPIENT, REPORT, expires_at=1000)
        self.assertEqual(self.service.send(PRINCIPAL, PAYLOAD)[0], 403)
        self.assertEqual(read_outbox(self.path), [])

    def test_concurrent_retries_commit_only_one_row(self):
        self.grant()
        workers = 6
        start = Barrier(workers, timeout=5)

        def attempt(_):
            start.wait()
            return self.service.send(PRINCIPAL, PAYLOAD)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            responses = list(pool.map(attempt, range(workers)))
        self.assertCountEqual([status for status, _ in responses], [201] + [200] * (workers - 1))
        self.assertEqual({body["mail_id"] for _, body in responses}, {1})
        self.assertEqual(len(read_outbox(self.path)), 1)

    def test_revocation_and_send_serialize(self):
        self.grant()
        start = Barrier(2, timeout=5)

        def revoke():
            start.wait()
            self.service.revoke(PRINCIPAL, RECIPIENT, REPORT)

        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(revoke)
            start.wait()
            status, _ = self.service.send(PRINCIPAL, PAYLOAD)
            pending.result()

        self.assertIn(status, {201, 403})
        self.assertEqual(len(read_outbox(self.path)), int(status == 201))
        self.assertEqual(self.service.send(PRINCIPAL, {**PAYLOAD, "request_id": "second"})[0], 403)

    def test_identity_and_report_are_part_of_grant(self):
        self.grant()
        self.assertEqual(self.service.send("agent-b", PAYLOAD)[0], 403)
        self.assertEqual(self.service.send(PRINCIPAL, {**PAYLOAD, "report_id": "other"})[0], 403)
        self.assertEqual(read_outbox(self.path), [])

    def test_reusing_key_with_changed_action_preserves_original(self):
        self.grant()
        self.service.grant(PRINCIPAL, RECIPIENT, "other")
        self.assertEqual(self.service.send(PRINCIPAL, PAYLOAD)[0], 201)
        self.assertEqual(self.service.send(PRINCIPAL, {**PAYLOAD, "report_id": "other"})[0], 409)
        self.assertEqual([row["report_id"] for row in read_outbox(self.path)], [REPORT])

    def test_policy_store_failure_cannot_write_outbox(self):
        self.grant()
        with self.service.connection() as db:
            db.execute("DROP TABLE grants")
        with self.assertRaises(sqlite3.Error):
            self.service.send(PRINCIPAL, PAYLOAD)
        self.assertEqual(read_outbox(self.path), [])

    def test_schema_rejects_injected_sender_and_multiple_addresses(self):
        self.grant()
        for payload in (
            {**PAYLOAD, "principal": PRINCIPAL},
            {**PAYLOAD, "recipient": f"{RECIPIENT}, other@example.test"},
            {**PAYLOAD, "recipient": RECIPIENT + "\r\nBcc: other@example.test"},
        ):
            self.assertEqual(self.service.send(PRINCIPAL, payload)[0], 400)
        self.assertEqual(read_outbox(self.path), [])


class LiveTraceTests(unittest.TestCase):
    @patch("mailguard.live.propose")
    def test_model_cannot_supply_trusted_identity_or_default_missing_recipient(self, propose):
        propose.return_value = ("test-model", "", [
            {"function": {"name": "send_report", "arguments": {"report_id": REPORT, "principal": PRINCIPAL}}},
        ])
        case, trace = live_case(load_suite(), "normal", "test-model")
        self.assertEqual(trace["model"], "test-model")
        event = case["events"][0]
        self.assertNotIn("principal", event)
        self.assertIsNone(event["args"]["recipient"])
        self.assertIsNone(event["permitted_effect"])


if __name__ == "__main__":
    unittest.main()
