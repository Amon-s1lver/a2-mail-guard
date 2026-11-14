"""Validate proposed sends and commit authorized effects to a mock outbox."""

import re
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum


class Mode(str, Enum):
    BASELINE = "baseline"
    TEXT_FILTER = "text-filter"
    AUTHORIZATION = "authorization"


FILTER_PHRASES = ("ignore previous", "override policy", "bypass approval")
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}", re.ASCII)
ADDRESS = re.compile(
    r"[a-zA-Z0-9_+%-]+(?:\.[a-zA-Z0-9_+%-]+)*@"
    r"[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+",
    re.ASCII,
)

SCHEMA = """
CREATE TABLE grants (
    principal TEXT NOT NULL,
    recipient TEXT NOT NULL,
    report_id TEXT NOT NULL,
    expires_at REAL,
    PRIMARY KEY (principal, recipient, report_id)
);
CREATE TABLE outbox (
    id INTEGER PRIMARY KEY,
    principal TEXT NOT NULL,
    recipient TEXT NOT NULL,
    report_id TEXT NOT NULL,
    request_key TEXT,
    UNIQUE (principal, request_key)
);
"""


@dataclass(frozen=True)
class SendRequest:
    recipient: str
    report_id: str
    request_id: str
    context: str = ""

    @classmethod
    def parse(cls, payload):
        required = {"recipient", "report_id", "request_id"}
        if not isinstance(payload, dict):
            raise ValueError("invalid_request_object")
        fields = payload.keys()
        if not required <= fields <= required | {"context"}:
            raise ValueError("unexpected_request_fields")
        if not all(isinstance(value, str) for value in payload.values()):
            raise ValueError("invalid_argument_type")
        recipient = payload["recipient"]
        if len(recipient) > 254 or not ADDRESS.fullmatch(recipient):
            raise ValueError("invalid_recipient")
        local, domain = recipient.rsplit("@", 1)
        report_id = payload["report_id"]
        request_id = payload["request_id"]
        if not IDENTIFIER.fullmatch(report_id) or not IDENTIFIER.fullmatch(request_id):
            raise ValueError("invalid_identifier")
        context = payload.get("context", "")
        if len(context) > 4000:
            raise ValueError("context_too_long")
        return cls(f"{local}@{domain.lower()}", report_id, request_id, context)


class MailService:
    """The service owns the database and is the only writer of outgoing mail."""

    def __init__(self, path, mode, *, clock=time.time):
        self.path = path
        self.mode = Mode(mode)
        self.clock = clock
        with self.connection() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=2)
        try:
            with db:
                yield db
        finally:
            db.close()

    def grant(self, principal, recipient, report_id, expires_at=None):
        with self.connection() as db:
            db.execute(
                "INSERT INTO grants VALUES (?, ?, ?, ?) "
                "ON CONFLICT(principal, recipient, report_id) "
                "DO UPDATE SET expires_at = excluded.expires_at",
                (principal, recipient, report_id, expires_at),
            )

    def revoke(self, principal, recipient, report_id):
        with self.connection() as db:
            db.execute(
                "DELETE FROM grants WHERE principal = ? AND recipient = ? AND report_id = ?",
                (principal, recipient, report_id),
            )

    def send(self, principal, payload):
        try:
            request = SendRequest.parse(payload)
        except ValueError as error:
            return 400, {"status": "invalid_request", "reason": str(error)}

        if self.mode is Mode.TEXT_FILTER:
            context = request.context.casefold()
            if any(phrase in context for phrase in FILTER_PHRASES):
                return 403, {"status": "denied", "reason": "text_filter"}

        with self.connection() as db:
            if self.mode is Mode.AUTHORIZATION:
                # Acquire the write reservation before reading policy. Revocation
                # and insertion therefore serialize against the same database.
                db.execute("BEGIN IMMEDIATE")
                allowed = db.execute(
                    "SELECT 1 FROM grants WHERE principal = ? AND recipient = ? "
                    "AND report_id = ? AND (expires_at IS NULL OR expires_at > ?)",
                    (principal, request.recipient, request.report_id, self.clock()),
                ).fetchone()
                if allowed is None:
                    return 403, {"status": "denied", "reason": "no_active_grant"}

                previous = db.execute(
                    "SELECT id, recipient, report_id FROM outbox "
                    "WHERE principal = ? AND request_key = ?",
                    (principal, request.request_id),
                ).fetchone()
                if previous is not None:
                    mail_id, recipient, report_id = previous
                    if (recipient, report_id) != (request.recipient, request.report_id):
                        return 409, {"status": "conflict", "reason": "request_id_reused"}
                    return 200, {"status": "already_sent", "mail_id": mail_id}

            request_key = request.request_id if self.mode is Mode.AUTHORIZATION else None
            cursor = db.execute(
                "INSERT INTO outbox (principal, recipient, report_id, request_key) "
                "VALUES (?, ?, ?, ?)",
                (principal, request.recipient, request.report_id, request_key),
            )
            return 201, {"status": "sent", "mail_id": cursor.lastrowid}
