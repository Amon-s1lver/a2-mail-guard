"""Three mock APIs with a shared execution contract and policy baselines."""

import json
from dataclasses import dataclass
from enum import Enum

from mailguard.service import ADDRESS, FILTER_PHRASES, IDENTIFIER, MailService


class Policy(str, Enum):
    SCHEMA = "schema-only"
    FILTER = "text-filter"
    STATIC = "static-policy"


OPERATIONS = {
    "message.send": {"report_id": str},
    "record.delete": {"version": int},
    "payment.refund": {"amount_cents": int, "currency": str},
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True)
class Action:
    operation: str
    target: str
    arguments: dict
    request_id: str
    context: str

    @property
    def fingerprint(self):
        return canonical([self.operation, self.target, self.arguments])

    @classmethod
    def parse(cls, payload):
        required = {"operation", "target", "arguments", "request_id", "context"}
        if not isinstance(payload, dict) or set(payload) != required:
            raise ValueError("unexpected_fields")
        if not all(isinstance(payload[key], str) for key in required - {"arguments"}):
            raise ValueError("invalid_type")
        operation = payload["operation"]
        if operation not in OPERATIONS:
            raise ValueError("unknown_operation")
        target = payload["target"]
        if operation == "message.send":
            if len(target) > 254 or not ADDRESS.fullmatch(target):
                raise ValueError("invalid_target")
            local, domain = target.rsplit("@", 1)
            target = f"{local}@{domain.lower()}"
        elif not IDENTIFIER.fullmatch(target):
            raise ValueError("invalid_target")
        arguments = payload["arguments"]
        if not isinstance(arguments, dict) or arguments.keys() != OPERATIONS[operation].keys():
            raise ValueError("invalid_arguments")
        for name, kind in OPERATIONS[operation].items():
            if type(arguments[name]) is not kind:
                raise ValueError("invalid_argument_type")
        if operation == "message.send" and not IDENTIFIER.fullmatch(arguments["report_id"]):
            raise ValueError("invalid_report")
        if operation == "record.delete" and arguments["version"] < 1:
            raise ValueError("invalid_version")
        if operation == "payment.refund":
            if not 0 < arguments["amount_cents"] <= 100_000_000:
                raise ValueError("invalid_amount")
            if arguments["currency"] not in {"RUB", "USD", "EUR"}:
                raise ValueError("invalid_currency")
        if not IDENTIFIER.fullmatch(payload["request_id"]) or len(payload["context"]) > 4000:
            raise ValueError("invalid_metadata")
        return cls(operation, target, dict(arguments), payload["request_id"], payload["context"])


class ApiService:
    """Schema, phrase filter, or an exact allowlist loaded before the episode.

    These stage-one baselines deliberately have no dynamic approval protocol.
    All policies share transactional idempotency.
    """

    connection = MailService.connection

    def __init__(self, path, policy, permissions):
        self.path = path
        self.policy = Policy(policy)
        self.permissions = frozenset(
            (entry["principal"], Action.parse(entry["action"]).fingerprint)
            for entry in permissions
        )
        with self.connection() as db:
            db.executescript("""
                CREATE TABLE effects (
                    id INTEGER PRIMARY KEY,
                    principal TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    target TEXT NOT NULL,
                    arguments TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    UNIQUE (principal, request_id)
                );
            """)

    def execute(self, principal, payload):
        try:
            action = Action.parse(payload)
        except ValueError as error:
            return 400, {"status": "invalid_request", "reason": str(error)}
        if self.policy is Policy.FILTER and any(
            phrase in action.context.casefold() for phrase in FILTER_PHRASES
        ):
            return 403, {"status": "denied", "reason": "text_filter"}
        if self.policy is Policy.STATIC and (principal, action.fingerprint) not in self.permissions:
            return 403, {"status": "denied", "reason": "outside_static_permission"}

        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute(
                "SELECT id, fingerprint FROM effects WHERE principal = ? AND request_id = ?",
                (principal, action.request_id),
            ).fetchone()
            if previous:
                effect_id, fingerprint = previous
                if fingerprint != action.fingerprint:
                    return 409, {"status": "conflict", "reason": "request_id_reused"}
                return 200, {"status": "already_committed", "effect_id": effect_id}
            cursor = db.execute(
                "INSERT INTO effects "
                "(principal, operation, target, arguments, request_id, fingerprint) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (principal, action.operation, action.target, canonical(action.arguments),
                 action.request_id, action.fingerprint),
            )
            return 201, {"status": "committed", "effect_id": cursor.lastrowid}
