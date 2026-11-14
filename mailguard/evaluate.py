"""Run the same labeled scenarios against each policy and score outbox effects."""

import csv
import json
import platform
import sqlite3
from collections import Counter
from contextlib import closing
from http.client import RemoteDisconnected
from pathlib import Path
from statistics import median
from tempfile import TemporaryDirectory
from time import perf_counter_ns

from .http_api import send_http, serve
from .service import MailService, Mode


SUITE_PATH = Path(__file__).resolve().parents[1] / "examples" / "scenarios.json"
START_TIME = 1000
DEFAULT_PRINCIPAL = "agent-a"


def load_suite(path=SUITE_PATH):
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def read_outbox(path):
    # Read the observed side effect independently of the send response.
    with closing(sqlite3.connect(path)) as db:
        return [
            {"id": row[0], "principal": row[1], "recipient": row[2], "report_id": row[3]}
            for row in db.execute(
                "SELECT id, principal, recipient, report_id FROM outbox ORDER BY id"
            )
        ]


def run_case(case, mode, defaults):
    now = START_TIME
    pending_reply_loss = set()

    def drop_reply(principal, payload):
        key = (principal, payload["request_id"])
        if key in pending_reply_loss:
            pending_reply_loss.remove(key)
            return True
        return False

    trace = []
    unauthorized = 0
    duplicate = 0
    seen_requests = set()
    outbox = []
    with TemporaryDirectory(prefix="mailguard-") as directory:
        db_path = Path(directory) / "mail.sqlite3"
        service = MailService(db_path, mode, clock=lambda: now)
        for grant in case.get("grants", defaults["grants"]):
            service.grant(*grant)
        with serve(service, ("agent-a", "agent-b"), drop_reply=drop_reply) as (url, tokens):
            for event in case["events"]:
                operation = event["op"]
                if operation == "revoke":
                    service.revoke(*event["grant"])
                    trace.append(event)
                    continue
                if operation == "advance_clock":
                    now += event["seconds"]
                    trace.append({**event, "time": now})
                    continue
                if operation != "send":
                    raise ValueError(f"Unknown scenario operation: {operation}")

                principal = event.get("principal", DEFAULT_PRINCIPAL)
                payload = {**defaults["request"], "context": case["document"], **event.get("args", {})}
                token = tokens.get(principal, "")
                if event.get("lose_reply"):
                    pending_reply_loss.add((principal, payload["request_id"]))

                started = perf_counter_ns()
                try:
                    status, response = send_http(url, token, payload, route=event.get("route", "/send"))
                except RemoteDisconnected:
                    if not event.get("lose_reply"):
                        raise
                    status, response = None, {"status": "reply_lost"}
                elapsed_us = (perf_counter_ns() - started) / 1000
                next_outbox = read_outbox(db_path)
                effects = next_outbox[len(outbox):]
                outbox = next_outbox

                # Labels describe the only effect permitted for this attempt.
                # They are test data, separate from the service's policy lookup.
                permitted = event["permitted_effect"]
                for effect in effects:
                    actual = [effect["principal"], effect["recipient"], effect["report_id"]]
                    unauthorized += actual != permitted
                    key = (*actual, payload["request_id"])
                    duplicate += key in seen_requests
                    seen_requests.add(key)
                trace.append({
                    "op": "send",
                    "source": event.get("source", "agent"),
                    "principal": principal,
                    "arguments": payload,
                    "permitted_effect": permitted,
                    "status_code": status,
                    "response": response,
                    "new_outbox_rows": effects,
                    "elapsed_us": round(elapsed_us, 1),
                })

    intended = case["task_effect"]
    completed = intended is not None and any(
        [row["principal"], row["recipient"], row["report_id"]] == intended for row in outbox
    )
    safe = unauthorized == 0 and duplicate == 0
    return {
        "scenario": case["id"],
        "family": case["family"],
        "description": case["description"],
        "mode": mode.value,
        "task_expected": intended is not None,
        "task_completed": completed,
        "safe": safe,
        "unauthorized_sends": unauthorized,
        "duplicate_sends": duplicate,
        "outbox": outbox,
        "trace": trace,
    }


def summarize(results, suite):
    by_id = {case["id"]: case for case in suite["scenarios"]}
    metrics = {}
    for mode in Mode:
        runs = [result for result in results if result["mode"] == mode.value]
        negative_cases = sum(by_id[run["scenario"]]["security_challenge"] for run in runs)
        task_cases = sum(run["task_expected"] for run in runs)
        send_steps = [step for run in runs for step in run["trace"] if step["op"] == "send"]
        decisions = Counter(step["response"]["status"] for step in send_steps)
        metrics[mode.value] = {
            "scenarios": len(runs),
            "security_challenge_scenarios": negative_cases,
            "scenarios_with_unauthorized_send": sum(run["unauthorized_sends"] > 0 for run in runs),
            "unauthorized_sends": sum(run["unauthorized_sends"] for run in runs),
            "expected_legitimate_tasks": task_cases,
            "completed_legitimate_tasks": sum(run["task_completed"] for run in runs),
            "false_denials": sum(
                step["permitted_effect"] is not None and step["status_code"] == 403
                for step in send_steps
            ),
            "duplicate_sends": sum(run["duplicate_sends"] for run in runs),
            "median_http_ms": round(median(step["elapsed_us"] for step in send_steps) / 1000, 3),
            "decisions": dict(sorted(decisions.items())),
        }
    return metrics


def evaluate(suite):
    return [
        run_case(case, mode, suite["defaults"])
        for case in suite["scenarios"]
        for mode in Mode
    ]


def write_results(path, suite, results, metrics):
    path.mkdir(parents=True, exist_ok=True)
    summary = {
        "suite_version": suite["version"],
        "input_source": "fixed tool calls",
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "metrics": metrics,
    }
    (path / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    with (path / "traces.jsonl").open("w", encoding="utf-8") as file:
        for result in results:
            file.write(json.dumps(result, ensure_ascii=False) + "\n")
    fields = (
        "scenario", "family", "mode", "task_expected", "task_completed",
        "unauthorized_sends", "duplicate_sends", "safe",
    )
    with (path / "outcomes.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
