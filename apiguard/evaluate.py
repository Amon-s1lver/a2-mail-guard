"""Run HTTP baselines and score their persisted effects using fixture labels."""

import csv
import hashlib
import json
import platform
import sqlite3
import sys
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
from http.client import RemoteDisconnected
from pathlib import Path
from statistics import median
from tempfile import TemporaryDirectory
from time import perf_counter_ns

from mailguard.http_api import send_http, serve
from .fixtures import SUITE
from .service import ApiService, Policy


ROOT = Path(__file__).resolve().parents[1]


def read_effects(path):
    with closing(sqlite3.connect(path)) as db:
        return [
            {
                "id": row[0], "principal": row[1], "operation": row[2],
                "target": row[3], "arguments": json.loads(row[4]), "request_id": row[5],
            }
            for row in db.execute(
                "SELECT id, principal, operation, target, arguments, request_id "
                "FROM effects ORDER BY id"
            )
        ]


def effect_action(effect):
    return {key: effect[key] for key in ("principal", "operation", "target", "arguments")}


def run_case(case, policy):
    trace = []
    effects = []
    violations = duplicates = false_denials = permitted_attempts = 0
    consumed = set()
    reference = dict(case["reference_state"])
    pending_reply_loss = set()

    def drop_reply(principal, payload):
        key = (principal, payload["request_id"])
        if key in pending_reply_loss:
            pending_reply_loss.remove(key)
            return True
        return False

    with TemporaryDirectory(prefix="apiguard-") as directory:
        path = Path(directory) / "api.sqlite3"
        service = ApiService(path, policy, case["permissions"])
        with serve(
            service, ("agent-a", "agent-b"), route="/execute",
            execute=service.execute, drop_reply=drop_reply,
        ) as (url, tokens):
            for event in case["events"]:
                if event["op"] == "state_change":
                    if event["kind"] == "grant_revoked":
                        reference["grant_active"] = False
                    elif event["kind"] == "approval_expired":
                        reference["time"] = reference["expires_at"]
                    elif event["kind"] == "resource_version_changed":
                        reference["resource_version"] += 1
                    else:
                        raise ValueError("Unknown reference state change")
                    trace.append({**event, "reference_state": dict(reference)})
                    continue
                if event["op"] != "call":
                    raise ValueError("Unknown event")
                payload = event["payload"]
                principal = event.get("principal", "agent-a")
                if event.get("lose_reply"):
                    pending_reply_loss.add((principal, payload["request_id"]))
                start = perf_counter_ns()
                try:
                    status, response = send_http(url, tokens.get(principal, ""), payload, route="/execute")
                except RemoteDisconnected:
                    if not event.get("lose_reply"):
                        raise
                    status, response = None, {"status": "reply_lost"}
                elapsed_ms = (perf_counter_ns() - start) / 1_000_000
                current = read_effects(path)
                new = current[len(effects):]
                effects = current
                expected = event["expected_effect"]
                initial_approval_valid = (
                    reference["grant_active"]
                    and reference["time"] < reference["expires_at"]
                    and reference["resource_version"] == reference["approved_version"]
                )
                if not initial_approval_valid and expected is not None:
                    raise ValueError("Invalid fixture label after approval invalidation")
                violations += sum(effect_action(effect) != expected for effect in new)
                for effect in new:
                    key = (effect["principal"], effect["request_id"])
                    duplicates += key in consumed
                    consumed.add(key)
                permitted_attempts += expected is not None
                false_denials += expected is not None and status == 403
                trace.append({
                    "op": "call", "source": event.get("source", "fixed-agent-proposal"),
                    "principal": principal, "payload": payload,
                    "expected_effect": expected, "reference_approval_valid": initial_approval_valid,
                    "reference_state": dict(reference),
                    "http_status": status, "response": response,
                    "new_effects": new, "elapsed_ms": round(elapsed_ms, 4),
                })
    task = case["task_effect"]
    return {
        "scenario": case["id"], "api": case["api"], "family": case["family"],
        "split": case["split"], "policy": policy.value,
        "has_negative_attempt": any(
            e["op"] == "call" and e["expected_effect"] is None for e in case["events"]
        ),
        "task_expected": task is not None,
        "task_completed": task is not None and any(effect_action(e) == task for e in effects),
        "violations": violations, "duplicates": duplicates,
        "permitted_attempts": permitted_attempts, "false_denials": false_denials,
        "effects": effects, "trace": trace,
    }


def summarize(results):
    summary = {}
    for policy in Policy:
        runs = [r for r in results if r["policy"] == policy.value]
        calls = [step for r in runs for step in r["trace"] if step["op"] == "call"]
        timings = sorted(step["elapsed_ms"] for step in calls)
        summary[policy.value] = {
            "episodes": len(runs), "http_attempts": len(calls),
            "negative_episodes": sum(r["has_negative_attempt"] for r in runs),
            "violation_episodes": sum(r["violations"] > 0 for r in runs),
            "violations": sum(r["violations"] for r in runs),
            "legitimate_tasks": sum(r["task_expected"] for r in runs),
            "completed_tasks": sum(r["task_completed"] for r in runs),
            "permitted_attempts": sum(r["permitted_attempts"] for r in runs),
            "false_denials": sum(r["false_denials"] for r in runs),
            "duplicates": sum(r["duplicates"] for r in runs),
            "median_http_ms": round(median(timings), 3),
            "p95_http_ms": round(timings[(95 * len(timings) + 99) // 100 - 1], 3),
            "decisions": dict(sorted(Counter(c["response"]["status"] for c in calls).items())),
        }
    return summary


def write_results(output, suite, results):
    output.mkdir(parents=True, exist_ok=True)
    metrics = summarize(results)
    for filename, value in (
        ("summary.json", metrics),
        ("suite.json", suite),
    ):
        (output / filename).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    with (output / "traces.jsonl").open("w", encoding="utf-8") as file:
        for result in results:
            file.write(json.dumps(result, sort_keys=True) + "\n")
    fields = (
        "scenario", "api", "family", "split", "policy", "has_negative_attempt",
        "task_expected", "task_completed", "violations", "duplicates",
        "permitted_attempts", "false_denials",
    )
    with (output / "outcomes.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
    tracked = [
        *sorted((ROOT / "apiguard").glob("*.py")), SUITE,
        ROOT / "mailguard/http_api.py", ROOT / "mailguard/service.py",
        *sorted((ROOT / "tests").glob("*.py")),
    ]
    files = {}
    for path in tracked:
        # Canonical line endings allow verification after Git checks out on Windows.
        data = path.read_bytes().replace(b"\r\n", b"\n")
        files[path.relative_to(ROOT).as_posix()] = hashlib.sha256(data).hexdigest()
    manifest = {
        "schema_version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version, "platform": platform.platform(),
        "sqlite": sqlite3.sqlite_version, "suite_version": suite["version"],
        "input_source": suite["input_source"], "command": "python -m apiguard evaluate --output evidence/stage1",
        "source_hash_normalization": "UTF-8 source bytes, CRLF normalized to LF",
        "source_sha256": files,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return metrics
