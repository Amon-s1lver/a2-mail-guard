"""Audit the saved reference results and source hashes without making network calls."""

import csv
import hashlib
import json
from pathlib import Path

from .evaluate import ROOT, effect_action, summarize


def verify(directory):
    suite = json.loads((directory / "suite.json").read_text(encoding="utf-8"))
    runs = [json.loads(line) for line in (directory / "traces.jsonl").read_text(encoding="utf-8").splitlines()]
    summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    cases = {case["id"]: case for case in suite["scenarios"]}
    keys = set()
    for run in runs:
        key = (run["scenario"], run["policy"])
        if key in keys:
            raise ValueError(f"Duplicate episode {key}")
        keys.add(key)
        case = cases[run["scenario"]]
        call_events = [e for e in case["events"] if e["op"] == "call"]
        calls = [s for s in run["trace"] if s["op"] == "call"]
        if len(calls) != len(call_events):
            raise ValueError(f"Call count mismatch {key}")
        effects = []
        violations = 0
        for event, step in zip(call_events, calls):
            if (event["payload"], event["expected_effect"]) != (step["payload"], step["expected_effect"]):
                raise ValueError(f"Fixture mismatch {key}")
            effects.extend(step["new_effects"])
            violations += sum(effect_action(e) != event["expected_effect"] for e in step["new_effects"])
        if effects != run["effects"] or violations != run["violations"]:
            raise ValueError(f"Effect mismatch {key}")
        expected_task = case["task_effect"]
        completed = expected_task is not None and any(effect_action(e) == expected_task for e in effects)
        if completed != run["task_completed"]:
            raise ValueError(f"Task mismatch {key}")
    if len(runs) != len(cases) * 3 or summarize(runs) != summary:
        raise ValueError("Summary or suite coverage mismatch")
    with (directory / "outcomes.csv").open(encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))
    if len(rows) != len(runs):
        raise ValueError("CSV row count mismatch")
    for row, run in zip(rows, runs):
        if any(row[field] != str(run[field]) for field in row):
            raise ValueError("CSV content mismatch")
    for relative, expected in manifest["source_sha256"].items():
        actual = hashlib.sha256((ROOT / relative).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        if actual != expected:
            raise ValueError(f"Source hash mismatch: {relative}")
    print(f"Verified {len(runs)} episodes, labels, effects, CSV, summary and {len(manifest['source_sha256'])} source hashes.")
