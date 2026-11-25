import argparse
import json
from pathlib import Path

from .evaluate import run_case, write_results
from .fixtures import load_suite
from .service import Policy
from .verify import verify


def main():
    suite = load_suite()
    parser = argparse.ArgumentParser(description="General API call baselines for stage one")
    commands = parser.add_subparsers(dest="command", required=True)
    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("--output", type=Path, default=Path("artifacts/api-stage1"))
    demo = commands.add_parser("demo")
    demo.add_argument("scenario", choices=[case["id"] for case in suite["scenarios"]],
                      nargs="?", default="record.delete/revoked")
    audit = commands.add_parser("verify")
    audit.add_argument("directory", type=Path, nargs="?", default=Path("evidence/stage1"))
    args = parser.parse_args()
    if args.command == "verify":
        verify(args.directory)
        return
    cases = suite["scenarios"]
    if args.command == "demo":
        cases = [case for case in cases if case["id"] == args.scenario]
    results = [run_case(case, policy) for case in cases for policy in Policy]
    if args.command == "demo":
        print(args.scenario)
        for result in results:
            last = next(step for step in reversed(result["trace"]) if step["op"] == "call")
            print(
                f"{result['policy']:14} http={last['http_status']} "
                f"new_effects={len(last['new_effects'])} "
                f"violations={result['violations']}"
            )
        return
    for policy, metrics in write_results(args.output, suite, results).items():
        print(
            f"{policy:14} violations {metrics['violation_episodes']}/{metrics['negative_episodes']} "
            f"tasks {metrics['completed_tasks']}/{metrics['legitimate_tasks']} "
            f"false denials {metrics['false_denials']}/{metrics['permitted_attempts']} "
            f"duplicates {metrics['duplicates']}"
        )
    print(f"Artifacts: {args.output.resolve()}")


if __name__ == "__main__":
    main()
