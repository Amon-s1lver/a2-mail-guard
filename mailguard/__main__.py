"""Run the benchmark, show an individual scenario, or replay live tool calls."""

import argparse
import json
from pathlib import Path
from urllib.error import URLError

from .evaluate import evaluate, load_suite, run_case, summarize, write_results
from .live import live_case
from .service import Mode


def show_case(case, runs):
    print(f"{case['id']} | {case['description']}")
    print(f"Document: {case['document']}\n")
    for run in runs:
        print(run["mode"])
        for step in run["trace"]:
            if step["op"] == "send":
                args = step["arguments"]
                reason = step["response"].get("reason")
                outcome = step["response"]["status"]
                if reason:
                    outcome = f"{outcome} ({reason})"
                print(f"  send {args['report_id']} -> {args['recipient']}: {outcome}")
            else:
                print(f"  {step['op']}")
        if not run["trace"]:
            print("  No tool calls reached the mail service.")
        print(f"  Outbox: {json.dumps(run['outbox'], ensure_ascii=False)}")
        print(f"  Unauthorized sends: {run['unauthorized_sends']} | Duplicates: {run['duplicate_sends']}\n")


def main():
    suite = load_suite()
    cases = {case["id"]: case for case in suite["scenarios"]}
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    benchmark = sub.add_parser("evaluate", help="run every fixed scenario")
    benchmark.add_argument("--output", type=Path, default=Path("artifacts"))
    demo = sub.add_parser("demo", help="compare all modes on one fixed scenario")
    demo.add_argument("scenario", choices=cases, nargs="?", default="paraphrased-injection")
    live = sub.add_parser("live", help="use one real tool proposal trace from local Ollama")
    live.add_argument("--model", required=True)
    live.add_argument("--scenario", default="paraphrased-injection",
                      choices=("normal", "literal-injection", "paraphrased-injection", "fake-approval"))
    live.add_argument("--output", type=Path, default=Path("artifacts/live.json"))
    args = parser.parse_args()

    if args.command == "evaluate":
        results = evaluate(suite)
        metrics = summarize(results, suite)
        write_results(args.output, suite, results, metrics)
        for mode, stats in metrics.items():
            print(
                f"{mode:14}  unauthorized scenarios: {stats['scenarios_with_unauthorized_send']:2}/"
                f"{stats['security_challenge_scenarios']}  "
                f"legitimate tasks: {stats['completed_legitimate_tasks']}/"
                f"{stats['expected_legitimate_tasks']}  "
                f"false denials: {stats['false_denials']}  duplicates: {stats['duplicate_sends']}  "
                f"median HTTP: {stats['median_http_ms']:.3f} ms"
            )
        print(f"Results: {args.output.resolve()}")
        failed = [
            run["scenario"]
            for run in results
            if run["mode"] == Mode.AUTHORIZATION.value
            and (not run["safe"] or run["task_expected"] != run["task_completed"])
        ]
        if failed:
            parser.exit(1, f"Authorization failed the expected outcomes: {', '.join(failed)}\n")
        return

    if args.command == "demo":
        case = cases[args.scenario]
        show_case(case, [run_case(case, mode, suite["defaults"]) for mode in Mode])
        return

    try:
        case, proposal = live_case(suite, args.scenario, args.model)
    except (URLError, TimeoutError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Could not obtain tool calls from local Ollama: {error}\n")
    results = [run_case(case, mode, suite["defaults"]) for mode in Mode]
    print(f"Ollama model: {proposal['model']}\n")
    show_case(case, results)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps({"proposal": proposal, "results": results}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Live trace: {args.output.resolve()}")


if __name__ == "__main__":
    main()
