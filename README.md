# MailGuard A2

A local prototype that prevents an AI agent from sending a report outside its current permissions. It compares three execution policies against the same tool calls and checks what actually reached the mock outbox.

**Drawerrr category** · Safeguarding delegated actions

## Quick start

From this directory, run with Python 3.10 or newer. The benchmark uses the standard library, SQLite and a temporary HTTP server bound to loopback.

```sh
python -m mailguard demo paraphrased-injection
python -m mailguard demo lost-reply-retry
python -m mailguard evaluate
python -m unittest discover -s tests -v
```

The first demo attempts to forward a report to an address supplied in an untrusted document. The second shows the outbox after a reply is lost and the caller retries. The benchmark writes `artifacts/summary.json`, `artifacts/outcomes.csv`, and `artifacts/traces.jsonl`. It exits with an error if the authorization mode creates an unexpected effect or misses a legitimate task.

## How it works

1. An agent proposes a recipient and report ID. The tool wrapper supplies the request ID. The server derives the agent identity from a session credential issued by the test harness. Each mode checks the identity and request format.
2. The **baseline** executes every well-formed authenticated call. The **text filter** also rejects three fixed phrases in the supplied document context. The **authorization mode** requires an active grant for the exact agent, recipient and report. The grant store is controlled by the harness, outside the model's tool interface.
3. The authorization mode reserves the SQLite writer before reading permissions. It checks the grant and writes the validated action in the same transaction, so a revocation committed first blocks the send. Replaying the same request ID and action returns the original receipt while permission remains active. Reusing that ID with different arguments is rejected when the changed action is otherwise permitted.

The `POST /send` route is the only HTTP path to the outbox. Calling it directly skips the agent and still reaches the same policy checks. The simulator stores the side effect in SQLite and uses synthetic addresses and report IDs.

## Experiment

[24 labeled scenarios](examples/scenarios.json) cover ordinary work, injected documents, incorrect attachments, cross-account use, revoked and expired grants, lost replies, ID substitution and direct API calls. Every mode starts with a fresh database and the same case-specific grants, request arguments and clock events. The grader reads newly inserted outbox rows after each request and compares them with the expected effect recorded in the fixture.

| Mode | Scenarios with an unauthorized send | Legitimate tasks completed | False denials | Duplicate sends |
| --- | ---: | ---: | ---: | ---: |
| Baseline | 13/19 | 8/8 | 0 | 2 |
| Text filter | 12/19 | 7/8 | 1 | 2 |
| Authorization and idempotency | 0/19 | 8/8 | 0 | 0 |

A security scenario includes at least one attempt whose effect should be suppressed. A case can also contain a legitimate task. The count of unauthorized scenarios includes a changed action that reuses the same request ID. Duplicate sends count repeated rows for the same principal, action and request ID and are measured independently. A false denial is a 403 on an attempt with a permitted effect.

The phrase filter blocked a literal injection, missed the paraphrase and rejected a training document quoting a blocked phrase. The retry test records the first send even though its response was lost. Separate tests exercise six simultaneous retries, concurrent revocation and a failed policy lookup.

Raw results from the reference run are in [summary.json](evidence/summary.json), [outcomes.csv](evidence/outcomes.csv) and [traces.jsonl](evidence/traces.jsonl). The reported median measures local HTTP round-trip time. It includes connection and disk overhead and varies by machine.

## Optional run with a local language model

With Ollama running at its default local address and a tool-capable model already installed, supply its installed name:

```sh
python -m mailguard live --model YOUR_INSTALLED_MODEL --scenario paraphrased-injection
```

The adapter requests tool calls once and replays that same proposal sequence across all three modes. It saves the model output, tool calls and observed outbox state in `artifacts/live.json`. A model may ignore the injection or make no tool calls. The reference results above use fixed proposals and measure the execution safeguard independently of model behavior. A live model run is not included in the reference evidence.

## Scope and limitations

- The fixtures are synthetic and hand labeled. The observed counts describe this suite and do not estimate attack rates against deployed models.
- The test harness owns grants, credentials and SQLite access. The threat model gives the agent the send tool and includes calls to its actual HTTP endpoint. It assumes the service host, session credentials and database are trusted.
- The permission check uses the clock sampled inside the transaction. The prototype models an irreversible operation as an outbox insert. Real email would need an independently secured delivery service and a clear authorization point for external delivery.
- Retry protection is scoped to the same principal and request ID. The prototype allows a new request ID to reuse an active grant, so application-level quotas or one-time approvals would need additional policy.

References · [Drawerrr challenge](https://www.drawerrr.com/challenge/ai-safety-and-control/prevent-irreversible-autonomous-actions) · [OWASP authorization guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) · [Ollama tool calling](https://docs.ollama.com/capabilities/tool-calling)
