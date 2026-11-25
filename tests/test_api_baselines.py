import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory

from apiguard.evaluate import effect_action, read_effects
from apiguard.fixtures import generate_suite, load_suite
from apiguard.service import Action, ApiService, Policy


class ApiBaselineTests(unittest.TestCase):
    def setUp(self):
        self.suite = load_suite()
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
    def test_each_api_has_sixteen_development_templates(self):
        groups = {}
        for case in self.suite["scenarios"]:
            groups.setdefault(case["api"], []).append(case)

        self.assertEqual(
            set(groups),
            {"message.send", "record.delete", "payment.refund"},
        )
        expected = {
            "benign", "injection", "scope", "dynamic-state",
            "retry", "bypass", "validation",
        }
        for api, cases in groups.items():
            self.assertEqual(len(cases), 16, api)
            self.assertEqual({case["family"] for case in cases}, expected, api)

    def test_state_change_forbids_later_effects(self):
        for case in self.suite["scenarios"]:
            stale = False
            for event in case["events"]:
                if event["op"] == "state_change":
                    stale = True
                elif event["op"] == "call" and stale:
                    self.assertIsNone(event["expected_effect"], case["id"])

    def test_fixture_generation_is_reproducible(self):
        self.assertEqual(generate_suite(), self.suite)

    def test_baselines_have_expected_difference_for_each_api(self):
        for policy in Policy:
            for index, operation in enumerate(("message.send", "record.delete", "payment.refund")):
                case = next(c for c in self.suite["scenarios"] if c["id"] == operation + "/paraphrased-injection")
                service = ApiService(self.directory / f"{policy.value}-{index}.db", policy, case["permissions"])
                status, _ = service.execute("agent-a", case["events"][0]["payload"])
                self.assertEqual(status, 403 if policy is Policy.STATIC else 201)
                self.assertEqual(len(read_effects(service.path)), int(status == 201))

    def test_concurrent_retries_are_idempotent_in_every_policy(self):
        case = self.suite["scenarios"][0]
        for policy in Policy:
            service = ApiService(self.directory / f"{policy.value}.db", policy, case["permissions"])
            with ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(
                    lambda _: service.execute("agent-a", case["events"][0]["payload"]), range(6)
                ))
            self.assertCountEqual([code for code, _ in results], [201] + [200] * 5)
            self.assertEqual(effect_action(read_effects(service.path)[0]), case["task_effect"])

    def test_request_id_is_bound_to_arguments_in_every_policy(self):
        case = next(c for c in self.suite["scenarios"] if c["id"] == "record.delete/key-substitution")
        for policy in Policy:
            extra = {"principal": "agent-a", "action": case["events"][1]["payload"]}
            service = ApiService(self.directory / f"{policy.value}.db", policy, [*case["permissions"], extra])
            self.assertEqual(service.execute("agent-a", case["events"][0]["payload"])[0], 201)
            self.assertEqual(service.execute("agent-a", case["events"][1]["payload"])[0], 409)
            self.assertEqual(len(read_effects(service.path)), 1)

    def test_invalid_types_and_extra_identity_cannot_create_effect(self):
        action = self.suite["scenarios"][0]["events"][0]["payload"]
        for payload in ([], {**action, "principal": "agent-a"}, {**action, "arguments": None}):
            with self.assertRaises(ValueError):
                Action.parse(payload)
        refund = next(c for c in self.suite["scenarios"] if c["api"] == "payment.refund")["events"][0]["payload"]
        for amount in (True, 0, -1, 100_000_001):
            bad = {**refund, "arguments": {"amount_cents": amount, "currency": "RUB"}}
            with self.assertRaises(ValueError):
                Action.parse(bad)

    def test_static_policy_commits_after_revocation(self):
        for operation in ("message.send", "record.delete", "payment.refund"):
            case = next(c for c in self.suite["scenarios"] if c["id"] == operation + "/revoked")
            service = ApiService(
                self.directory / f"{operation}-revoked.db",
                Policy.STATIC,
                case["permissions"],
            )
            payload = next(event["payload"] for event in case["events"] if event["op"] == "call")
            status, _ = service.execute("agent-a", payload)
            self.assertEqual(status, 201, operation)
            self.assertEqual(len(read_effects(service.path)), 1)
