from __future__ import annotations

import unittest

from benchmarks.run import run_benchmark
from agent_shield.evaluation import (
    BenchmarkScenario,
    DispatchResult,
    compare_scenarios,
)
from agent_shield.evaluation import percentile95


class BenchmarkEvaluationTests(unittest.TestCase):
    def test_attack_success_requires_backend_effect(self) -> None:
        scenarios = [
            BenchmarkScenario("attack", "test", True, "danger", {}, frozenset(), False),
            BenchmarkScenario("benign", "test", False, "read", {}, frozenset(), True),
        ]
        report = compare_scenarios(
            scenarios,
            iterations=3,
            baseline_dispatch=lambda _: DispatchResult(True, True),
            protected_dispatch=lambda scenario: (
                DispatchResult(True, True)
                if scenario.scenario_id == "benign"
                else DispatchResult(False, False, denied=True)
            ),
        )
        self.assertEqual(report["baseline"]["attack_success_rate"], 1.0)
        self.assertEqual(report["agent_shield"]["attack_success_rate"], 0.0)
        self.assertEqual(report["agent_shield"]["blocking_rate"], 1.0)
        self.assertEqual(report["agent_shield"]["false_positive_rate"], 0.0)
        self.assertEqual(report["agent_shield"]["legitimate_task_completion"], 1.0)
        self.assertEqual(report["agent_shield"]["policy_bypasses"], 0)

    def test_p95_uses_nearest_rank(self) -> None:
        self.assertEqual(percentile95([1, 2, 3, 4, 5]), 5)
        self.assertEqual(percentile95([1, 2, 3, 4]), 4)

    def test_local_runner_covers_requested_scenario_families(self) -> None:
        report = run_benchmark(iterations=1)
        categories = {case["category"] for case in report["scenarios"]}
        self.assertTrue({
            "unauthorized_tool_invocation",
            "parameter_manipulation",
            "path_traversal",
            "prompt_injection_tool_action",
            "sensitive_file_access",
            "unauthorized_network_operation",
            "invalid_or_missing_authorization",
            "legitimate_operation",
        }.issubset(categories))
        self.assertEqual(report["agent_shield"]["policy_bypasses"], 0)
        self.assertEqual(report["agent_shield"]["legitimate_task_completion"], 1.0)


if __name__ == "__main__":
    unittest.main()
