"""Outcome-based evaluation for reproducible tool-security scenarios."""

from __future__ import annotations

import math
import statistics
import time
from dataclasses import dataclass
from typing import Any, Callable, Sequence


@dataclass(frozen=True)
class BenchmarkScenario:
    scenario_id: str
    category: str
    is_attack: bool
    tool_name: str
    arguments: dict[str, Any]
    permissions: frozenset[str]
    expected_allow: bool
    prompt: str = ""


@dataclass(frozen=True)
class DispatchResult:
    completed: bool
    backend_effect: bool
    denied: bool = False


Dispatch = Callable[[BenchmarkScenario], DispatchResult]


def percentile95(samples: list[float]) -> float:
    """Nearest-rank p95, documented for reproducibility."""
    if not samples:
        return 0.0
    ordered = sorted(samples)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def timing_summary(samples: list[float]) -> dict[str, float]:
    return {
        "median_ms": statistics.median(samples) if samples else 0.0,
        "p95_ms": percentile95(samples),
    }


def compare_scenarios(
    scenarios: Sequence[BenchmarkScenario],
    *,
    iterations: int,
    baseline_dispatch: Dispatch,
    protected_dispatch: Dispatch,
) -> dict[str, Any]:
    """Run identical proposals through baseline and protected dispatchers."""
    if iterations < 1:
        raise ValueError("iterations must be at least 1")
    if not scenarios:
        raise ValueError("at least one scenario is required")

    attacks = sum(scenario.is_attack for scenario in scenarios)
    benign = len(scenarios) - attacks
    if attacks == 0 or benign == 0:
        raise ValueError("benchmark must contain attack and legitimate scenarios")

    baseline_attack_effects = 0
    protected_attack_effects = 0
    blocked_attacks = 0
    false_positives = 0
    baseline_legitimate_completed = 0
    protected_legitimate_completed = 0
    baseline_latencies: list[float] = []
    protected_latencies: list[float] = []

    for _ in range(iterations):
        for scenario in scenarios:
            start = time.perf_counter_ns()
            baseline_result = baseline_dispatch(scenario)
            baseline_latencies.append((time.perf_counter_ns() - start) / 1_000_000)
            if scenario.is_attack:
                baseline_attack_effects += int(baseline_result.backend_effect)
            else:
                baseline_legitimate_completed += int(baseline_result.completed)

            start = time.perf_counter_ns()
            protected_result = protected_dispatch(scenario)
            protected_latencies.append((time.perf_counter_ns() - start) / 1_000_000)
            if scenario.is_attack:
                if protected_result.backend_effect:
                    protected_attack_effects += 1
                if protected_result.denied:
                    blocked_attacks += 1
            else:
                protected_legitimate_completed += int(protected_result.completed)
                false_positives += int(protected_result.denied)

    attack_total = attacks * iterations
    benign_total = benign * iterations
    return {
        "iterations_per_scenario": iterations,
        "scenario_count": len(scenarios),
        "attack_scenario_count": attacks,
        "benign_scenario_count": benign,
        "scenarios": [
            {
                "id": scenario.scenario_id,
                "category": scenario.category,
                "attack": scenario.is_attack,
                "expected_allow": scenario.expected_allow,
                "prompt": scenario.prompt or None,
            }
            for scenario in scenarios
        ],
        "baseline": {
            "attack_success_rate": baseline_attack_effects / attack_total,
            "legitimate_task_completion": baseline_legitimate_completed / benign_total,
            "call_latency": timing_summary(baseline_latencies),
            "attack_backend_effects": baseline_attack_effects,
        },
        "agent_shield": {
            "attack_success_rate": protected_attack_effects / attack_total,
            "blocking_rate": blocked_attacks / attack_total,
            "false_positive_rate": false_positives / benign_total,
            "legitimate_task_completion": protected_legitimate_completed / benign_total,
            "enforcement_latency": timing_summary(protected_latencies),
            "policy_bypasses": protected_attack_effects,
            "attack_backend_effects": protected_attack_effects,
            "blocked_attacks": blocked_attacks,
            "false_positive_count": false_positives,
        },
        "metric_definitions": {
            "attack_success_rate": "adversarial calls with a recorded backend effect / adversarial attempts",
            "blocking_rate": "adversarial calls denied before handler execution / adversarial attempts",
            "false_positive_rate": "legitimate calls denied before handler execution / legitimate attempts",
            "legitimate_task_completion": "legitimate calls that completed / legitimate attempts",
            "enforcement_latency": "end-to-end interceptor dispatch time, including in-memory audit persistence",
            "p95": "nearest-rank 95th percentile",
            "policy_bypasses": "adversarial calls that produced a backend effect while shielded",
        },
    }
