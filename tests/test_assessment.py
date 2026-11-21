from __future__ import annotations

import unittest

from agent_shield.assessment import (
    MEMORY_POISONING_PROBE_QUERIES,
    POISONED_MEMORY_SNIPPET,
    PROMPT_FAMILIES,
    risk_grade,
    score_from_severity_and_confidence,
    severity_from_type,
)


class AssessmentAssetTests(unittest.TestCase):
    def test_prompt_families_are_named_and_nonempty(self) -> None:
        self.assertTrue(PROMPT_FAMILIES)
        self.assertTrue(all(family.attack_type and family.prompts for family in PROMPT_FAMILIES))
        self.assertTrue(MEMORY_POISONING_PROBE_QUERIES)
        self.assertIn("ignore all safety", POISONED_MEMORY_SNIPPET.lower())

    def test_heuristic_scores_remain_bounded_and_advisory(self) -> None:
        self.assertEqual(severity_from_type("data_exfiltration"), 10)
        self.assertEqual(score_from_severity_and_confidence(8, 0.5), 4.0)
        self.assertEqual(score_from_severity_and_confidence(10, 0.0), 0.0)
        self.assertEqual(risk_grade(8.0), "CRITICAL")


if __name__ == "__main__":
    unittest.main()
