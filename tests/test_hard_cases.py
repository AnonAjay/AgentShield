from __future__ import annotations

import unittest

from benchmarks.hard_cases import run_hard_cases


class HardRedTeamTests(unittest.TestCase):
    def test_runner_reproduces_and_names_known_boundary_gaps(self) -> None:
        report = run_hard_cases()
        cases = {case["id"]: case["status"] for case in report["cases"]}
        self.assertEqual(cases["hardlink-filesystem-escape"], "VULNERABLE")
        self.assertEqual(cases["unvalidated-array-items"], "VULNERABLE")
        self.assertEqual(cases["allowlisted-host-unapproved-port"], "SCOPE_GAP")
        self.assertEqual(cases["network-lookalike-suffix"], "BLOCKED")
        self.assertEqual(cases["unicode-confusable-tool-name"], "BLOCKED")
        self.assertEqual(report["vulnerability_count"], 2)
        self.assertEqual(report["scope_gap_count"], 1)
        self.assertEqual(report["finding_count"], 3)


if __name__ == "__main__":
    unittest.main()
