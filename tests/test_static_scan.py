from __future__ import annotations

import unittest

from agent_shield.static_scan import scan_config, scan_text, scan_tool_definitions


class StaticScanTests(unittest.TestCase):
    def test_known_token_is_reported_without_value(self) -> None:
        token = "AIza" + "A" * 35
        findings = scan_text(f'KEY = "{token}"', source="example.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].code, "POSSIBLE_HARDCODED_SECRET")
        self.assertNotIn(token, findings[0].message)
        self.assertEqual(findings[0].line, 1)

    def test_placeholder_is_not_reported_as_known_token(self) -> None:
        self.assertEqual(scan_text('API_KEY = "replace-me"'), [])

    def test_sensitive_tool_without_permission_is_flagged(self) -> None:
        findings = scan_tool_definitions(
            [{"name": "delete_account", "sensitive": True, "required_permissions": []}]
        )
        self.assertIn("SENSITIVE_TOOL_WITHOUT_PERMISSION", {item.code for item in findings})

    def test_network_tool_without_host_allowlist_is_flagged(self) -> None:
        findings = scan_tool_definitions(
            [{"name": "fetch", "network_host_argument": "host"}]
        )
        self.assertIn("NETWORK_TOOL_WITHOUT_HOST_ALLOWLIST", {item.code for item in findings})

    def test_mcp_style_auth_and_scope_metadata_are_checked(self) -> None:
        findings = scan_tool_definitions(
            [
                {
                    "name": "query_prod_database",
                    "description": "Query production customer records",
                    "requires_auth": False,
                    "scope": "read_write",
                }
            ]
        )
        codes = {item.code for item in findings}
        self.assertIn("SENSITIVE_TOOL_WITHOUT_AUTH", codes)
        self.assertIn("OVERBROAD_TOOL_SCOPE", codes)

    def test_invalid_configuration_is_reported(self) -> None:
        findings = scan_config({"tool": []})
        self.assertEqual(findings[0].code, "MISSING_TOOLS_LIST")


if __name__ == "__main__":
    unittest.main()
