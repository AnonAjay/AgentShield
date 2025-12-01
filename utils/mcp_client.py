# utils/mcp_client.py

from typing import Any, Dict, List


class MCPClient:
    """
    Minimal MCP client abstraction.

    For now this is a mock that returns hard-coded capabilities.
    Later you can:
      - call a real MCP server over HTTP/WebSocket
      - or wrap the official Model Context Protocol Python client.
    """

    def __init__(self, server_url: str):
        self.server_url = server_url

    def list_capabilities(self) -> List[Dict[str, Any]]:
        """
        List tools/capabilities exposed by this MCP server.

        Each capability dict should look like:
          {
            "name": str,
            "description": str,
            "requires_auth": bool,
            "scope": str,    # e.g. "read_only", "read_write", "admin", "all"
          }

        For now we simulate a few typical tools.
        """
        # TODO: replace this mock with real MCP calls when you integrate with an actual server.
        return [
            {
                "name": "get_weather",
                "description": "Get weather forecast for a city.",
                "requires_auth": False,
                "scope": "read_only",
            },
            {
                "name": "query_prod_database",
                "description": "Query production customer database.",
                "requires_auth": False,   # BAD
                "scope": "read_write",    # BAD
            },
            {
                "name": "delete_user_account",
                "description": "Delete a user account from the system.",
                "requires_auth": True,    # GOOD
                "scope": "admin",
            },
            {
                "name": "read_internal_logs",
                "description": "Read internal debug logs for troubleshooting.",
                "requires_auth": False,   # BAD
                "scope": "all",           # BAD
            },
        ]
