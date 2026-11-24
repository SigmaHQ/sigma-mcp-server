"""Sigma MCP server exposing pySigma functionality via FastMCP.

This module assembles the server: importing the tool, resource and prompt
modules registers their components on the shared :data:`mcp` instance.
"""

from __future__ import annotations

# Imported for their side effect of registering components on ``mcp``.
import sigma.mcp.prompts  # noqa: F401
import sigma.mcp.resources  # noqa: F401
import sigma.mcp.tools.index  # noqa: F401
import sigma.mcp.tools.pipelines  # noqa: F401
import sigma.mcp.tools.rules  # noqa: F401
from sigma.mcp.server import mcp

__all__ = ["main", "mcp"]


def main() -> None:
    """Entry point for the sigma-mcp-server command."""
    mcp.run()
