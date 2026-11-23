"""The shared FastMCP server instance.

Tool, resource and prompt modules import ``mcp`` from here and register
themselves with its decorators.  :mod:`sigma.mcp.main` imports all of those
modules so that every component is registered before the server runs.
"""

from __future__ import annotations

from fastmcp import FastMCP

mcp: FastMCP = FastMCP("sigma-mcp-server")
