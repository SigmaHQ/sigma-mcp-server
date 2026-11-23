"""The shared FastMCP server instance.

Tool, resource and prompt modules import ``mcp`` from here and register
themselves with its decorators.  :mod:`sigma.mcp.main` imports all of those
modules so that every component is registered before the server runs.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastmcp import FastMCP

from sigma.mcp import config
from sigma.mcp.index_manager import index_manager


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[dict[str, Any]]:
    """Start building the SigmaHQ rule index in the background.

    The server accepts requests at once; tools that need the index report
    its state until it is ready.  Set ``SIGMA_MCP_NO_WARMUP=1`` to skip this.
    """
    if config.warmup_enabled():
        index_manager.start_warmup()
    yield {}


mcp: FastMCP = FastMCP("sigma-mcp-server", lifespan=lifespan)
