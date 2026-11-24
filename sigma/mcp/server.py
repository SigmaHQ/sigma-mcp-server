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
from fastmcp.server.transforms import ResourcesAsTools

from sigma.mcp import config
from sigma.mcp.index_manager import index_manager
from sigma.mcp.reference_data import reference_data


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[dict[str, Any]]:
    """Start building the rule index and loading MITRE data in the background.

    The server accepts requests at once; tools that need the index report
    its state until it is ready, and ``validate_rule`` skips validators whose
    MITRE data is not loaded yet.  Set ``SIGMA_MCP_NO_WARMUP=1`` to skip this.
    """
    if config.warmup_enabled():
        index_manager.start_warmup()
        reference_data.start_loading()
    yield {}


mcp: FastMCP = FastMCP("sigma-mcp-server", lifespan=lifespan)

# Clients that support tools but not resources (for example Pydantic AI
# agents) reach every resource through the list_resources and read_resource
# tools.
mcp.add_transform(ResourcesAsTools(mcp))
