"""Hardening for a server that anyone on the internet can use.

:func:`apply_public_mode` is called by :mod:`sigma.mcp.main` when
``SIGMA_MCP_PUBLIC`` is set.  It

* removes the tools a client must not trigger on a shared server
  (:data:`PRIVATE_TOOLS`, e.g. downloading the SigmaHQ rules again),
* rejects tool calls whose arguments exceed ``SIGMA_MCP_MAX_INPUT_BYTES``,
* limits the requests per second and client (``SIGMA_MCP_RATE_LIMIT``), and
* runs at most ``SIGMA_MCP_MAX_CONCURRENT_TOOLS`` tool calls at once, so a
  few expensive calls (e.g. ``analyze_pipeline_coverage``) cannot occupy
  every worker thread.

The server keeps no secrets and only fetches fixed URLs, so it needs no
authentication.
"""

from __future__ import annotations

import json
import logging
import weakref
from typing import Any

import anyio
import mcp.types as mt
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_http_request
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.server.middleware.rate_limiting import RateLimitingMiddleware
from fastmcp.tools.base import ToolResult

from sigma.mcp import config

log = logging.getLogger(__name__)

PRIVATE_TOOLS = ("update_sigma_repository",)
"""Tools removed in public mode.  The rule index is built when the image is
built and refreshed by deploying a new image."""

QUEUE_TIMEOUT = 30.0
"""Seconds a tool call waits for a free slot before it is rejected."""

_hardened: weakref.WeakSet[FastMCP] = weakref.WeakSet()


def client_id(context: MiddlewareContext[Any]) -> str:
    """Identify the client of a request by its IP address.

    Behind a reverse proxy, uvicorn takes the address from
    ``X-Forwarded-For`` for the proxies listed in ``FORWARDED_ALLOW_IPS``.
    Requests without an HTTP connection (stdio, in-memory) share one ID.
    """
    try:
        request = get_http_request()
    except RuntimeError:
        return "local"
    return request.client.host if request.client else "unknown"


class InputSizeMiddleware(Middleware):
    """Reject tool calls whose JSON-encoded arguments exceed *max_bytes*."""

    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max_bytes

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        arguments = context.message.arguments or {}
        size = len(json.dumps(arguments, ensure_ascii=False).encode("utf-8"))
        if size > self.max_bytes:
            raise ToolError(
                f"The arguments are {size} bytes; this public server accepts at "
                f"most {self.max_bytes} bytes per tool call. Send fewer or "
                "smaller rules and pipelines, or run sigma-mcp-server locally "
                "(uvx sigma-mcp-server) for large inputs."
            )
        return await call_next(context)


class ConcurrencyLimitMiddleware(Middleware):
    """Run at most *limit* tool calls at once; wait up to *timeout* for a slot."""

    def __init__(self, limit: int, timeout: float = QUEUE_TIMEOUT) -> None:
        self.limit = limit
        self.timeout = timeout
        self._limiter: anyio.CapacityLimiter | None = None

    @property
    def limiter(self) -> anyio.CapacityLimiter:
        # Created lazily: a CapacityLimiter must be made inside an event loop.
        if self._limiter is None:
            self._limiter = anyio.CapacityLimiter(self.limit)
        return self._limiter

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        limiter = self.limiter
        with anyio.move_on_after(self.timeout):
            await limiter.acquire()
            try:
                return await call_next(context)
            finally:
                limiter.release()
        raise ToolError(
            "The server is busy. Please try again in a moment, or run "
            "sigma-mcp-server locally (uvx sigma-mcp-server)."
        )


def apply_public_mode(server: FastMCP) -> None:
    """Remove private tools from *server* and add the protective middleware.

    Calling it again for the same server does nothing.
    """
    if server in _hardened:
        return
    _hardened.add(server)
    for name in PRIVATE_TOOLS:
        try:
            server.local_provider.remove_tool(name)
        except KeyError:
            log.debug("Tool %s is not registered", name)
    rate = config.rate_limit()
    if rate > 0:
        server.add_middleware(
            RateLimitingMiddleware(
                max_requests_per_second=rate, get_client_id=client_id
            )
        )
    max_bytes = config.max_input_bytes()
    if max_bytes > 0:
        server.add_middleware(InputSizeMiddleware(max_bytes))
    server.add_middleware(ConcurrencyLimitMiddleware(config.max_concurrent_tools()))
