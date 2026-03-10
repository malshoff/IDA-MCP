"""Sigmaker proxy tools - signature creation and searching."""
from __future__ import annotations

from typing import Optional, Any, Annotated

try:
    from pydantic import Field
except ImportError:
    Field = lambda **kwargs: None  # type: ignore

import sys
import os
_this_dir = os.path.dirname(os.path.abspath(__file__))
if _this_dir not in sys.path:
    sys.path.insert(0, _this_dir)

from _state import forward  # type: ignore


def register_tools(server: Any) -> None:
    """Register sigmaker tools to server."""

    @server.tool(description="Create a unique IDA-style signature for an address (e.g. '48 8B ? ? 48 89'). Returns {signature, address, length, unique}.")
    def create_sig(
        addr: Annotated[str, Field(description="Address or function name to create a signature for")],
        wildcard_operands: Annotated[bool, Field(description="Wildcard relocatable operands for stability across updates")] = True,
        max_length: Annotated[int, Field(description="Maximum signature length in bytes (1..500)")] = 100,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """Create unique IDA-style signature."""
        params: dict[str, Any] = {
            "addr": addr,
            "wildcard_operands": wildcard_operands,
            "max_length": max_length,
        }
        return forward("create_sig", params, port, timeout=timeout)

    @server.tool(description="Search the database for all matches of an IDA-style signature (e.g. '48 8B ? ? 48 89'). Returns {signature, total, matches}.")
    def search_sig(
        signature: Annotated[str, Field(description="IDA-style signature to search for (e.g. '48 8B ? ? 48 89')")],
        limit: Annotated[int, Field(description="Maximum number of results (1..1000)")] = 100,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """Search for IDA-style signature matches."""
        return forward("search_sig", {"signature": signature, "limit": limit}, port, timeout=timeout)
