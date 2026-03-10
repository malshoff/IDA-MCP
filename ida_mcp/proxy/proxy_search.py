"""Search proxy tools - unified search and regex string search."""
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
    """Register search tools to server."""

    @server.tool(description="Search for patterns in the binary (strings, immediate values, or references).")
    def find(
        type: Annotated[str, Field(description="Search type: 'string', 'immediate', 'data_ref', or 'code_ref'")],
        target: Annotated[str, Field(description="Search target (string, integer value, or address)")],
        limit: Annotated[int, Field(description="Max matches (default: 100)")] = 100,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """Unified search."""
        return forward("find", {"type": type, "target": target, "limit": limit}, port, timeout=timeout)

    @server.tool(description="Search strings in the database with case-insensitive regex patterns.")
    def find_regex(
        pattern: Annotated[str, Field(description="Regex pattern to search for in IDB strings")],
        limit: Annotated[int, Field(description="Max matches (default: 100)")] = 100,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """Regex string search."""
        return forward("find_regex", {"pattern": pattern, "limit": limit}, port, timeout=timeout)
