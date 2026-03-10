"""Graph proxy tools - call graph and callees."""
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
    """Register graph tools to server."""

    @server.tool(description="Build call graph starting from root functions. Returns nodes and edges with depth info.")
    def callgraph(
        roots: Annotated[str, Field(description="Root function address(es) or name(s), comma-separated")],
        max_depth: Annotated[int, Field(description="Maximum traversal depth (default: 5)")] = 5,
        max_nodes: Annotated[int, Field(description="Max nodes in graph (default: 1000)")] = 1000,
        max_edges: Annotated[int, Field(description="Max edges in graph (default: 5000)")] = 5000,
        max_edges_per_func: Annotated[int, Field(description="Max edges per function (default: 200)")] = 200,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """Build call graph from root functions."""
        return forward("callgraph", {
            "roots": roots,
            "max_depth": max_depth,
            "max_nodes": max_nodes,
            "max_edges": max_edges,
            "max_edges_per_func": max_edges_per_func,
        }, port, timeout=timeout)

    @server.tool(description="Get functions called by the specified functions.")
    def callees(
        addr: Annotated[str, Field(description="Function address(es) or name(s), comma-separated")],
        limit: Annotated[int, Field(description="Max callees per function (default: 200)")] = 200,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """Get callees of specified functions."""
        return forward("callees", {"addr": addr, "limit": limit}, port, timeout=timeout)
