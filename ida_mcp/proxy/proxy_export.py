"""Export proxy tools - struct reading, struct search, function export."""
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
    """Register export tools to server."""

    @server.tool(description="Read struct layout with actual memory values at an address.")
    def read_struct(
        addr: Annotated[str, Field(description="Memory address to read struct from")],
        struct_name: Annotated[Optional[str], Field(description="Struct type name (auto-detect if omitted)")] = None,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """Read struct with memory values."""
        params: dict[str, Any] = {"addr": addr}
        if struct_name:
            params["struct_name"] = struct_name
        return forward("read_struct", params, port, timeout=timeout)

    @server.tool(description="Search for structures by name substring.")
    def search_structs(
        filter: Annotated[str, Field(description="Case-insensitive substring to search for in structure names")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """Search structs by name."""
        return forward("search_structs", {"filter": filter}, port, timeout=timeout)

    @server.tool(description="Export function data in various formats (JSON with code, C header, or prototypes).")
    def export_funcs(
        addr: Annotated[str, Field(description="Function address(es) or name(s), comma-separated")],
        format: Annotated[str, Field(description="Export format: 'json', 'c_header', or 'prototypes'")] = "json",
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """Export function data."""
        return forward("export_funcs", {"addr": addr, "format": format}, port, timeout=timeout)

    @server.tool(description="Define function at address. IDA auto-determines bounds unless end address specified.")
    def define_func(
        addr: Annotated[str, Field(description="Address to define a function at")],
        end: Annotated[Optional[str], Field(description="End address (default: auto-detect)")] = None,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """Define function at address."""
        params: dict[str, Any] = {"addr": addr}
        if end:
            params["end"] = end
        return forward("define_func", params, port, timeout=timeout)

    @server.tool(description="Convert bytes to code instruction at address.")
    def define_code(
        addr: Annotated[str, Field(description="Address to convert bytes to code instruction")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        """Define code at address."""
        return forward("define_code", {"addr": addr}, port, timeout=timeout)
