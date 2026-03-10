"""Export & Struct API - Read structs, search structs, export functions.

Provides tools:
    - read_struct        Read struct layout with actual memory values at address
    - search_structs     Search structure names by substring
    - export_funcs       Export function data in various formats
"""
from __future__ import annotations

import contextlib
from typing import Annotated, Optional, List, Union

from .rpc import tool
from .sync import idaread
from .utils import parse_address, hex_addr, normalize_list_input

# IDA modules
import idaapi  # type: ignore
import idautils  # type: ignore
import ida_funcs  # type: ignore
import ida_bytes  # type: ignore
import ida_typeinf  # type: ignore
import ida_nalt  # type: ignore
import ida_lines  # type: ignore

# Compat
from . import compat  # type: ignore


# ============================================================================
# Read Struct
# ============================================================================

@tool
@idaread
def read_struct(
    addr: Annotated[str, "Memory address to read struct from"],
    struct_name: Annotated[Optional[str], "Struct type name (auto-detect if omitted)"] = None,
) -> dict:
    """Read struct layout with actual memory values at an address."""
    parsed = parse_address(addr)
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": f"Cannot resolve address: {addr}"}

    ea = parsed["value"]

    # Auto-detect struct type if not provided
    if not struct_name:
        tif_auto = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(tif_auto, ea) and tif_auto.is_udt():
            struct_name = tif_auto.get_type_name()

    if not struct_name:
        return {"error": "No struct specified and could not auto-detect from address"}

    # Lookup struct type
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, struct_name):
        return {"error": f"Struct '{struct_name}' not found"}

    udt_data = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt_data):
        return {"error": "Failed to get struct details"}

    is_64bit = False
    with contextlib.suppress(Exception):
        is_64bit = compat.inf_is_64bit()

    members: List[dict] = []
    for member in udt_data:
        offset = member.begin() // 8
        member_type = member.type._print()
        member_name = member.name
        member_size = member.type.get_size()
        member_addr = ea + offset

        # Read memory value at member address
        value_str = None
        with contextlib.suppress(Exception):
            if member.type.is_ptr():
                if is_64bit:
                    value = idaapi.get_qword(member_addr)
                    value_str = f"0x{value:016X}"
                else:
                    value = idaapi.get_dword(member_addr)
                    value_str = f"0x{value:08X}"
            elif member_size == 1:
                value = idaapi.get_byte(member_addr)
                value_str = f"0x{value:02X} ({value})"
            elif member_size == 2:
                value = idaapi.get_word(member_addr)
                value_str = f"0x{value:04X} ({value})"
            elif member_size == 4:
                value = idaapi.get_dword(member_addr)
                value_str = f"0x{value:08X} ({value})"
            elif member_size == 8:
                value = idaapi.get_qword(member_addr)
                value_str = f"0x{value:016X} ({value})"
            else:
                raw = ida_bytes.get_bytes(member_addr, min(member_size, 16))
                if raw:
                    value_str = " ".join(f"{b:02X}" for b in raw)
                    if member_size > 16:
                        value_str += "..."

        members.append({
            "name": member_name,
            "offset": hex_addr(offset),
            "type": member_type,
            "size": member_size,
            "addr": hex_addr(member_addr),
            "value": value_str,
        })

    return {
        "struct": struct_name,
        "addr": hex_addr(ea),
        "size": tif.get_size(),
        "members": members,
    }


# ============================================================================
# Search Structs
# ============================================================================

@tool
@idaread
def search_structs(
    filter: Annotated[str, "Case-insensitive substring to search for in structure names"],
) -> dict:
    """Search for structures by name substring."""
    results: List[dict] = []

    try:
        limit = compat.get_ordinal_limit()
    except Exception:
        # Fallback
        limit = ida_typeinf.get_ordinal_qty(None) + 1  # type: ignore

    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal):
            type_name = tif.get_type_name()
            if type_name and filter.lower() in type_name.lower():
                if tif.is_udt():
                    udt_data = ida_typeinf.udt_type_data_t()
                    cardinality = 0
                    is_union = False
                    if tif.get_udt_details(udt_data):
                        cardinality = udt_data.size()
                        is_union = udt_data.is_union

                    results.append({
                        "name": type_name,
                        "size": tif.get_size(),
                        "fields": cardinality,
                        "is_union": is_union,
                    })

    return {"filter": filter, "total": len(results), "structs": results}


# ============================================================================
# Export Functions
# ============================================================================

def _get_prototype(func) -> Optional[str]:
    """Get function prototype string."""
    try:
        tif = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(tif, func.start_ea):
            return tif._print(func.start_ea)
    except Exception:
        pass
    return None


def _decompile_safe(ea: int) -> Optional[str]:
    """Decompile function, returning None on failure."""
    try:
        import ida_hexrays  # type: ignore
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            return str(cfunc)
    except Exception:
        pass
    return None


def _get_comments(ea: int) -> dict:
    """Get all comments at an address."""
    result = {}
    with contextlib.suppress(Exception):
        cmt = ida_bytes.get_cmt(ea, 0)
        if cmt:
            result["regular"] = cmt
    with contextlib.suppress(Exception):
        cmt = ida_bytes.get_cmt(ea, 1)
        if cmt:
            result["repeatable"] = cmt
    return result if result else None


@tool
@idaread
def export_funcs(
    addr: Annotated[str, "Function address(es) or name(s), comma-separated"],
    format: Annotated[str, "Export format: 'json' (default), 'c_header', or 'prototypes'"] = "json",
) -> dict:
    """Export function data in various formats (JSON with code, C header, or prototypes)."""
    queries = normalize_list_input(addr)
    results: List[dict] = []

    for fn_str in queries:
        parsed = parse_address(fn_str)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"addr": fn_str, "error": f"Cannot resolve: {fn_str}"})
            continue

        ea = parsed["value"]
        func = idaapi.get_func(ea)
        if not func:
            results.append({"addr": fn_str, "error": "Function not found"})
            continue

        func_data: dict = {
            "addr": hex_addr(func.start_ea),
            "name": ida_funcs.get_func_name(func.start_ea),
            "prototype": _get_prototype(func),
            "size": hex_addr(func.end_ea - func.start_ea),
        }

        comments = _get_comments(ea)
        if comments:
            func_data["comments"] = comments

        if format == "json":
            func_data["code"] = _decompile_safe(ea)

        results.append(func_data)

    fmt = format.lower().strip()
    if fmt == "c_header":
        lines = ["// Auto-generated by IDA MCP", ""]
        for func in results:
            if "prototype" in func and func["prototype"]:
                lines.append(f"{func['prototype']};")
        return {"format": "c_header", "content": "\n".join(lines)}

    elif fmt == "prototypes":
        prototypes = []
        for func in results:
            if "prototype" in func and func["prototype"]:
                prototypes.append({"name": func.get("name"), "prototype": func["prototype"]})
        return {"format": "prototypes", "functions": prototypes}

    return {"format": "json", "functions": results}
