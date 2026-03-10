"""Search API - Unified search and regex string search.

Provides tools:
    - find            Search for strings, immediates, data refs, or code refs
    - find_regex      Regex search across IDB string list
"""
from __future__ import annotations

import re
from typing import Annotated, Optional, List, Union

from .rpc import tool
from .sync import idaread
from .utils import parse_address, hex_addr

# IDA modules
import idaapi  # type: ignore
import idautils  # type: ignore
import ida_funcs  # type: ignore
import ida_name  # type: ignore


def _resolve_addr(query: str):
    """Resolve address from hex string or IDA name. Returns (ea, error_str)."""
    parsed = parse_address(query)
    if parsed["ok"] and parsed["value"] is not None:
        return parsed["value"], None
    try:
        ea = idaapi.get_name_ea(idaapi.BADADDR, query)
        if ea != idaapi.BADADDR:
            return ea, None
    except Exception:
        pass
    return None, f"Cannot resolve: {query}"


# ============================================================================
# Unified Search
# ============================================================================

@tool
@idaread
def find(
    type: Annotated[str, "Search type: 'immediate', 'data_ref', or 'code_ref'"],
    target: Annotated[str, "Search target (integer value or address)"],
    limit: Annotated[int, "Max matches (default: 100, max: 10000)"] = 100,
) -> dict:
    """Search for patterns in the binary (immediate values or references). Use find_regex for string search."""
    if limit <= 0 or limit > 10000:
        limit = 10000

    search_type = type.strip().lower()
    matches: List[dict] = []
    truncated = False

    if search_type == "immediate":
        # Search for immediate value in instructions
        try:
            value = int(target, 0)
        except ValueError:
            return {"type": search_type, "query": target, "matches": [], "total": 0, "error": "Invalid number"}

        # Search across executable segments
        for seg_ea in idautils.Segments():
            if len(matches) >= limit:
                truncated = True
                break
            seg = idaapi.getseg(seg_ea)
            if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
                continue

            current_ea = seg.start_ea
            while current_ea < seg.end_ea and len(matches) < limit:
                insn = idaapi.insn_t()
                insn_len = idaapi.decode_insn(insn, current_ea)
                if insn_len > 0:
                    # Check all operands for the immediate value
                    for i in range(8):
                        op = insn.ops[i]
                        if op.type == 0:  # o_void
                            break
                        if op.type == idaapi.o_imm and op.value == value:
                            entry = {"ea": hex_addr(current_ea)}
                            func = idaapi.get_func(current_ea)
                            if func:
                                entry["function"] = ida_funcs.get_func_name(func.start_ea)
                            matches.append(entry)
                            break
                next_ea = idaapi.next_head(current_ea, seg.end_ea)
                if next_ea == idaapi.BADADDR:
                    break
                current_ea = next_ea

    elif search_type in ("data_ref", "code_ref"):
        # Search for references to an address
        ea_resolved, err = _resolve_addr(target)
        if ea_resolved is None:
            return {"type": search_type, "query": target, "matches": [], "total": 0, "error": err}

        target_ea = ea_resolved
        xref_iter = idautils.DataRefsTo(target_ea) if search_type == "data_ref" else idautils.CodeRefsTo(target_ea, 1)
        for ref_ea in xref_iter:
            if len(matches) >= limit:
                truncated = True
                break
            entry = {"ea": hex_addr(ref_ea)}
            func = idaapi.get_func(ref_ea)
            if func:
                entry["function"] = ida_funcs.get_func_name(func.start_ea)
            matches.append(entry)

    else:
        return {"type": search_type, "query": target, "matches": [], "total": 0,
                "error": f"Unknown search type: {type}. Use 'string', 'immediate', 'data_ref', or 'code_ref'."}

    result: dict = {
        "type": search_type,
        "query": target,
        "total": len(matches),
        "matches": matches,
    }
    if truncated:
        result["truncated"] = True
    return result


# ============================================================================
# Regex String Search
# ============================================================================

@tool
@idaread
def find_regex(
    pattern: Annotated[str, "Regex pattern to search for in IDB strings"],
    limit: Annotated[int, "Max matches (default: 100, max: 500)"] = 100,
) -> dict:
    """Search strings in the database with case-insensitive regex patterns."""
    if limit <= 0:
        limit = 100
    if limit > 500:
        limit = 500

    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return {"error": f"Invalid regex: {e}", "matches": [], "total": 0}

    matches: List[dict] = []
    truncated = False

    # Build string list from IDA
    sc = idautils.Strings()
    for s in sc:
        if len(matches) >= limit:
            truncated = True
            break
        text = str(s)
        if regex.search(text):
            entry: dict = {"ea": hex_addr(s.ea), "string": text}
            func = idaapi.get_func(s.ea)
            if func:
                entry["function"] = ida_funcs.get_func_name(func.start_ea)
            matches.append(entry)

    result: dict = {
        "pattern": pattern,
        "total": len(matches),
        "matches": matches,
    }
    if truncated:
        result["truncated"] = True
    return result
