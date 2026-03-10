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
import ida_bytes  # type: ignore
import ida_search  # type: ignore
import ida_funcs  # type: ignore
import ida_name  # type: ignore
import ida_ida  # type: ignore


# ============================================================================
# Unified Search
# ============================================================================

def _get_min_ea() -> int:
    """Get minimum IDB address."""
    try:
        return ida_ida.inf_get_min_ea()  # type: ignore
    except Exception:
        try:
            return idaapi.cvar.inf.min_ea  # type: ignore
        except Exception:
            return 0

def _get_max_ea() -> int:
    """Get maximum IDB address."""
    try:
        return ida_ida.inf_get_max_ea()  # type: ignore
    except Exception:
        try:
            return idaapi.cvar.inf.max_ea  # type: ignore
        except Exception:
            return 0xFFFFFFFFFFFFFFFF

def _bin_search(start: int, end: int, data: bytes) -> int:
    """Binary search for exact bytes, compatible across IDA versions."""
    mask = b"\xff" * len(data)
    try:
        # IDA 9.x
        return idaapi.bin_search(
            start, end, data, mask,
            idaapi.BIN_SEARCH_FORWARD | idaapi.BIN_SEARCH_NOBREAK,
        )
    except Exception:
        pass
    try:
        # IDA 8.x ida_bytes
        return ida_bytes.bin_search(
            start, end, data, mask,
            ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK,
        )
    except Exception:
        pass
    return idaapi.BADADDR


@tool
@idaread
def find(
    type: Annotated[str, "Search type: 'string', 'immediate', 'data_ref', or 'code_ref'"],
    target: Annotated[str, "Search target (string to find, integer value, or address)"],
    limit: Annotated[int, "Max matches (default: 100, max: 10000)"] = 100,
) -> dict:
    """Search for patterns in the binary (strings, immediate values, or references)."""
    if limit <= 0 or limit > 10000:
        limit = 10000

    search_type = type.strip().lower()
    matches: List[dict] = []
    truncated = False

    if search_type == "string":
        # Search for UTF-8 byte pattern in the binary
        pattern_bytes = target.encode("utf-8")
        if not pattern_bytes:
            return {"type": search_type, "query": target, "matches": [], "total": 0, "error": "Empty pattern"}

        ea = _get_min_ea()
        max_ea = _get_max_ea()
        while ea != idaapi.BADADDR and len(matches) < limit:
            ea = _bin_search(ea, max_ea, pattern_bytes)
            if ea == idaapi.BADADDR:
                break
            entry: dict = {"ea": hex_addr(ea)}
            func = idaapi.get_func(ea)
            if func:
                entry["function"] = ida_funcs.get_func_name(func.start_ea)
            matches.append(entry)
            ea += 1

        if len(matches) >= limit:
            truncated = True

    elif search_type == "immediate":
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
        parsed = parse_address(target)
        if not parsed["ok"] or parsed["value"] is None:
            return {"type": search_type, "query": target, "matches": [], "total": 0, "error": f"Cannot resolve: {target}"}

        target_ea = parsed["value"]
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
