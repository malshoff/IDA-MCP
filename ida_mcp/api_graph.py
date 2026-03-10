"""Graph analysis API - Call graph traversal and callee analysis.

Provides tools:
    - callgraph      Build call graph from root functions
    - callees        Get functions called by specified functions
"""
from __future__ import annotations

from typing import Annotated, Optional, List, Union

from .rpc import tool
from .sync import idaread
from .utils import parse_address, hex_addr, normalize_list_input

# IDA modules
import idaapi  # type: ignore
import idautils  # type: ignore
import ida_funcs  # type: ignore
import ida_name  # type: ignore
import ida_ua  # type: ignore


def _resolve_addr(query: str):
    """Resolve address from hex string or IDA name. Returns (ea, error_str)."""
    parsed = parse_address(query)
    if parsed["ok"] and parsed["value"] is not None:
        return parsed["value"], None
    # Fallback: try as IDA symbol name
    try:
        ea = idaapi.get_name_ea(idaapi.BADADDR, query)
        if ea != idaapi.BADADDR:
            return ea, None
    except Exception:
        pass
    return None, f"Cannot resolve: {query}"


# ============================================================================
# Call Graph
# ============================================================================

@tool
@idaread
def callgraph(
    roots: Annotated[str, "Root function address(es) or name(s), comma-separated"],
    max_depth: Annotated[int, "Maximum traversal depth (default: 5)"] = 5,
    max_nodes: Annotated[int, "Max nodes in graph (default: 1000, max: 100000)"] = 1000,
    max_edges: Annotated[int, "Max edges in graph (default: 5000, max: 200000)"] = 5000,
    max_edges_per_func: Annotated[int, "Max edges per function (default: 200, max: 5000)"] = 200,
) -> dict:
    """Build call graph starting from root functions."""
    if max_depth < 0:
        max_depth = 0
    if max_nodes <= 0 or max_nodes > 100000:
        max_nodes = 100000
    if max_edges <= 0 or max_edges > 200000:
        max_edges = 200000
    if max_edges_per_func <= 0 or max_edges_per_func > 5000:
        max_edges_per_func = 5000

    queries = normalize_list_input(roots)
    results: List[dict] = []

    for root_str in queries:
        ea, err = _resolve_addr(root_str)
        if ea is None:
            results.append({"root": root_str, "error": err, "nodes": [], "edges": []})
            continue

        func = idaapi.get_func(ea)
        if not func:
            results.append({"root": root_str, "error": "Function not found", "nodes": [], "edges": []})
            continue

        nodes = {}
        edges: List[dict] = []
        visited: set = set()
        truncated = False
        per_func_capped = False
        limit_reason = None

        def _hit_limit(reason: str):
            nonlocal truncated, limit_reason
            truncated = True
            limit_reason = reason

        def _traverse(addr: int, depth: int):
            nonlocal per_func_capped
            if truncated or depth > max_depth or addr in visited:
                return
            if len(nodes) >= max_nodes:
                _hit_limit("nodes")
                return
            visited.add(addr)

            f = idaapi.get_func(addr)
            if not f:
                return

            func_name = ida_funcs.get_func_name(f.start_ea)
            nodes[addr] = {
                "addr": hex_addr(addr),
                "name": func_name,
                "depth": depth,
            }

            edges_added = 0
            for item_ea in idautils.FuncItems(f.start_ea):
                if truncated:
                    break
                for xref in idautils.CodeRefsFrom(item_ea, 0):
                    if truncated:
                        break
                    if edges_added >= max_edges_per_func:
                        per_func_capped = True
                        break
                    callee_func = idaapi.get_func(xref)
                    if callee_func:
                        if len(edges) >= max_edges:
                            _hit_limit("edges")
                            break
                        edges.append({
                            "from": hex_addr(addr),
                            "to": hex_addr(callee_func.start_ea),
                            "type": "call",
                        })
                        edges_added += 1
                        _traverse(callee_func.start_ea, depth + 1)
                if edges_added >= max_edges_per_func:
                    break

        _traverse(ea, 0)

        results.append({
            "root": root_str,
            "nodes": list(nodes.values()),
            "edges": edges,
            "max_depth": max_depth,
            "truncated": truncated,
            "limit_reason": limit_reason,
            "per_func_capped": per_func_capped,
        })

    return {"results": results}


# ============================================================================
# Callees
# ============================================================================

@tool
@idaread
def callees(
    addr: Annotated[str, "Function address(es) or name(s), comma-separated"],
    limit: Annotated[int, "Max callees per function (default: 200, max: 500)"] = 200,
) -> dict:
    """Get functions called by the specified functions."""
    if limit <= 0 or limit > 500:
        limit = 500

    queries = normalize_list_input(addr)
    results: List[dict] = []

    for fn_str in queries:
        ea, err = _resolve_addr(fn_str)
        if ea is None:
            results.append({"addr": fn_str, "callees": None, "error": err})
            continue

        func = idaapi.get_func(ea)
        if not func:
            results.append({"addr": fn_str, "callees": None, "error": "No function found"})
            continue

        func_end = func.end_ea
        callees_dict: dict = {}
        more = False
        current_ea = func.start_ea

        while current_ea < func_end:
            if len(callees_dict) >= limit:
                more = True
                break

            insn = ida_ua.insn_t()
            insn_len = ida_ua.decode_insn(insn, current_ea)
            if insn_len == 0:
                next_ea = idaapi.next_head(current_ea, func_end)
                if next_ea == idaapi.BADADDR:
                    break
                current_ea = next_ea
                continue

            # Check for call instructions via xrefs
            for xref in idautils.CodeRefsFrom(current_ea, 0):
                callee_func = idaapi.get_func(xref)
                if xref not in callees_dict:
                    func_type = "internal" if callee_func is not None else "external"
                    func_name = ida_name.get_name(xref)
                    if func_name:
                        callees_dict[xref] = {
                            "addr": hex_addr(xref),
                            "name": func_name,
                            "type": func_type,
                        }

            next_ea = idaapi.next_head(current_ea, func_end)
            if next_ea == idaapi.BADADDR:
                break
            current_ea = next_ea

        results.append({
            "addr": fn_str,
            "callees": list(callees_dict.values()),
            "more": more,
        })

    return {"results": results}
