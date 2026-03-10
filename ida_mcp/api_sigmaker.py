"""Sigmaker API - Signature creation and searching (IDA format).

Provides tools:
    - create_sig      Generate a unique IDA-style signature for an address
    - search_sig      Search the database for matches of an IDA-style signature
"""
from __future__ import annotations

import contextlib
from typing import Annotated, Optional, List

from .rpc import tool
from .sync import idaread
from .utils import parse_address, hex_addr

# IDA modules
import idaapi  # type: ignore
import ida_funcs  # type: ignore

# sigmaker imports - graceful fallback if not available
_SIGMAKER_AVAILABLE = False
try:
    import sigmaker  # type: ignore
    _SIGMAKER_AVAILABLE = True
except ImportError:
    pass


# ============================================================================
# Signature Creation
# ============================================================================

@tool
@idaread
def create_sig(
    addr: Annotated[str, "Address or function name to create a signature for"],
    wildcard_operands: Annotated[bool, "Wildcard relocatable operands for stability across updates"] = True,
    max_length: Annotated[int, "Maximum signature length in bytes (1..500)"] = 100,
) -> dict:
    """Create a unique IDA-style signature for an address (e.g. '48 8B ? ? 48 89')."""
    if not _SIGMAKER_AVAILABLE:
        return {"error": "sigmaker module not found. Ensure sigmaker.py is in Python path."}

    if max_length < 1 or max_length > 500:
        return {"error": "max_length out of range (1..500)"}

    # Resolve the address
    parsed = parse_address(addr)
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": f"Cannot resolve address: {addr}"}

    ea = parsed["value"]

    # Build configuration - IDA format only, no interactive prompts
    cfg = sigmaker.SigMakerConfig(
        output_format=sigmaker.SignatureType.IDA,
        wildcard_operands=wildcard_operands,
        continue_outside_of_function=True,
        wildcard_optimized=True,
        enable_continue_prompt=False,
        ask_longer_signature=False,
        max_single_signature_length=max_length,
    )

    try:
        maker = sigmaker.SignatureMaker()
        result = maker.make_signature(ea, cfg)
    except Exception as e:
        return {"error": f"Signature generation failed: {e}"}

    if not result.signature or len(result.signature) == 0:
        return {"error": "Could not generate a signature for this address"}

    # Format as IDA-style string
    sig_str = format(result.signature, "ida")

    # Check uniqueness
    try:
        is_unique = sigmaker.SignatureSearcher.is_unique(sig_str)
    except Exception:
        is_unique = None

    # Get function name if available
    func_name = None
    with contextlib.suppress(Exception):
        f = ida_funcs.get_func(ea)
        if f:
            func_name = idaapi.get_func_name(f.start_ea)

    result_dict: dict = {
        "signature": sig_str,
        "address": hex_addr(ea),
        "length": len(result.signature),
        "unique": is_unique,
    }
    if func_name:
        result_dict["function"] = func_name

    return result_dict


# ============================================================================
# Signature Searching
# ============================================================================

@tool
@idaread
def search_sig(
    signature: Annotated[str, "IDA-style signature to search for (e.g. '48 8B ? ? 48 89')"],
    limit: Annotated[int, "Maximum number of results (1..1000)"] = 100,
) -> dict:
    """Search the database for all matches of an IDA-style signature."""
    if not _SIGMAKER_AVAILABLE:
        return {"error": "sigmaker module not found. Ensure sigmaker.py is in Python path."}

    if not signature or not signature.strip():
        return {"error": "empty signature"}
    if limit < 1 or limit > 1000:
        return {"error": "limit out of range (1..1000)"}

    # Parse/normalize the input signature
    try:
        sig_str = sigmaker.SignatureParser.parse(signature)
    except Exception as e:
        return {"error": f"Failed to parse signature: {e}"}

    if not sig_str:
        return {"error": "Unrecognized signature format"}

    # Search for matches
    try:
        all_matches = sigmaker.SignatureSearcher.find_all(sig_str)
    except Exception as e:
        return {"error": f"Search failed: {e}"}

    truncated = len(all_matches) > limit
    matches_to_return = all_matches[:limit]

    # Build result list with function context
    match_list: List[dict] = []
    for m in matches_to_return:
        ea = int(m)
        entry: dict = {"ea": hex_addr(ea)}

        func_name = None
        with contextlib.suppress(Exception):
            f = ida_funcs.get_func(ea)
            if f:
                func_name = idaapi.get_func_name(f.start_ea)
        if func_name:
            entry["function"] = func_name

        match_list.append(entry)

    result: dict = {
        "signature": sig_str,
        "total": len(all_matches),
        "matches": match_list,
    }
    if truncated:
        result["truncated"] = True

    return result
