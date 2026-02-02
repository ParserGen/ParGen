from __future__ import annotations
import re
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from .syntax_validator import Issue, Severity
_MISALIGNED_VARIANT_RE = re.compile('bit_start=(?P<actual>\\d+)\\s+while\\s+other\\s+variants\\s+start\\s+at\\s+(?P<expected>\\d+)', re.IGNORECASE)

def _coerce_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value.is_integer():
            return int(value)
        return None
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return None
        try:
            return int(candidate, 0)
        except ValueError:
            return None
    return None

def _build_node_lookup(tree: Dict[str, Any]) -> Dict[Any, Dict[str, Any]]:
    nodes = tree.get('nodes', []) if isinstance(tree, dict) else []
    lookup: Dict[Any, Dict[str, Any]] = {}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        nid = node.get('node_id')
        if nid is None:
            continue
        lookup[nid] = node
        lookup[str(nid)] = node
    return lookup

def _walk_subtree(root_id: int, lookup: Dict[Any, Dict[str, Any]]) -> List[int]:
    seen: Set[int] = {int(root_id)}
    out: List[int] = [int(root_id)]
    stack: List[int] = [int(root_id)]
    while stack:
        nid = stack.pop()
        node = lookup.get(nid) or lookup.get(str(nid)) or {}
        for cid in node.get('children_ids') or []:
            cid_int = _coerce_int(cid)
            if cid_int is None or cid_int in seen:
                continue
            seen.add(cid_int)
            out.append(cid_int)
            stack.append(cid_int)
    return out

def _shift_subtree_bit_starts(tree: Dict[str, Any], root_id: int, delta_bits: int) -> List[str]:
    lookup = _build_node_lookup(tree)
    changes: List[str] = []
    for nid in _walk_subtree(int(root_id), lookup):
        node = lookup.get(nid) or lookup.get(str(nid))
        if not node:
            continue
        start = _coerce_int(node.get('bit_start'))
        if start is None:
            continue
        new_start = start + int(delta_bits)
        if new_start < 0:
            continue
        if new_start == start:
            continue
        node['bit_start'] = int(new_start)
        changes.append(f'shift node {nid}.bit_start {start}->{new_start}')
    return changes

def repair_misaligned_variant_starts(tree: Dict[str, Any], issues: Iterable[Issue]) -> List[str]:
    lookup = _build_node_lookup(tree)
    changes: List[str] = []
    for issue in issues:
        if getattr(issue, 'severity', None) != Severity.ERROR:
            continue
        if (getattr(issue, 'code', None) or '') != 'MISALIGNED_VARIANT_START':
            continue
        target = getattr(issue, 'target', None)
        var_id = _coerce_int(getattr(target, 'identifier', None) if target else None)
        if var_id is None:
            continue
        node = lookup.get(var_id) or lookup.get(str(var_id))
        if not node:
            continue
        current_start = _coerce_int(node.get('bit_start'))
        if current_start is None:
            continue
        match = _MISALIGNED_VARIANT_RE.search(str(getattr(issue, 'description', '') or ''))
        if not match:
            continue
        expected_start = _coerce_int(match.group('expected'))
        actual_start = _coerce_int(match.group('actual'))
        if expected_start is None or actual_start is None:
            continue
        actual_start = current_start
        delta = expected_start - actual_start
        if delta == 0:
            continue
        changes.extend(_shift_subtree_bit_starts(tree, int(var_id), int(delta)))
        changes.append(f'repair MISALIGNED_VARIANT_START variant={var_id} delta={delta}')
    return changes

def repair_missing_length_of_from_byte_count(tree: Dict[str, Any]) -> List[str]:
    candidate = tree
    lookup = _build_node_lookup(candidate)
    edges = candidate.get('edges')
    if not isinstance(edges, list):
        edges = []
        candidate['edges'] = edges
    incoming_length_of: Dict[Any, List[Dict[str, Any]]] = defaultdict(list)
    for e in edges:
        if not isinstance(e, dict):
            continue
        if e.get('rel') != 'length_of':
            continue
        incoming_length_of[e.get('dst')].append(e)

    def _has_length_of(dst_id: Any) -> bool:
        return bool(incoming_length_of.get(dst_id) or incoming_length_of.get(str(dst_id)))
    changes: List[str] = []
    leaf_types = {'field', 'selector', 'type', 'length', 'checksum'}
    variable_tokens = {'variable', 'unknown', 'dynamic'}
    for node in list(candidate.get('nodes') or []):
        if not isinstance(node, dict):
            continue
        nid = node.get('node_id')
        if nid is None:
            continue
        ntype = str(node.get('node_type') or '').lower()
        if ntype not in leaf_types:
            continue
        if _has_length_of(nid):
            continue
        size_expr = node.get('size_bits')
        if not isinstance(size_expr, str) or size_expr.strip().lower() not in variable_tokens:
            continue
        data_type = str(node.get('data_type') or '').lower()
        if data_type not in {'bytes', 'bitfield', 'binary'}:
            continue
        parent_id = node.get('parent_id')
        parent = lookup.get(parent_id) or lookup.get(str(parent_id)) or {}
        children = parent.get('children_ids') or []
        idx: Optional[int] = None
        try:
            idx = children.index(nid)
        except ValueError:
            try:
                idx = children.index(str(nid))
            except ValueError:
                idx = None
        if idx is None or idx <= 0:
            continue
        prev_id = children[idx - 1]
        prev_node = lookup.get(prev_id) or lookup.get(str(prev_id)) or {}
        prev_size = _coerce_int(prev_node.get('size_bits'))
        prev_name = str(prev_node.get('name') or '').lower()
        if prev_size != 8:
            continue
        if 'byte_count' not in prev_name and 'byte count' not in prev_name:
            continue
        src_id = _coerce_int(prev_node.get('node_id'))
        dst_id = _coerce_int(nid)
        if src_id is None or dst_id is None:
            continue
        if any((isinstance(e, dict) and e.get('rel') == 'length_of' and (_coerce_int(e.get('src')) == src_id) and (_coerce_int(e.get('dst')) == dst_id) for e in edges)):
            continue
        edges.append({'src': int(src_id), 'dst': int(dst_id), 'rel': 'length_of', 'formula': f'val({int(src_id)})*8', 'message_type': node.get('message_type') or prev_node.get('message_type') or 'bidirectional'})
        incoming_length_of[dst_id].append(edges[-1])
        changes.append(f'add length_of {src_id}->{dst_id}')
    return changes
