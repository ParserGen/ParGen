from __future__ import annotations
from dataclasses import dataclass
import re
from typing import Any, Dict, List, Optional

@dataclass
class Node:
    id: int
    name: str
    kind: str
    data_type: str
    bit_start: Any
    size_bits: Any
    message_type: str
    parent_id: Optional[int]
    children_ids: List[int]
    constraints: List[str]
    description: str
    byte_order: str
    stop_condition: Optional[str] = None
    max_items: Optional[int] = None

@dataclass
class Edge:
    src: int
    dst: int
    rel: str
    formula: str
    message_type: str

@dataclass
class ParseIR:
    protocol_name: str
    root_id: int
    nodes: Dict[int, Node]
    edges: List[Edge]
_BIT_START_RE = re.compile('^(?P<base>\\d+)\\.bit_start\\s*\\+\\s*(?P<offset>-?\\d+)\\s*$')

def _parse_bit_start_ref(expr: Any) -> Optional[tuple[int, int]]:
    s = str(expr or '').strip()
    if not s:
        return None
    m = _BIT_START_RE.match(s)
    if not m:
        return None
    try:
        return (int(m.group('base')), int(m.group('offset')))
    except Exception:
        return None
_ENUM_SINGLE_RE = re.compile('^\\s*enum\\s*:\\s*(?P<value>[^|]+)\\s*$', flags=re.IGNORECASE)

def _maybe_single_enum_value(constraints: List[str]) -> Optional[int]:
    for raw in constraints or []:
        s = str(raw or '').strip()
        if not s or '|' in s:
            continue
        m = _ENUM_SINGLE_RE.match(s)
        if not m:
            continue
        value = str(m.group('value') or '').strip()
        if not value:
            continue
        try:
            return int(value, 0)
        except Exception:
            continue
    return None

def _maybe_condition_on_eq_constant(*, formula: str, selector_id: int) -> Optional[int]:
    s = str(formula or '').replace(' ', '')
    if not s or f'val({int(selector_id)})' not in s:
        return None
    _, sep, rhs = s.partition('==')
    if sep != '==' or not rhs:
        return None
    m = re.match('^(0x[0-9a-fA-F]+|\\d+)', rhs)
    if not m:
        return None
    try:
        return int(m.group(1), 0)
    except Exception:
        return None

def _collapse_redundant_selector_aliases(parse_ir: ParseIR) -> None:
    nodes = parse_ir.nodes
    edges = parse_ir.edges
    referenced_by_edge: set[int] = set()
    for e in edges:
        referenced_by_edge.add(int(e.src))
        referenced_by_edge.add(int(e.dst))
    removed: set[int] = set()
    for edge in edges:
        if str(edge.rel or '').strip().lower() != 'condition_on':
            continue
        selector = nodes.get(int(edge.src))
        variant = nodes.get(int(edge.dst))
        if selector is None or variant is None:
            continue
        if selector.kind != 'selector' or variant.kind != 'variant':
            continue
        selector_size = _as_int(selector.size_bits)
        if selector_size <= 0:
            continue
        k = _maybe_condition_on_eq_constant(formula=str(edge.formula or ''), selector_id=int(selector.id))
        if k is None:
            continue
        v_start = _parse_bit_start_ref(variant.bit_start)
        if v_start is None or v_start != (int(selector.id), int(selector_size)):
            continue
        redundant_id: Optional[int] = None
        for child_id in list(variant.children_ids or []):
            child = nodes.get(int(child_id))
            if child is None or child.kind != 'field':
                continue
            if int(child_id) in referenced_by_edge:
                continue
            if _as_int(child.size_bits) != selector_size:
                continue
            c_start = _parse_bit_start_ref(child.bit_start)
            if c_start is None or c_start != (int(variant.id), 0):
                continue
            if _maybe_single_enum_value(child.constraints) != int(k):
                continue
            redundant_id = int(child_id)
            break
        if redundant_id is None:
            continue
        siblings = [cid for cid in variant.children_ids or [] if int(cid) != redundant_id]
        shift_bits = selector_size
        if any((_parse_bit_start_ref(nodes[int(cid)].bit_start) is None or (_parse_bit_start_ref(nodes[int(cid)].bit_start) or (None, None))[0] != int(variant.id) for cid in siblings if int(cid) in nodes)):
            continue
        variant.children_ids = siblings
        for sib_id in siblings:
            sib = nodes.get(int(sib_id))
            if sib is None:
                continue
            base, off = _parse_bit_start_ref(sib.bit_start) or (None, None)
            if base != int(variant.id) or off is None or off < shift_bits:
                continue
            sib.bit_start = f'{int(variant.id)}.bit_start + {int(off - shift_bits)}'
        v_size = _as_int(variant.size_bits)
        if v_size >= shift_bits and v_size > 0:
            variant.size_bits = int(v_size - shift_bits)
        removed.add(int(redundant_id))
    if not removed:
        return
    for rid in removed:
        nodes.pop(int(rid), None)
    for node in nodes.values():
        if node.children_ids:
            node.children_ids = [cid for cid in node.children_ids if int(cid) not in removed]

def build_parse_ir(tree_json: Dict[str, Any]) -> ParseIR:
    tree = tree_json.get('protocol_tree') or tree_json
    nodes_raw = tree.get('nodes') or []
    edges_raw = tree.get('edges') or []
    nodes: Dict[int, Node] = {}
    for raw in nodes_raw:
        if not isinstance(raw, dict):
            continue
        node_id = _as_int(raw.get('node_id') or raw.get('id') or len(nodes))
        name = str(raw.get('name') or f'node_{node_id}')
        raw_kind = raw.get('node_type') or raw.get('kind') or raw.get('type') or 'field'
        kind = normalize_kind(raw_kind)
        data_type = str(raw.get('data_type') or raw.get('field_type') or raw.get('value_type') or '')
        bit_start = raw.get('bit_start') or raw.get('start_bit') or raw.get('start')
        size_bits = raw.get('size_bits') or raw.get('bit_length') or raw.get('size')
        message_type = str(raw.get('message_type') or raw.get('direction') or raw.get('msg_type') or '')
        parent_id = _maybe_int(raw.get('parent_id'))
        children_ids = [_as_int(child) for child in raw.get('children_ids') or [] if child is not None]
        constraints = [str(c) for c in raw.get('constraints') or [] if c is not None]
        description = str(raw.get('description') or '')
        byte_order = str(raw.get('byte_order') or '')
        stop_condition = raw.get('stop_condition') or raw.get('repeat_until')
        stop_condition = str(stop_condition) if stop_condition is not None else None
        max_items = _maybe_int(raw.get('max_items'))
        nodes[node_id] = Node(id=node_id, name=name, kind=kind, data_type=data_type, bit_start=bit_start, size_bits=size_bits, message_type=message_type, parent_id=parent_id, children_ids=children_ids, constraints=constraints, description=description, byte_order=byte_order, stop_condition=stop_condition, max_items=max_items)
    root_id = _infer_root_id(tree, nodes)
    edges: List[Edge] = []
    for raw in edges_raw:
        if not isinstance(raw, dict):
            continue
        src = _as_int(raw.get('src') or raw.get('source') or 0)
        dst = _as_int(raw.get('dst') or raw.get('target') or 0)
        rel = str(raw.get('rel') or raw.get('relation') or '')
        formula = str(raw.get('formula') or raw.get('expr') or '')
        message_type = str(raw.get('message_type') or raw.get('direction') or '')
        edges.append(Edge(src=src, dst=dst, rel=rel, formula=formula, message_type=message_type))
    protocol_name = str(tree_json.get('protocol_name') or tree.get('name') or tree.get('protocol_name') or 'unknown_protocol')
    parse_ir = ParseIR(protocol_name=protocol_name, root_id=root_id, nodes=nodes, edges=edges)
    _collapse_redundant_selector_aliases(parse_ir)
    return parse_ir

def _as_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        try:
            return int(str(value), 0)
        except Exception:
            return 0

def _maybe_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        try:
            return int(str(value), 0)
        except Exception:
            return None

def _infer_root_id(tree: Dict[str, Any], nodes: Dict[int, Node]) -> int:
    explicit = tree.get('root_node_id') or tree.get('root_id')
    if explicit is not None:
        return _as_int(explicit)
    for node_id, node in nodes.items():
        if node.parent_id is None:
            return node_id
    if nodes:
        return next(iter(nodes.keys()))
    return 0

def normalize_kind(raw_kind: str) -> str:
    k = str(raw_kind).lower()
    mapping = {'protocol': 'protocol', 'header': 'header', 'payload': 'payload', 'container': 'container', 'tlv_seq': 'tlv_seq', 'selector': 'selector', 'variant': 'variant', 'field': 'field'}
    return mapping.get(k, 'field')
