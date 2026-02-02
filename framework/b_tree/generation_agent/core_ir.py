from __future__ import annotations
from typing import Dict, Any, List
import copy
import re
import logging
from framework.b_tree.tree_utils import normalize_protocol_tree
_ALLOWED_NODE_TYPES = {'protocol', 'header', 'payload', 'field', 'selector', 'variant', 'container', 'message', 'tlv_seq'}
_ALLOWED_MESSAGE_TYPES = {'bidirectional', 'request', 'response'}
_SIMPLE_SIZE_RE = re.compile('^val\\([^)]+\\)\\s*\\*\\s*8$')
_SAFE_EXPR_RE = re.compile('^[0-9A-Za-z_\\s\\(\\)\\.\\+\\-\\*/%<>=!&|,]+$')
_VAL_EQ_CONST_RE = re.compile('^val\\(\\s*(?P<id>-?\\d+)\\s*\\)\\s*==\\s*(?P<const>0x[0-9a-fA-F]+|\\d+)\\s*$')
_END_NAME_RE = re.compile('(?:^|[^a-z])(end|terminat|eom|eof|stop)(?:[^a-z]|$)', re.IGNORECASE)
_PAD_NAME_RE = re.compile('(?:^|[^a-z])(pad|padding)(?:[^a-z]|$)', re.IGNORECASE)
_BANNED_SIZE_SYMBOLS = {'total_bits', 'parent.', 'remaining_bits'}

def _coerce_int(value: Any) -> Any:
    try:
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            candidate = value.strip()
            if candidate:
                return int(candidate, 0)
    except Exception:
        return value
    return value

def canonicalize_protocol_tree(protocol_tree: Dict[str, Any]) -> Dict[str, Any]:
    logger = logging.getLogger(__name__)
    try:
        tree = normalize_protocol_tree(copy.deepcopy(protocol_tree))
    except Exception as exc:
        logger.warning('canonicalize_protocol_tree failed to normalize tree; returning input as-is: %s', exc, exc_info=True)
        tree = copy.deepcopy(protocol_tree)
    nodes: List[Dict[str, Any]] = tree.get('nodes', [])
    node_by_id: Dict[Any, Dict[str, Any]] = {n.get('node_id'): n for n in nodes if isinstance(n, dict) and n.get('node_id') is not None}
    root_id = tree.get('root_node_id')
    if root_id not in node_by_id:
        candidate = next((n for n in nodes if n.get('parent_id') in (None, -1)), nodes[0] if nodes else None)
        if candidate:
            root_id = candidate.get('node_id')
            tree['root_node_id'] = root_id
    if root_id in node_by_id:
        node_by_id[root_id]['node_type'] = 'protocol'
    for node in nodes:
        raw_type = (node.get('node_type') or '').strip().lower()
        if raw_type not in _ALLOWED_NODE_TYPES:
            name_desc = f"{node.get('name', '')} {node.get('description', '')}".lower()
            if 'header' in name_desc:
                node['node_type'] = 'header'
            elif 'payload' in name_desc or 'pdu' in name_desc:
                node['node_type'] = 'payload'
            elif 'message' in name_desc:
                node['node_type'] = 'message'
            else:
                node['node_type'] = 'field'
        else:
            node['node_type'] = raw_type
        if 'message_type' in node:
            mt = (node.get('message_type') or '').strip().lower()
            node['message_type'] = mt if mt in _ALLOWED_MESSAGE_TYPES else 'bidirectional'
        size_bits = node.get('size_bits')
        mark_needs_binding = False
        if isinstance(size_bits, int):
            pass
        elif isinstance(size_bits, str):
            stripped = size_bits.strip()
            if stripped.isdigit() or (stripped.startswith('-') and stripped[1:].isdigit()):
                node['size_bits'] = stripped
            elif _SIMPLE_SIZE_RE.match(stripped.replace(' ', '')):
                node['size_bits'] = re.sub('\\\\s+', ' ', stripped)
            elif _SAFE_EXPR_RE.match(stripped) and ':' not in stripped and (not any((sym in stripped.lower() for sym in _BANNED_SIZE_SYMBOLS))):
                node['size_bits'] = re.sub('\\\\s+', ' ', stripped)
            else:
                node['size_bits'] = 'variable'
                mark_needs_binding = True
        else:
            node['size_bits'] = 'variable'
            mark_needs_binding = True
        if mark_needs_binding:
            node['needs_length_binding'] = True

    def _coerce_int_or_none(val: Any) -> Any:
        try:
            if isinstance(val, bool):
                return None
            if isinstance(val, int):
                return val
            if isinstance(val, str) and val.strip():
                return int(val.strip(), 0)
        except Exception:
            return None
        return None

    def _node_name(nid: Any) -> str:
        node = node_by_id.get(nid) or node_by_id.get(str(nid))
        if not isinstance(node, dict):
            return ''
        return str(node.get('name') or '')

    def _node_type(nid: Any) -> str:
        node = node_by_id.get(nid) or node_by_id.get(str(nid))
        if not isinstance(node, dict):
            return ''
        return str(node.get('node_type') or '').strip().lower()

    def _node_children(nid: Any) -> List[Any]:
        node = node_by_id.get(nid) or node_by_id.get(str(nid))
        if not isinstance(node, dict):
            return []
        kids = node.get('children_ids') or []
        return list(kids) if isinstance(kids, list) else []

    def _is_zero_size_variant(nid: Any) -> bool:
        node = node_by_id.get(nid) or node_by_id.get(str(nid))
        if not isinstance(node, dict):
            return False
        if str(node.get('node_type') or '').strip().lower() != 'variant':
            return False
        if node.get('children_ids'):
            return False
        sb = node.get('size_bits')
        if sb == 0:
            return True
        if isinstance(sb, str) and sb.strip() in {'0', '+0', '-0'}:
            return True
        return False

    def _parse_val_eq_const(formula: Any) -> Any:
        if not isinstance(formula, str):
            return None
        stripped = formula.strip()
        m = _VAL_EQ_CONST_RE.match(stripped)
        if not m:
            return None
        try:
            selector_id = int(m.group('id'), 0)
            const_val = int(m.group('const'), 0)
        except Exception:
            return None
        return (selector_id, const_val, stripped)

    def _collect_descendants(root: Any, children_map: Dict[Any, List[Dict[str, Any]]]) -> set[Any]:
        seen: set[Any] = set()
        stack: List[Any] = [root]
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            for child in children_map.get(cur, []) or []:
                cid = child.get('node_id')
                if cid is None:
                    continue
                stack.append(cid)
        return seen

    def _infer_stop_condition_for_tlv_seq(tlv_id: Any, descendants: set[Any], edges: List[Dict[str, Any]]) -> Any:
        candidates: List[tuple[int, int, str, str]] = []
        for e in edges:
            if not isinstance(e, dict):
                continue
            if str(e.get('rel') or '').strip() != 'condition_on':
                continue
            dst = e.get('dst')
            if dst is None or dst not in descendants:
                continue
            if not _is_zero_size_variant(dst):
                continue
            parsed = _parse_val_eq_const(e.get('formula'))
            if not parsed:
                continue
            _sel, const_val, formula_str = parsed
            vname = _node_name(dst)
            score = 0
            if _END_NAME_RE.search(vname) and (not _PAD_NAME_RE.search(vname)):
                score += 100
            if const_val != 0:
                score += 10
            candidates.append((score, const_val, formula_str, vname))
        if not candidates:
            return None
        candidates.sort(key=lambda t: (t[0], t[1]), reverse=True)
        best = candidates[0]
        if best[0] >= 100:
            return best[2]
        consts = {c[1] for c in candidates}
        if 0 in consts and len(consts) >= 2:
            best = max(candidates, key=lambda t: t[1])
            return best[2]
        return None
    edges_raw = tree.get('edges', [])
    edges_list: List[Dict[str, Any]] = edges_raw if isinstance(edges_raw, list) else []
    root_id = tree.get('root_node_id')
    for e in edges_list:
        if not isinstance(e, dict) or str(e.get('rel') or '').strip() != 'condition_on':
            continue
        sid = _coerce_int_or_none(e.get('src'))
        vid = _coerce_int_or_none(e.get('dst'))
        if sid is None or vid is None:
            continue
        sel = node_by_id.get(sid) or node_by_id.get(str(sid))
        var = node_by_id.get(vid) or node_by_id.get(str(vid))
        if not isinstance(sel, dict) or not isinstance(var, dict):
            continue
        if str(sel.get('node_type') or '').strip().lower() != 'selector':
            continue
        if str(var.get('node_type') or '').strip().lower() != 'variant':
            continue
        if _coerce_int_or_none(var.get('parent_id')) != int(sid):
            continue
        sel_size = _coerce_int_or_none(sel.get('size_bits'))
        if sel_size is None or int(sel_size) <= 0:
            continue
        var_bs = var.get('bit_start')
        if not isinstance(var_bs, str) or not var_bs.strip():
            continue
        var_bs_norm = var_bs.strip().replace(' ', '')
        after_sel_norm = f'{int(sid)}.bit_start+{int(sel_size)}'
        if var_bs_norm != after_sel_norm:
            continue
        parent_id = _coerce_int_or_none(sel.get('parent_id'))
        if parent_id is None:
            continue
        parent = node_by_id.get(parent_id) or node_by_id.get(str(parent_id))
        if not isinstance(parent, dict):
            continue
        sel_children = sel.get('children_ids')
        if isinstance(sel_children, list) and sel_children:
            sel['children_ids'] = [c for c in sel_children if _coerce_int_or_none(c) != int(vid)]
        parent_children = parent.get('children_ids')
        if not isinstance(parent_children, list):
            parent_children = []
            parent['children_ids'] = parent_children
        if int(vid) not in {_coerce_int_or_none(c) for c in parent_children}:
            try:
                idx = next((i for i, c in enumerate(parent_children) if _coerce_int_or_none(c) == int(sid)))
                parent_children.insert(idx + 1, int(vid))
            except StopIteration:
                parent_children.append(int(vid))
        var['parent_id'] = int(parent_id)
    children_map: Dict[Any, List[Dict[str, Any]]] = {}
    for node in nodes:
        parent_id = node.get('parent_id')
        children_map.setdefault(parent_id, []).append(node)
    tlv_nodes = [n for n in nodes if isinstance(n, dict) and str(n.get('node_type') or '').strip().lower() == 'tlv_seq']
    if tlv_nodes:
        max_node_id = -1
        for n in nodes:
            nid_int = _coerce_int_or_none(n.get('node_id') if isinstance(n, dict) else None)
            if isinstance(nid_int, int) and nid_int > max_node_id:
                max_node_id = nid_int
        for tlv in tlv_nodes:
            tlv_id = tlv.get('node_id')
            if tlv_id is None:
                continue
            stop_formula = tlv.get('stop_condition') or tlv.get('repeat_until')
            if not stop_formula and edges_list:
                descendants = _collect_descendants(tlv_id, children_map)
                inferred = _infer_stop_condition_for_tlv_seq(tlv_id, descendants, edges_list)
                if inferred:
                    stop_formula = inferred
                    tlv['stop_condition'] = inferred
            if not stop_formula:
                continue
            parent_id = tlv.get('parent_id')
            if parent_id is None:
                continue
            parent = node_by_id.get(parent_id) or node_by_id.get(str(parent_id))
            if not isinstance(parent, dict):
                continue
            parent_children = parent.get('children_ids')
            if not isinstance(parent_children, list) or tlv_id not in parent_children:
                continue
            if parent_children and parent_children[-1] != tlv_id:
                continue
            sibling_nodes = [_node_name(cid).lower() for cid in parent_children if cid != tlv_id]
            if any((_PAD_NAME_RE.search(name) for name in sibling_nodes)):
                continue
            parent_size = parent.get('size_bits')
            parent_size_is_variable = isinstance(parent_size, str) and parent_size.strip().lower() in {'variable', 'unknown', 'dynamic', ''}
            if parent_id != root_id and parent_size_is_variable:
                continue
            max_node_id += 1
            padding_id = max_node_id
            padding_node = {'node_id': int(padding_id), 'name': 'Padding', 'node_type': 'payload', 'description': 'Trailing bytes after TLV end marker (padding)', 'bit_start': f'{tlv_id}.bit_start + {tlv_id}.size_bits', 'size_bits': f'({parent_id}.bit_start + {parent_id}.size_bits) - {padding_id}.bit_start', 'data_type': 'binary', 'byte_order': parent.get('byte_order') or tlv.get('byte_order') or 'big', 'message_type': parent.get('message_type') or tlv.get('message_type') or 'bidirectional', 'constraints': [], 'dependencies': [], 'parent_id': parent_id, 'children_ids': [], 'source': ''}
            nodes.append(padding_node)
            node_by_id[padding_id] = padding_node
            node_by_id[str(padding_id)] = padding_node
            parent_children.append(padding_id)
            children_map.setdefault(parent_id, []).append(padding_node)
    tlv_seq_ids = {n.get('node_id') for n in nodes if isinstance(n, dict) and str(n.get('node_type') or '').strip().lower() == 'tlv_seq'}
    tlv_scoped_nodes: set[Any] = set(tlv_seq_ids)
    if tlv_seq_ids:
        stack: List[Any] = list(tlv_seq_ids)
        while stack:
            current_id = stack.pop()
            for child in children_map.get(current_id, []) or []:
                child_id = child.get('node_id')
                if child_id is None or child_id in tlv_scoped_nodes:
                    continue
                tlv_scoped_nodes.add(child_id)
                stack.append(child_id)
    for parent_id, kids in children_map.items():
        if parent_id is not None and parent_id in tlv_scoped_nodes:
            continue
        parent = node_by_id.get(parent_id)
        base = 0
        if parent is not None:
            p_bs = parent.get('bit_start')
            if isinstance(p_bs, int) and p_bs >= 0:
                base = p_bs

        def _key(n: Dict[str, Any]) -> int:
            bs = n.get('bit_start')
            return bs if isinstance(bs, int) and bs >= 0 else 10 ** 12
        non_variants = [k for k in kids if str(k.get('node_type') or '').lower() != 'variant']
        variants = [k for k in kids if str(k.get('node_type') or '').lower() == 'variant']
        current = base
        for child in sorted(non_variants, key=_key):
            bs = child.get('bit_start')
            if isinstance(bs, int):
                if bs < current:
                    child['bit_start'] = current
            elif isinstance(bs, str):
                stripped = bs.strip()
                if stripped and (stripped.isdigit() or (stripped.startswith('-') and stripped[1:].isdigit())):
                    try:
                        bs_int = int(stripped, 0)
                    except Exception:
                        bs_int = None
                    if bs_int is None or bs_int < current:
                        child['bit_start'] = current
                    else:
                        child['bit_start'] = bs_int
            else:
                child['bit_start'] = current
            sb = child.get('size_bits')
            sb_int = None
            if isinstance(sb, int):
                sb_int = sb
            elif isinstance(sb, str) and sb.strip().lstrip('-').isdigit():
                try:
                    sb_int = int(sb.strip(), 0)
                except Exception:
                    sb_int = None
            if sb_int is not None and sb_int >= 0:
                current += sb_int
        for child in sorted(variants, key=_key):
            bs = child.get('bit_start')
            if isinstance(bs, int):
                if bs < current:
                    child['bit_start'] = current
            elif isinstance(bs, str):
                stripped = bs.strip()
                if stripped and (stripped.isdigit() or (stripped.startswith('-') and stripped[1:].isdigit())):
                    try:
                        bs_int = int(stripped, 0)
                    except Exception:
                        bs_int = None
                    if bs_int is None or bs_int < current:
                        child['bit_start'] = current
                    else:
                        child['bit_start'] = bs_int
            else:
                child['bit_start'] = current
    return tree

def add_request_response_variants(protocol_tree: Dict[str, Any]) -> Dict[str, Any]:
    return protocol_tree
