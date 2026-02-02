from __future__ import annotations
import os
import re
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple
from .interpreter import LEAF_TYPES
from ..validation_agent.traffic_errors import TrafficParseFailure
_VARIABLE_TOKENS = {'variable', 'unknown', 'dynamic'}
_TLV_SEQ_NODE_TYPES = {'tlv_seq'}

def _coerce_int_or_none(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int) and (not isinstance(value, bool)):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            return int(s, 0)
        except Exception:
            return None
    return None

def _build_node_lookup(tree: Dict[str, Any]) -> Dict[Any, Dict[str, Any]]:
    lookup: Dict[Any, Dict[str, Any]] = {}
    for node in tree.get('nodes', []) if isinstance(tree, dict) else []:
        if not isinstance(node, dict):
            continue
        nid = node.get('node_id')
        if nid is None:
            continue
        lookup[nid] = node
        lookup[str(nid)] = node
    return lookup

def _node_label(lookup: Dict[Any, Dict[str, Any]], node_id: Any) -> str:
    node = lookup.get(node_id) or lookup.get(str(node_id)) or {}
    name = node.get('name') or node.get('node_name') or ''
    try:
        nid = int(node_id)
    except Exception:
        nid = node_id
    if name:
        return f'{name}(ID:{nid})'
    return f'node(ID:{nid})'

def _parse_selector_variants(sig: str) -> List[Tuple[int, int]]:
    if not sig:
        return []
    m = re.search('selector_variants=([0-9,>\\\\-]+)', sig)
    if not m:
        return []
    body = m.group(1)
    pairs: List[Tuple[int, int]] = []
    for part in body.split(','):
        part = part.strip()
        if not part:
            continue
        if '->' not in part:
            continue
        left, right = part.split('->', 1)
        sid = _coerce_int_or_none(left)
        vid = _coerce_int_or_none(right)
        if sid is None or vid is None:
            continue
        pairs.append((int(sid), int(vid)))
    return pairs

def _norm_text(text: Any) -> str:
    if text is None:
        return ''
    return str(text).strip().lower()

def _parse_enum_constraint(constraint: Any) -> Optional[List[int]]:
    if not isinstance(constraint, str):
        return None
    raw = constraint.strip()
    if not raw:
        return None
    if not raw.lower().startswith('enum:'):
        return None
    body = raw.split(':', 1)[1].strip()
    if not body:
        return None
    allowed: List[int] = []
    for part in body.split('|'):
        p = part.strip()
        if not p:
            continue
        try:
            allowed.append(int(p, 0))
        except Exception:
            return None
    return allowed or None

def _formula_is_simple_val(formula: Any, src_id: int) -> bool:
    if not isinstance(formula, str):
        return False
    f = formula.strip()
    if not f:
        return False
    pattern = f'\\(?\\s*val\\(\\s*{int(src_id)}\\s*\\)\\s*\\)?'
    return bool(re.fullmatch(pattern, f, flags=re.IGNORECASE))

def infer_repair_hints(tree: Dict[str, Any], failures: Iterable[TrafficParseFailure]) -> List[Dict[str, Any]]:
    failures_list = list(failures or [])
    if not failures_list:
        return []
    lookup = _build_node_lookup(tree)
    edges = tree.get('edges') if isinstance(tree, dict) else None
    if not isinstance(edges, list):
        edges = []
    incoming_length_of: Dict[Any, List[Dict[str, Any]]] = defaultdict(list)
    cond_on: Dict[Any, List[Dict[str, Any]]] = defaultdict(list)
    for e in edges:
        if not isinstance(e, dict):
            continue
        rel = e.get('rel')
        if rel == 'length_of':
            incoming_length_of[e.get('dst')].append(e)
        elif rel == 'condition_on':
            cond_on[e.get('dst')].append(e)

    def _has_length_of(dst_id: Any) -> bool:
        return bool(incoming_length_of.get(dst_id) or incoming_length_of.get(str(dst_id)))

    def _first_length_of_formula(dst_id: Any) -> Optional[str]:
        for key in (dst_id, str(dst_id)):
            for e in incoming_length_of.get(key, []) or []:
                formula = e.get('formula')
                if formula:
                    return str(formula)
        return None

    def _find_selector_for_variant(variant_id: Any) -> Optional[int]:
        for key in (variant_id, str(variant_id)):
            for e in cond_on.get(key, []) or []:
                sid = _coerce_int_or_none(e.get('src'))
                if sid is None:
                    continue
                sel = lookup.get(sid) or lookup.get(str(sid)) or {}
                if str(sel.get('node_type') or '').lower() == 'selector':
                    return int(sid)
        return None

    def _coerce_size_bits(value: Any) -> Optional[int]:
        if value is None:
            return None
        if isinstance(value, int) and (not isinstance(value, bool)):
            return int(value)
        if isinstance(value, float):
            return int(value) if value.is_integer() else None
        if isinstance(value, str):
            s = value.strip()
            if not s:
                return None
            if s.lower() in _VARIABLE_TOKENS:
                return None
            try:
                return int(s, 0)
            except Exception:
                return None
        return None

    def _is_ancestor(ancestor_id: int, node_id: int) -> bool:
        current_id: Optional[int] = int(node_id)
        seen: set[int] = set()
        while current_id is not None and current_id not in seen:
            seen.add(current_id)
            node = lookup.get(current_id) or lookup.get(str(current_id)) or {}
            parent_raw = node.get('parent_id')
            parent_id = _coerce_int_or_none(parent_raw)
            if parent_id is None:
                return False
            if int(parent_id) == int(ancestor_id):
                return True
            current_id = int(parent_id)
        return False

    def _walk_subtree_ids(root_id: int) -> List[int]:
        root_id = int(root_id)
        seen: set[int] = {root_id}
        out: List[int] = []
        stack: List[int] = [root_id]
        while stack:
            nid = stack.pop()
            node = lookup.get(nid) or lookup.get(str(nid)) or {}
            for cid in node.get('children_ids') or []:
                cid_int = _coerce_int_or_none(cid)
                if cid_int is None or cid_int in seen:
                    continue
                seen.add(cid_int)
                out.append(int(cid_int))
                stack.append(int(cid_int))
        return out

    def _subtree_has_internal_length_of(root_id: int) -> bool:
        root_id = int(root_id)
        subtree = {root_id}
        subtree.update(_walk_subtree_ids(root_id))
        for e in edges:
            if not isinstance(e, dict):
                continue
            if e.get('rel') != 'length_of':
                continue
            src = _coerce_int_or_none(e.get('src'))
            dst = _coerce_int_or_none(e.get('dst'))
            if src is None or dst is None:
                continue
            if int(src) in subtree and int(dst) in subtree:
                return True
        return False

    def _subtree_has_payload_node(root_id: int) -> bool:
        root_id = int(root_id)
        subtree = {root_id}
        subtree.update(_walk_subtree_ids(root_id))
        for nid in subtree:
            node = lookup.get(nid) or lookup.get(str(nid)) or {}
            if str(node.get('node_type') or '').strip().lower() == 'payload':
                return True
        return False
    path_counts: Counter[int] = Counter()
    failure_node_counts: Counter[int] = Counter()
    failure_kinds_by_node: Dict[int, Counter[str]] = defaultdict(Counter)
    variant_counts: Counter[int] = Counter()
    speculative_variant_counts: Counter[int] = Counter()
    speculative_variant_kinds: Dict[int, Counter[str]] = defaultdict(Counter)
    speculative_variant_samples: Dict[int, List[int]] = defaultdict(list)
    routing_candidate_counts: Counter[int] = Counter()
    routing_candidate_samples: Dict[int, List[int]] = defaultdict(list)
    tail_gap_bits_by_src: Dict[int, Counter[int]] = defaultdict(Counter)
    tail_gap_samples_by_src: Dict[int, List[int]] = defaultdict(list)
    tail_gap_payload_counts: Counter[Tuple[int, int, str]] = Counter()
    tail_gap_payload_samples: Dict[Tuple[int, int, str], List[int]] = defaultdict(list)
    enum_constraint_values_by_node: Dict[int, Counter[int]] = defaultdict(Counter)
    enum_constraint_samples_by_node: Dict[int, List[int]] = defaultdict(list)
    global_field_values: Dict[int, Counter[int]] = defaultdict(Counter)
    enum_failure_guard_values_by_node: Dict[int, Dict[int, Counter[int]]] = defaultdict(lambda: defaultdict(Counter))
    oob_overshoot_bits_by_node: Dict[int, Counter[int]] = defaultdict(Counter)
    oob_overshoot_samples_by_node: Dict[int, List[int]] = defaultdict(list)
    coverage_gap_counts: Counter[Tuple[int, int, str]] = Counter()
    coverage_gap_samples: Dict[Tuple[int, int, str], List[int]] = defaultdict(list)
    for f in failures_list:
        try:
            failure_kind = str(getattr(f, 'failure_kind', None) or '').strip().lower()
        except Exception:
            failure_kind = ''
        node_id = _coerce_int_or_none(getattr(f, 'node_id', None))
        if node_id is not None and failure_kind:
            failure_node_counts[int(node_id)] += 1
            failure_kinds_by_node[int(node_id)][str(failure_kind)] += 1
        if failure_kind == 'constraint':
            ckind = _norm_text(getattr(f, 'constraint_kind', None))
            if ckind == 'enum' and node_id is not None:
                val = _coerce_int_or_none(getattr(f, 'constraint_value', None))
                if val is not None:
                    enum_constraint_values_by_node[int(node_id)][int(val)] += 1
                    if len(enum_constraint_samples_by_node[int(node_id)]) < 8:
                        try:
                            pkt_idx = int(getattr(f, 'packet_index', 0) or 0)
                        except Exception:
                            pkt_idx = 0
                        enum_constraint_samples_by_node[int(node_id)].append(pkt_idx)
        ctx_vals_global = getattr(f, 'context_field_values', None) or {}
        if isinstance(ctx_vals_global, dict) and ctx_vals_global:
            for raw_id, raw_val in ctx_vals_global.items():
                fid = _coerce_int_or_none(raw_id)
                fval = _coerce_int_or_none(raw_val)
                if fid is None or fval is None:
                    continue
                global_field_values[int(fid)][int(fval)] += 1
        for nid in getattr(f, 'path_node_ids', None) or []:
            nid_int = _coerce_int_or_none(nid)
            if nid_int is not None:
                path_counts[int(nid_int)] += 1
        try:
            msg = str(getattr(f, 'message', None) or '')
            kind = str(getattr(f, 'failure_kind', None) or '').strip().lower()
        except Exception:
            msg = ''
            kind = ''
        if msg.startswith('routing_candidate_failed'):
            vid = _coerce_int_or_none(getattr(f, 'node_id', None))
            if vid is not None:
                routing_candidate_counts[int(vid)] += 1
                try:
                    pkt_idx = int(getattr(f, 'packet_index', 0) or 0)
                except Exception:
                    pkt_idx = 0
                if len(routing_candidate_samples[int(vid)]) < 8:
                    routing_candidate_samples[int(vid)].append(pkt_idx)
        if msg.startswith('speculative_candidate_failure'):
            vid = _coerce_int_or_none(getattr(f, 'node_id', None))
            if vid is not None:
                speculative_variant_counts[int(vid)] += 1
                if kind:
                    speculative_variant_kinds[int(vid)][kind] += 1
                try:
                    pkt_idx = int(getattr(f, 'packet_index', 0) or 0)
                except Exception:
                    pkt_idx = 0
                if len(speculative_variant_samples[int(vid)]) < 8:
                    speculative_variant_samples[int(vid)].append(pkt_idx)
        sig = str(getattr(f, 'group_signature', None) or '')
        for _sid, vid in _parse_selector_variants(sig):
            variant_counts[int(vid)] += 1
        if failure_kind in {'oob_seek', 'oob_read'}:
            nid = _coerce_int_or_none(getattr(f, 'node_id', None))
            bit_start = _coerce_int_or_none(getattr(f, 'bit_start', None))
            size_eval = _coerce_int_or_none(getattr(f, 'size_bits_eval', None))
            total_bits = _coerce_int_or_none(getattr(f, 'total_bits', None))
            if nid is not None and bit_start is not None and (size_eval is not None) and (total_bits is not None):
                overshoot = int(bit_start) + int(size_eval) - int(total_bits)
                if overshoot > 0:
                    oob_overshoot_bits_by_node[int(nid)][int(overshoot)] += 1
                    if len(oob_overshoot_samples_by_node[int(nid)]) < 8:
                        try:
                            pkt_idx = int(getattr(f, 'packet_index', 0) or 0)
                        except Exception:
                            pkt_idx = 0
                        oob_overshoot_samples_by_node[int(nid)].append(pkt_idx)
        if failure_kind == 'coverage_gap':
            src_id = _coerce_int_or_none(getattr(f, 'length_mismatch_src', None) or getattr(f, 'length_src_node_id', None))
            dst_id = _coerce_int_or_none(getattr(f, 'length_mismatch_dst', None) or getattr(f, 'node_id', None))
            formula = str(getattr(f, 'length_formula', None) or '').strip()
            if src_id is not None and dst_id is not None and formula:
                key = (int(src_id), int(dst_id), formula)
                coverage_gap_counts[key] += 1
                if len(coverage_gap_samples[key]) < 8:
                    try:
                        pkt_idx = int(getattr(f, 'packet_index', 0) or 0)
                    except Exception:
                        pkt_idx = 0
                    coverage_gap_samples[key].append(pkt_idx)
        tail_bits = getattr(f, 'coverage_tail_leftover_bits', None)
        if tail_bits is None:
            continue
        ctx_vals = getattr(f, 'context_field_values', None) or {}
        if not isinstance(ctx_vals, dict) or not ctx_vals:
            continue
        try:
            pkt_idx = int(getattr(f, 'packet_index', 0) or 0)
        except Exception:
            pkt_idx = 0

        def _is_bytes_like_payload(node: Dict[str, Any]) -> bool:
            node_type = _norm_text(node.get('node_type'))
            data_type = _norm_text(node.get('data_type'))
            if node_type != 'payload' and data_type not in {'bytes', 'binary'}:
                return False
            if node.get('children_ids'):
                return False
            raw_size_bits = node.get('size_bits')
            if raw_size_bits is None:
                return True
            if isinstance(raw_size_bits, (int, float)) and (not isinstance(raw_size_bits, bool)):
                return int(raw_size_bits) == 0
            if isinstance(raw_size_bits, str) and raw_size_bits.strip().lower() in _VARIABLE_TOKENS:
                return True
            return False
        payload_id: Optional[int] = None
        for pid in reversed(getattr(f, 'path_node_ids', None) or []):
            pid_int = _coerce_int_or_none(pid)
            if pid_int is None:
                continue
            node = lookup.get(pid_int) or lookup.get(str(pid_int)) or {}
            if not isinstance(node, dict):
                continue
            if not _is_bytes_like_payload(node):
                continue
            if _has_length_of(pid_int):
                continue
            payload_id = int(pid_int)
            break
        if payload_id is not None:
            current: Optional[int] = payload_id
            seen_ancestors: set[int] = set()
            while current is not None and current not in seen_ancestors:
                seen_ancestors.add(int(current))
                node = lookup.get(current) or lookup.get(str(current)) or {}
                parent_id = _coerce_int_or_none(node.get('parent_id')) if isinstance(node, dict) else None
                if parent_id is None:
                    break
                formula = _first_length_of_formula(parent_id)
                if isinstance(formula, str) and formula.strip():
                    key = (int(parent_id), int(payload_id), str(formula).strip())
                    tail_gap_payload_counts[key] += 1
                    if len(tail_gap_payload_samples[key]) < 8:
                        tail_gap_payload_samples[key].append(pkt_idx)
                    break
                current = parent_id
        for raw_src, raw_val in ctx_vals.items():
            src_id = _coerce_int_or_none(raw_src)
            val = _coerce_int_or_none(raw_val)
            if src_id is None or val is None:
                continue
            if int(val) * 8 == int(tail_bits):
                tail_gap_bits_by_src[int(src_id)][int(tail_bits)] += 1
                if len(tail_gap_samples_by_src[int(src_id)]) < 8:
                    tail_gap_samples_by_src[int(src_id)].append(int(getattr(f, 'packet_index', 0) or 0))
    hints: List[Dict[str, Any]] = []
    seen_keys: set[Tuple[str, int, int]] = set()
    try:
        spec_weight = int(os.getenv('STEP2_TRAFFIC_HINT_SPEC_WEIGHT', '3').strip())
    except Exception:
        spec_weight = 3
    spec_weight = max(1, spec_weight)
    for node in tree.get('nodes', []) if isinstance(tree, dict) else []:
        if not isinstance(node, dict):
            continue
        nid = _coerce_int_or_none(node.get('node_id'))
        if nid is None:
            continue
        ntype = str(node.get('node_type') or '').lower()
        if ntype not in LEAF_TYPES:
            continue
        if _has_length_of(nid):
            continue
        size_expr = node.get('size_bits')
        if not isinstance(size_expr, str) or size_expr.strip().lower() not in _VARIABLE_TOKENS:
            continue
        data_type = str(node.get('data_type') or '').lower()
        if data_type not in {'bytes', 'bitfield', 'binary'}:
            continue
        parent_id = node.get('parent_id')
        parent = lookup.get(parent_id) or lookup.get(str(parent_id)) or {}
        score = path_counts.get(nid, 0) + path_counts.get(_coerce_int_or_none(parent_id) or -1, 0)
        if score <= 0:
            continue
        children = parent.get('children_ids') or []
        try:
            idx = children.index(nid)
        except ValueError:
            try:
                idx = children.index(str(nid))
            except ValueError:
                idx = -1
        if idx <= 0:
            continue
        prev_id = _coerce_int_or_none(children[idx - 1])
        if prev_id is None:
            continue
        prev = lookup.get(prev_id) or lookup.get(str(prev_id)) or {}
        prev_size = _coerce_int_or_none(prev.get('size_bits'))
        if prev_size is None or prev_size <= 0:
            continue
        if prev_size not in {8, 16, 32}:
            continue
        prev_name = str(prev.get('name') or '').lower()
        name_bonus = 0.0
        if 'byte_count' in prev_name or 'byte count' in prev_name:
            name_bonus += 0.25
        if 'length' in prev_name or 'len' in prev_name or 'size' in prev_name or ('count' in prev_name):
            name_bonus += 0.05
        evidence = tail_gap_bits_by_src.get(prev_id, Counter())
        match_count = int(sum(evidence.values())) if evidence else 0
        try:
            max_tail_bits = max((int(k) for k in evidence.keys())) if evidence else 0
        except Exception:
            max_tail_bits = 0
        magnitude_bonus = min(5, max(0, int(max_tail_bits) // 256)) if max_tail_bits else 0
        evidence_bonus = 0.0
        if match_count >= 2:
            evidence_bonus += 0.2
        elif match_count == 1:
            evidence_bonus += 0.1
        formula = f'val({prev_id})*8'
        confidence = min(1.0, 0.4 + name_bonus + evidence_bonus)
        key = ('add_length_of', int(prev_id), int(nid))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        hints.append({'kind': 'add_length_of', 'score': int(score) + int(match_count) + int(magnitude_bonus), 'confidence': float(confidence), 'src_id': int(prev_id), 'dst_id': int(nid), 'formula': formula, 'description': 'Variable-length leaf without length binding; consider binding it to a preceding length/byte-count field to eliminate systematic tail gaps.', 'target': _node_label(lookup, nid), 'src': _node_label(lookup, prev_id), 'evidence': {'tail_gap_matches': dict(evidence) if evidence else {}, 'match_count': match_count, 'example_packets': tail_gap_samples_by_src.get(prev_id, [])}})
    for (src_id, dst_id, formula), occ in coverage_gap_counts.most_common():
        if occ <= 0:
            continue
        dst_node = lookup.get(dst_id) or lookup.get(str(dst_id)) or {}
        children = dst_node.get('children_ids') or []
        if not isinstance(children, list) or not children:
            continue
        candidates: List[int] = []
        for cid in children:
            cid_int = _coerce_int_or_none(cid)
            if cid_int is None:
                continue
            cnode = lookup.get(cid_int) or lookup.get(str(cid_int)) or {}
            if not isinstance(cnode, dict):
                continue
            cchildren = cnode.get('children_ids') or []
            node_type = str(cnode.get('node_type') or '').lower()
            leaf_like = node_type in LEAF_TYPES or not cchildren
            if not leaf_like:
                continue
            if _has_length_of(cid_int):
                continue
            size_bits = cnode.get('size_bits')
            if size_bits is None:
                candidates.append(int(cid_int))
                continue
            if isinstance(size_bits, (int, float)) and (not isinstance(size_bits, bool)):
                if int(size_bits) == 0:
                    candidates.append(int(cid_int))
                continue
            if isinstance(size_bits, str) and size_bits.strip().lower() in _VARIABLE_TOKENS:
                candidates.append(int(cid_int))
                continue
        if not candidates:
            continue
        dst_start = _coerce_int_or_none(dst_node.get('bit_start')) if isinstance(dst_node, dict) else None
        if dst_start is not None:
            ranked: List[Tuple[int, int]] = []
            for cid in candidates:
                cnode = lookup.get(cid) or lookup.get(str(cid)) or {}
                cstart = _coerce_int_or_none(cnode.get('bit_start')) if isinstance(cnode, dict) else None
                penalty = 0 if cstart == dst_start else 1
                ranked.append((penalty, cid))
            ranked.sort()
            candidates = [cid for _penalty, cid in ranked]
        leaf_id = candidates[0]
        key = ('add_length_of', int(src_id), int(leaf_id))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        hints.append({'kind': 'add_length_of', 'score': int(occ), 'confidence': 0.7, 'src_id': int(src_id), 'dst_id': int(leaf_id), 'formula': str(formula), 'description': 'coverage_gap indicates a length_of-sized region is being skipped (wire matches expected but content is smaller). Bind the same length formula to the variable leaf so it actually consumes bits on-wire (eliminates content_bits=0).', 'target': _node_label(lookup, leaf_id), 'src': _node_label(lookup, src_id), 'evidence': {'occurrences': int(occ), 'gap_container': _node_label(lookup, dst_id), 'example_packets': coverage_gap_samples.get((src_id, dst_id, formula), [])}})
    for (container_id, payload_id, formula), occ in tail_gap_payload_counts.most_common():
        if occ <= 0:
            continue
        suggested = f'({int(container_id)}.bit_start + ({formula})) - ({int(payload_id)}.bit_start)'
        key = ('set_size_bits', int(payload_id), int(container_id))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        hints.append({'kind': 'set_size_bits', 'score': int(occ), 'confidence': 0.7, 'node_id': int(payload_id), 'suggested_size_bits': suggested, 'description': 'coverage_tail_gap suggests a bytes-like payload is not consuming the remaining bits within a length_of-controlled container. Set payload.size_bits to container_end - payload_start so it consumes the remainder on-wire.', 'target': _node_label(lookup, payload_id), 'evidence': {'container': _node_label(lookup, container_id), 'length_formula': str(formula), 'occurrences': int(occ), 'example_packets': tail_gap_payload_samples.get((container_id, payload_id, formula), [])}})
    for nid, overshoot_counter in oob_overshoot_bits_by_node.items():
        total = sum((int(v) for v in overshoot_counter.values()))
        if total < 2:
            continue
        overshoot, freq = overshoot_counter.most_common(1)[0]
        if freq < 2:
            continue
        node = lookup.get(nid) or lookup.get(str(nid)) or {}
        if not isinstance(node, dict):
            continue
        size_expr = node.get('size_bits')
        node_type = _norm_text(node.get('node_type'))
        data_type = _norm_text(node.get('data_type'))
        if node_type == 'payload' or data_type in {'bytes', 'binary'}:
            for key in (nid, str(nid)):
                for e in incoming_length_of.get(key, []) or []:
                    src_id = _coerce_int_or_none(e.get('src'))
                    if src_id is None:
                        continue
                    if not _formula_is_simple_val(e.get('formula'), int(src_id)):
                        continue
                    src_node = lookup.get(src_id) or lookup.get(str(src_id)) or {}
                    src_size = _coerce_int_or_none(src_node.get('size_bits'))
                    if src_size in {8, 16, 32}:
                        size_expr = None
                        break
                if size_expr is None:
                    break
            if size_expr is None:
                continue
        suggested: Optional[Any] = None
        if isinstance(size_expr, (int, float)) and (not isinstance(size_expr, bool)):
            suggested = max(0, int(size_expr) - int(overshoot))
        elif isinstance(size_expr, str):
            s = size_expr.strip()
            if s and s.lower() not in _VARIABLE_TOKENS:
                suggested = f'({s}) - {int(overshoot)}'
        if suggested is None:
            continue
        key = ('set_size_bits', int(nid), int(overshoot))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        hints.append({'kind': 'set_size_bits', 'score': int(total), 'confidence': 0.65, 'node_id': int(nid), 'suggested_size_bits': suggested, 'description': 'Node consistently reads/seeks past end by a constant delta. This often indicates size_bits double-counts a shared prefix; decrease size_bits by the overshoot.', 'target': _node_label(lookup, nid), 'evidence': {'overshoot_bits_mode': int(overshoot), 'overshoot_bits_counts': dict(overshoot_counter), 'example_packets': oob_overshoot_samples_by_node.get(nid, [])}})
    for node in tree.get('nodes', []) if isinstance(tree, dict) else []:
        if not isinstance(node, dict):
            continue
        vid = _coerce_int_or_none(node.get('node_id'))
        if vid is None:
            continue
        has_children = bool(node.get('children_ids'))
        if not has_children:
            continue
        routing_hits = int(routing_candidate_counts.get(vid, 0) or 0)
        spec = int(speculative_variant_counts.get(vid, 0) or 0)
        occ = int(variant_counts.get(vid, 0) + path_counts.get(vid, 0) + spec_weight * spec)
        if occ <= 0:
            continue
        sid = _find_selector_for_variant(vid)
        if sid is None:
            continue
        var_start = _coerce_int_or_none(node.get('bit_start'))
        if var_start is None:
            continue
        parent_id = node.get('parent_id')
        parent = lookup.get(parent_id) or lookup.get(str(parent_id)) or {}
        parent_start = _coerce_int_or_none(parent.get('bit_start')) if isinstance(parent, dict) else None
        parent_len_formula = _first_length_of_formula(parent_id)
        if not parent_len_formula:
            raw_parent_size = parent.get('size_bits') if isinstance(parent, dict) else None
            if isinstance(raw_parent_size, str):
                raw_parent_size_norm = raw_parent_size.strip()
                if raw_parent_size_norm and raw_parent_size_norm.lower() not in _VARIABLE_TOKENS and ('val(' in raw_parent_size_norm):
                    parent_len_formula = raw_parent_size_norm
        if not parent_len_formula:
            continue
        sel = lookup.get(sid) or lookup.get(str(sid)) or {}
        sel_start = _coerce_int_or_none(sel.get('bit_start'))
        sel_size = _coerce_int_or_none(sel.get('size_bits'))
        suggested_size: Optional[str] = None
        shared_prefix_bits: Optional[int] = None
        if parent_start is not None and var_start >= parent_start:
            shared_prefix_bits = int(var_start - parent_start)
            if shared_prefix_bits == 0:
                suggested_size = str(parent_len_formula)
            else:
                suggested_size = f'({parent_len_formula}) - {shared_prefix_bits}'
        elif sel_start is not None and sel_size is not None:
            selector_end = sel_start + sel_size
            if var_start == selector_end:
                shared_prefix_bits = int(sel_size)
                suggested_size = f'({parent_len_formula}) - {sel_size}'
            elif var_start == sel_start:
                shared_prefix_bits = 0
                suggested_size = str(parent_len_formula)
        if suggested_size:
            cur_size = node.get('size_bits')
            cur_size_str = str(cur_size).strip().lower() if isinstance(cur_size, str) else None
            should_suggest = False
            if cur_size is None:
                should_suggest = True
            elif isinstance(cur_size, (int, float)) and (not isinstance(cur_size, bool)):
                should_suggest = True
            elif isinstance(cur_size, str) and (cur_size_str in _VARIABLE_TOKENS or 'val(' not in cur_size.lower()):
                should_suggest = True
            if should_suggest:
                key = ('set_variant_size_bits', int(vid), int(sid))
                if key not in seen_keys:
                    seen_keys.add(key)
                    hints.append({'kind': 'set_variant_size_bits', 'score': occ, 'confidence': 0.6, 'variant_id': int(vid), 'selector_id': int(sid), 'suggested_size_bits': suggested_size, 'routing_failures': routing_hits, 'description': 'Selector-controlled variant likely needs a size_bits formula tied to the parent length field; if the parent length includes shared prefix fields, subtract the prefix bits before sizing the variant. Wrong/variable size_bits can trigger OOB speculative failures and coverage_tail_gap.', 'target': _node_label(lookup, vid), 'evidence': {'occurrences': occ, 'winner_path_occurrences': int(variant_counts.get(vid, 0) + path_counts.get(vid, 0)), 'shared_prefix_bits': shared_prefix_bits, 'routing_failures': routing_hits, 'routing_failure_packets': routing_candidate_samples.get(vid, []), 'speculative_failures': int(speculative_variant_counts.get(vid, 0)), 'speculative_kinds': dict(speculative_variant_kinds.get(vid, Counter())), 'example_packets': speculative_variant_samples.get(vid, [])}})
        child_starts: List[int] = []
        for cid in node.get('children_ids') or []:
            cnode = lookup.get(cid) or lookup.get(str(cid)) or {}
            cstart = _coerce_int_or_none(cnode.get('bit_start'))
            if cstart is not None:
                child_starts.append(int(cstart))
        if sel_size is not None and child_starts and (min(child_starts) == var_start + sel_size):
            key = ('shift_variant_subtree', int(vid), int(sel_size))
            if key not in seen_keys:
                seen_keys.add(key)
                hints.append({'kind': 'shift_variant_subtree', 'score': occ, 'confidence': 0.55, 'variant_id': int(vid), 'selector_id': int(sid), 'shift_bits': -int(sel_size), 'routing_failures': routing_hits, 'description': 'Variant subtree appears to double-count the selector prefix (children start after selector again). Consider shifting descendants left by selector_size_bits.', 'target': _node_label(lookup, vid), 'evidence': {'occurrences': occ, 'min_child_bit_start': min(child_starts), 'routing_failures': routing_hits, 'routing_failure_packets': routing_candidate_samples.get(vid, [])}})
    tlv_seq_ids: List[int] = [int(_coerce_int_or_none(n.get('node_id'))) for n in (tree.get('nodes', []) if isinstance(tree, dict) else []) if isinstance(n, dict) and _coerce_int_or_none(n.get('node_id')) is not None and (str(n.get('node_type') or '').strip().lower() in _TLV_SEQ_NODE_TYPES)]
    tlv_scoped: set[int] = set()
    for seq_id in tlv_seq_ids:
        tlv_scoped.add(int(seq_id))
        tlv_scoped.update(_walk_subtree_ids(int(seq_id)))
    for e in edges:
        if not isinstance(e, dict) or e.get('rel') != 'condition_on':
            continue
        sid = _coerce_int_or_none(e.get('src'))
        vid = _coerce_int_or_none(e.get('dst'))
        if sid is None or vid is None:
            continue
        if tlv_scoped and int(vid) not in tlv_scoped:
            continue
        sel = lookup.get(sid) or lookup.get(str(sid)) or {}
        if str(sel.get('node_type') or '').lower() != 'selector':
            continue
        if _is_ancestor(int(sid), int(vid)):
            continue
        var = lookup.get(vid) or lookup.get(str(vid)) or {}
        var_size = _coerce_size_bits(var.get('size_bits'))
        sel_size = _coerce_size_bits(sel.get('size_bits'))
        if var_size is None or sel_size is None or var_size <= 0 or (sel_size <= 0):
            continue
        child_ids = var.get('children_ids') or []
        if not child_ids:
            continue
        child_sizes: List[int] = []
        all_fixed = True
        for cid in child_ids:
            cid_int = _coerce_int_or_none(cid)
            if cid_int is None:
                all_fixed = False
                break
            cnode = lookup.get(cid_int) or lookup.get(str(cid_int)) or {}
            csize = _coerce_size_bits(cnode.get('size_bits'))
            if csize is None or csize <= 0:
                all_fixed = False
                break
            child_sizes.append(int(csize))
        if not all_fixed or not child_sizes:
            continue
        children_sum = int(sum(child_sizes))
        if children_sum <= 0:
            continue
        if int(var_size) - int(children_sum) != int(sel_size):
            continue
        key = ('set_size_bits', int(vid), int(sid))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        hints.append({'kind': 'set_size_bits', 'score': 10, 'confidence': 0.75, 'node_id': int(vid), 'suggested_size_bits': int(children_sum), 'description': 'Selector-controlled variant appears to double-count the selector prefix in size_bits (variant.size_bits = sum(children) + selector.size_bits). Reduce size_bits to sum(children) to avoid skipping one extra byte and desynchronizing parsing.', 'target': _node_label(lookup, vid), 'evidence': {'selector_id': int(sid), 'selector_size_bits': int(sel_size), 'variant_size_bits': int(var_size), 'children_sum_bits': int(children_sum)}})
    for seq_id in tlv_seq_ids:
        seq_desc = {int(seq_id)}
        seq_desc.update(_walk_subtree_ids(int(seq_id)))
        edges_by_selector: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        for e in edges:
            if not isinstance(e, dict) or e.get('rel') != 'condition_on':
                continue
            src = _coerce_int_or_none(e.get('src'))
            dst = _coerce_int_or_none(e.get('dst'))
            if src is None or dst is None:
                continue
            if int(src) not in seq_desc or int(dst) not in seq_desc:
                continue
            sel = lookup.get(src) or lookup.get(str(src)) or {}
            if str(sel.get('node_type') or '').lower() != 'selector':
                continue
            edges_by_selector[int(src)].append(e)
        for selector_id, group_edges in edges_by_selector.items():
            if len(group_edges) < 2:
                continue
            violating_vals = enum_constraint_values_by_node.get(int(selector_id)) or Counter()
            if violating_vals:
                sel_node = lookup.get(selector_id) or lookup.get(str(selector_id)) or {}
                constraints = sel_node.get('constraints') or []
                if isinstance(constraints, list):
                    occ = int(sum((int(v) for v in violating_vals.values())))
                    for c in constraints:
                        allowed = _parse_enum_constraint(c)
                        if not allowed:
                            continue
                        key = ('remove_enum_constraint', int(selector_id), str(c).strip())
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)
                        hints.append({'kind': 'remove_enum_constraint', 'score': occ, 'confidence': 0.75, 'node_id': int(selector_id), 'constraint': str(c), 'description': 'TLV tag selector is constrained by an enum, but traffic shows many other tag values. Remove the enum constraint so a catch-all TLV variant can consume unknown options (prevents early aborts and large tail gaps).', 'target': _node_label(lookup, selector_id), 'evidence': {'allowed': list(allowed), 'observed_top': {int(k): int(v) for k, v in violating_vals.most_common(6)}, 'occurrences': occ, 'example_packets': enum_constraint_samples_by_node.get(int(selector_id), [])}})
            generic_edge: Optional[Dict[str, Any]] = None
            for e in group_edges:
                vid = _coerce_int_or_none(e.get('dst'))
                if vid is None:
                    continue
                if _subtree_has_internal_length_of(int(vid)) or _subtree_has_payload_node(int(vid)):
                    generic_edge = e
                    break
            if generic_edge is None:
                other_formulas = [str(e.get('formula') or '').strip() for e in group_edges if str(e.get('formula') or '').strip()]
                if not other_formulas:
                    continue
                new_formula = ' and '.join([f'not({f})' for f in other_formulas])
                parent_counts: Counter[int] = Counter()
                bit_start_counts: Counter[str] = Counter()
                length_size_counts: Counter[int] = Counter()
                for e in group_edges:
                    vid = _coerce_int_or_none(e.get('dst'))
                    if vid is None:
                        continue
                    vnode = lookup.get(vid) or lookup.get(str(vid)) or {}
                    if not isinstance(vnode, dict):
                        continue
                    pid = _coerce_int_or_none(vnode.get('parent_id'))
                    if pid is not None:
                        parent_counts[int(pid)] += 1
                    bs = vnode.get('bit_start')
                    if isinstance(bs, str) and bs.strip():
                        bit_start_counts[bs.strip()] += 1
                    elif isinstance(bs, (int, float)) and (not isinstance(bs, bool)):
                        bit_start_counts[str(int(bs))] += 1
                    for cid in vnode.get('children_ids') or []:
                        cid_int = _coerce_int_or_none(cid)
                        if cid_int is None:
                            continue
                        cnode = lookup.get(cid_int) or lookup.get(str(cid_int)) or {}
                        if not isinstance(cnode, dict):
                            continue
                        cname = str(cnode.get('name') or '').lower()
                        ctype = str(cnode.get('node_type') or '').lower()
                        if ctype not in {'field', 'length'}:
                            continue
                        if 'len' not in cname and 'length' not in cname:
                            continue
                        csize = _coerce_size_bits(cnode.get('size_bits'))
                        if csize in {8, 16, 32}:
                            length_size_counts[int(csize)] += 1
                if not parent_counts or not bit_start_counts:
                    continue
                variant_parent_id = int(parent_counts.most_common(1)[0][0])
                variant_bit_start = str(bit_start_counts.most_common(1)[0][0]).strip()
                length_size_bits = int(length_size_counts.most_common(1)[0][0]) if length_size_counts else 8
                key = ('add_tlv_generic_variant', int(selector_id), int(variant_parent_id))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                hints.append({'kind': 'add_tlv_generic_variant', 'score': max(12, int(failure_node_counts.get(int(selector_id), 0) or 0)), 'confidence': 0.7, 'selector_id': int(selector_id), 'variant_parent_id': int(variant_parent_id), 'variant_bit_start': variant_bit_start, 'formula': new_formula, 'message_type': group_edges[0].get('message_type') or 'bidirectional', 'length_size_bits': int(length_size_bits), 'description': 'TLV-sequence selector has only special-case variants and no catch-all branch that consumes Length+Data for unknown tags. Add a generic TLV variant (Tag + Len + Data) so unrecognized options still advance the cursor and parsing stays aligned.', 'target': f'selector={_node_label(lookup, selector_id)}', 'evidence': {'existing_condition_on': other_formulas, 'variant_parent_id': int(variant_parent_id), 'variant_bit_start': variant_bit_start, 'length_size_bits': int(length_size_bits)}})
                continue
            generic_vid = _coerce_int_or_none(generic_edge.get('dst'))
            if generic_vid is None:
                continue
            other_formulas: List[str] = []
            for e in group_edges:
                dst = _coerce_int_or_none(e.get('dst'))
                if dst is None or int(dst) == int(generic_vid):
                    continue
                formula = e.get('formula')
                if not isinstance(formula, str) or not formula.strip():
                    continue
                other_formulas.append(formula.strip())
            if not other_formulas:
                continue
            new_formula = ' and '.join([f'not({f})' for f in other_formulas])
            cur_formula = str(generic_edge.get('formula') or '').strip()
            if cur_formula == new_formula.strip():
                continue
            key = ('set_condition_on_formula', int(selector_id), int(generic_vid))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            hints.append({'kind': 'set_condition_on_formula', 'score': 12, 'confidence': 0.7, 'src_id': int(selector_id), 'dst_id': int(generic_vid), 'formula': new_formula, 'message_type': generic_edge.get('message_type') or 'bidirectional', 'description': "TLV-sequence selector variants are missing a catch-all branch. Rewrite the generic TLV variant's condition to be the complement of all other special-case variants, so unknown option codes still consume length+data and the cursor stays aligned.", 'target': _node_label(lookup, generic_vid), 'src': _node_label(lookup, selector_id)})
    tlv_marker_re = re.compile('^\\s*(\\d+)\\.bit_start\\s*\\+\\s*\\1\\.size_bits\\s*$')
    for f in failures_list:
        kind = str(getattr(f, 'failure_kind', '') or '').strip().lower()
        if kind not in {'oob_seek', 'oob_read'}:
            continue
        nid = _coerce_int_or_none(getattr(f, 'node_id', None))
        if nid is None:
            continue
        node = lookup.get(nid) or lookup.get(str(nid)) or {}
        bit_start_expr = node.get('bit_start')
        if not isinstance(bit_start_expr, str) or not bit_start_expr.strip():
            continue
        m = tlv_marker_re.match(bit_start_expr.strip())
        if not m:
            continue
        seq_id = _coerce_int_or_none(m.group(1))
        if seq_id is None:
            continue
        seq_node = lookup.get(seq_id) or lookup.get(str(seq_id)) or {}
        if str(seq_node.get('node_type') or '').strip().lower() not in _TLV_SEQ_NODE_TYPES:
            continue
        key = ('make_semantic_only', int(nid), int(seq_id))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        hints.append({'kind': 'make_semantic_only', 'score': 20, 'confidence': 0.8, 'node_id': int(nid), 'description': 'Trailing marker field is positioned after a tlv_seq and caused an out-of-bounds read/seek. Make it semantic-only (size_bits=0, drop constraints) to avoid double-consuming the TLV terminator.', 'target': _node_label(lookup, nid), 'evidence': {'tlv_seq_id': int(seq_id), 'failure_kind': str(getattr(f, 'failure_kind', '')), 'example_packet': int(getattr(f, 'packet_index', 0) or 0)}})
    val_eq_const_re = re.compile('^\\s*val\\(\\s*(?P<sid>-?\\d+)\\s*\\)\\s*==\\s*(?P<const>0x[0-9a-fA-F]+|\\d+)\\s*$')

    def _strip_parens_once(text: str) -> str:
        t = (text or '').strip()
        if t.startswith('(') and t.endswith(')'):
            inner = t[1:-1].strip()
            if inner:
                return inner
        return t

    def _parse_relative_offset(expr: Any, base_ids: Tuple[int, ...]) -> Optional[int]:
        if not isinstance(expr, str) or not expr.strip():
            return None
        raw = expr.strip().replace(' ', '')
        for base_id in base_ids:
            if raw == f'{base_id}.bit_start':
                return 0
            prefix = f'{base_id}.bit_start+'
            if raw.startswith(prefix):
                tail = raw[len(prefix):]
                if tail.isdigit() or (tail.startswith('-') and tail[1:].isdigit()):
                    try:
                        return int(tail, 0)
                    except Exception:
                        return None
        return None
    for e in edges:
        if not isinstance(e, dict) or e.get('rel') != 'condition_on':
            continue
        sid = _coerce_int_or_none(e.get('src'))
        vid = _coerce_int_or_none(e.get('dst'))
        if sid is None or vid is None:
            continue
        if tlv_scoped and int(vid) not in tlv_scoped:
            continue
        formula = str(e.get('formula') or '').strip()
        if not formula:
            continue
        formula = _strip_parens_once(formula)
        m = val_eq_const_re.match(formula)
        if not m:
            continue
        try:
            parsed_sid = int(m.group('sid'), 0)
            const_val = int(m.group('const'), 0)
        except Exception:
            continue
        if parsed_sid != int(sid):
            continue
        sel_node = lookup.get(sid) or lookup.get(str(sid)) or {}
        if str(sel_node.get('node_type') or '').strip().lower() != 'selector':
            continue
        sel_size = _coerce_size_bits(sel_node.get('size_bits'))
        if sel_size is None or sel_size <= 0:
            continue
        var_node = lookup.get(vid) or lookup.get(str(vid)) or {}
        if not isinstance(var_node, dict):
            continue
        var_bit_start = var_node.get('bit_start')
        if not isinstance(var_bit_start, str) or not var_bit_start.strip():
            continue
        var_bs_norm = var_bit_start.strip().replace(' ', '')
        after_sel_norm = f'{int(sid)}.bit_start+{int(sel_size)}'
        if var_bs_norm != after_sel_norm:
            continue
        code_child_id: Optional[int] = None
        for cid in var_node.get('children_ids') or []:
            cid_int = _coerce_int_or_none(cid)
            if cid_int is None:
                continue
            child = lookup.get(cid_int) or lookup.get(str(cid_int)) or {}
            if not isinstance(child, dict):
                continue
            if _coerce_size_bits(child.get('size_bits')) != int(sel_size):
                continue
            constraints = child.get('constraints') or []
            if not isinstance(constraints, list) or not constraints:
                continue
            allowed: Optional[List[int]] = None
            for c in constraints:
                allowed = _parse_enum_constraint(c)
                if allowed is not None:
                    break
            if not allowed or len(allowed) != 1 or int(allowed[0]) != int(const_val):
                continue
            child_off = _parse_relative_offset(child.get('bit_start'), (int(vid),))
            if child_off != 0:
                continue
            code_child_id = int(cid_int)
            break
        if code_child_id is None:
            continue
        key = ('make_semantic_only', int(code_child_id), int(vid))
        if key not in seen_keys:
            seen_keys.add(key)
            hints.append({'kind': 'make_semantic_only', 'score': 30, 'confidence': 0.9, 'node_id': int(code_child_id), 'description': 'TLV variant redundantly re-models the selector tag as a Code field while the variant itself already starts after the selector (bit_start = selector.bit_start + selector.size_bits). Make the redundant Code field semantic-only to avoid shifting the TLV body by 1 byte.', 'target': _node_label(lookup, code_child_id), 'evidence': {'selector_id': int(sid), 'selector_size_bits': int(sel_size), 'variant_id': int(vid), 'tag_value': int(const_val), 'condition_on': formula}})
        for cid in var_node.get('children_ids') or []:
            cid_int = _coerce_int_or_none(cid)
            if cid_int is None or int(cid_int) == int(code_child_id):
                continue
            child = lookup.get(cid_int) or lookup.get(str(cid_int)) or {}
            if not isinstance(child, dict):
                continue
            off = _parse_relative_offset(child.get('bit_start'), (int(vid), int(code_child_id)))
            if off is None or off < int(sel_size):
                continue
            new_off = int(off) - int(sel_size)
            if new_off < 0:
                continue
            suggested = f'{int(vid)}.bit_start + {new_off}'
            key = ('set_bit_start', int(cid_int), int(vid))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            hints.append({'kind': 'set_bit_start', 'score': 28, 'confidence': 0.85, 'node_id': int(cid_int), 'suggested_bit_start': suggested, 'description': 'TLV variant appears shifted by one tag-width (the variant starts after the selector but also includes a redundant Code field). Shift this child left by selector.size_bits so Length/Value align correctly.', 'target': _node_label(lookup, cid_int), 'evidence': {'variant_id': int(vid), 'selector_id': int(sid), 'selector_size_bits': int(sel_size), 'old_bit_start': child.get('bit_start'), 'new_bit_start': suggested}})
        var_size = _coerce_size_bits(var_node.get('size_bits'))
        if var_size is not None and var_size > int(sel_size):
            child_sizes: List[int] = []
            all_fixed = True
            for cid in var_node.get('children_ids') or []:
                cid_int = _coerce_int_or_none(cid)
                if cid_int is None:
                    all_fixed = False
                    break
                cnode = lookup.get(cid_int) or lookup.get(str(cid_int)) or {}
                csize = _coerce_size_bits(cnode.get('size_bits'))
                if csize is None or csize < 0:
                    all_fixed = False
                    break
                child_sizes.append(int(csize))
            if all_fixed and child_sizes:
                total_children = int(sum(child_sizes))
                if int(var_size) == total_children and int(var_size) - int(sel_size) > 0:
                    suggested_size = int(var_size) - int(sel_size)
                    key = ('set_size_bits', int(vid), int(sid))
                    if key not in seen_keys:
                        seen_keys.add(key)
                        hints.append({'kind': 'set_size_bits', 'score': 26, 'confidence': 0.8, 'node_id': int(vid), 'suggested_size_bits': int(suggested_size), 'description': 'TLV variant size_bits appears to include the selector tag width even though the variant already starts after the selector. Reduce variant.size_bits by selector.size_bits to avoid skipping an extra byte after parsing the TLV body.', 'target': _node_label(lookup, vid), 'evidence': {'variant_size_bits': int(var_size), 'selector_size_bits': int(sel_size), 'children_sum_bits': int(total_children)}})
    for e in edges:
        if not isinstance(e, dict) or e.get('rel') != 'length_of':
            continue
        src_id = _coerce_int_or_none(e.get('src'))
        dst_id = _coerce_int_or_none(e.get('dst'))
        if src_id is None or dst_id is None:
            continue
        if not _formula_is_simple_val(e.get('formula'), int(src_id)):
            continue
        src_node = lookup.get(src_id) or lookup.get(str(src_id)) or {}
        dst_node = lookup.get(dst_id) or lookup.get(str(dst_id)) or {}
        if not isinstance(src_node, dict) or not isinstance(dst_node, dict):
            continue
        dst_node_type = _norm_text(dst_node.get('node_type'))
        dst_data_type = _norm_text(dst_node.get('data_type'))
        if dst_node_type != 'payload' and dst_data_type not in {'bytes', 'binary'}:
            continue
        src_size_bits = _coerce_int_or_none(src_node.get('size_bits'))
        if src_size_bits not in {8, 16, 32}:
            continue
        occ = int(failure_node_counts.get(int(dst_id), 0) or 0)
        if occ <= 0:
            continue
        desired = f'val({int(src_id)})*8'
        confidence = 0.65
        if dst_node_type == 'payload':
            confidence += 0.1
        if occ >= 5:
            confidence += 0.1
        confidence = min(0.9, confidence)
        key = ('add_length_of', int(src_id), int(dst_id))
        if key not in seen_keys:
            seen_keys.add(key)
            hints.append({'kind': 'add_length_of', 'score': occ, 'confidence': float(confidence), 'src_id': int(src_id), 'dst_id': int(dst_id), 'formula': desired, 'description': 'length_of formula looks like a raw byte count (val(L)) for a bytes-like payload; scale to bits by using val(L)*8 to restore byte alignment and avoid TLV desync.', 'target': _node_label(lookup, dst_id), 'src': _node_label(lookup, src_id), 'evidence': {'occurrences': occ, 'current_formula': str(e.get('formula') or ''), 'failure_kinds': dict(failure_kinds_by_node.get(int(dst_id), Counter()))}})
        cur_size_bits = dst_node.get('size_bits')
        if _formula_is_simple_val(cur_size_bits, int(src_id)) and str(cur_size_bits).strip() != desired:
            key2 = ('set_size_bits', int(dst_id), int(src_id))
            if key2 not in seen_keys:
                seen_keys.add(key2)
                hints.append({'kind': 'set_size_bits', 'score': occ, 'confidence': float(min(0.95, confidence + 0.05)), 'node_id': int(dst_id), 'suggested_size_bits': desired, 'description': 'Payload size_bits matches raw byte-count val(L); scale to val(L)*8 so the tree consumes the correct number of bits and length_of checks stay consistent.', 'target': _node_label(lookup, dst_id), 'evidence': {'current_size_bits': str(cur_size_bits), 'length_src': _node_label(lookup, src_id)}})
    try:
        min_enum_occ = int(os.getenv('STEP2_TRAFFIC_HINT_ENUM_RELAX_MIN_OCC', '3').strip())
    except Exception:
        min_enum_occ = 3
    min_enum_occ = max(1, min_enum_occ)

    def _is_guard_candidate_field(field_id: int) -> bool:
        node = lookup.get(field_id) or lookup.get(str(field_id)) or {}
        if not isinstance(node, dict):
            return False
        ntype = _norm_text(node.get('node_type'))
        if ntype not in {'field', 'selector', 'type', 'length'}:
            return False
        name = _norm_text(node.get('name'))
        raw_exclude = os.getenv('STEP2_TRAFFIC_GUARD_EXCLUDE_NAME_REGEX', '(^|[^a-z0-9])(ver|version|revision|rev)([^a-z0-9]|$)')
        if raw_exclude and raw_exclude.strip().lower() not in {'0', 'false', 'off', 'none'}:
            try:
                if re.search(raw_exclude, name):
                    return False
            except re.error:
                pass
        size = _coerce_int_or_none(node.get('size_bits'))
        if size not in {8, 16, 32}:
            return False
        constraints = node.get('constraints') or []
        if isinstance(constraints, list) and any((isinstance(c, str) and c.strip().lower().startswith('enum:') for c in constraints)):
            return True
        if any((tok in name for tok in ('type', 'op', 'code', 'kind', 'flags', 'class', 'cmd', 'command'))):
            return True
        return False
    for f in failures_list:
        if _norm_text(getattr(f, 'failure_kind', None)) != 'constraint':
            continue
        if _norm_text(getattr(f, 'constraint_kind', None)) != 'enum':
            continue
        nid = _coerce_int_or_none(getattr(f, 'node_id', None))
        if nid is None:
            continue
        ctx_vals = getattr(f, 'context_field_values', None) or {}
        if not isinstance(ctx_vals, dict) or not ctx_vals:
            continue
        for raw_gid, raw_gval in ctx_vals.items():
            gid = _coerce_int_or_none(raw_gid)
            gval = _coerce_int_or_none(raw_gval)
            if gid is None or gval is None:
                continue
            if int(gid) == int(nid):
                continue
            if not _is_guard_candidate_field(int(gid)):
                continue
            enum_failure_guard_values_by_node[int(nid)][int(gid)][int(gval)] += 1
    for nid, observed_vals in enum_constraint_values_by_node.items():
        occ = int(sum((int(v) for v in observed_vals.values())))
        if occ < min_enum_occ:
            continue
        node = lookup.get(nid) or lookup.get(str(nid)) or {}
        if not isinstance(node, dict):
            continue
        if _norm_text(node.get('node_type')) != 'field':
            continue
        constraints = node.get('constraints') or []
        if not isinstance(constraints, list):
            continue
        distinct = len(observed_vals)
        if distinct < 2:
            continue
        for c in constraints:
            allowed = _parse_enum_constraint(c)
            if not allowed or len(allowed) != 1:
                continue
            allowed_val = int(allowed[0])
            if allowed_val != 0:
                continue
            if allowed_val in observed_vals:
                continue
            best_guard: Optional[Tuple[int, int, float, int]] = None
            guard_map = enum_failure_guard_values_by_node.get(int(nid)) or {}
            for gid, counts in guard_map.items():
                support = int(sum((int(v) for v in counts.values())))
                if support < min_enum_occ:
                    continue
                bad_val, bad_cnt = counts.most_common(1)[0]
                ratio = float(bad_cnt) / float(support) if support else 0.0
                if ratio < 0.9:
                    continue
                if len(global_field_values.get(int(gid), Counter())) < 2:
                    continue
                cand = (int(gid), int(bad_val), float(ratio), int(support))
                if best_guard is None or cand[2] > best_guard[2] or (cand[2] == best_guard[2] and cand[3] > best_guard[3]):
                    best_guard = cand
            if best_guard is not None:
                gid, bad_val, ratio, support = best_guard
                new_constraint = f'formula: (val({gid}) == {bad_val}) or (value == 0)'
                key = ('replace_constraint', int(nid), int(gid))
                if key not in seen_keys:
                    seen_keys.add(key)
                    hints.append({'kind': 'replace_constraint', 'score': occ, 'confidence': float(min(0.98, 0.7 + 0.1 * ratio)), 'node_id': int(nid), 'remove': str(c), 'add': new_constraint, 'description': 'Traffic suggests this enum:0 constraint only applies under a specific mode (guard field value). Rewrite it as a conditional `formula:` constraint instead of dropping it entirely.', 'target': _node_label(lookup, nid), 'evidence': {'guard_id': int(gid), 'guard_value_mode': int(bad_val), 'support': int(support), 'dominance_ratio': float(ratio), 'observed_top': {int(k): int(v) for k, v in observed_vals.most_common(5)}, 'example_packets': enum_constraint_samples_by_node.get(int(nid), [])}})
                continue
            key = ('remove_enum_constraint', int(nid), int(allowed_val))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            confidence = 0.6 + (0.1 if occ >= 5 else 0.0) + (0.1 if distinct >= 5 else 0.0)
            confidence = min(0.95, confidence)
            hints.append({'kind': 'remove_enum_constraint', 'score': occ, 'confidence': float(confidence), 'node_id': int(nid), 'constraint': str(c), 'description': "Traffic violates a single-value enum constraint (likely overly strict 'MUST be 0' prose). Remove this enum constraint so parsing can proceed; other checks (coverage/length) will still catch misalignment.", 'target': _node_label(lookup, nid), 'evidence': {'allowed': allowed_val, 'observed_top': {int(k): int(v) for k, v in observed_vals.most_common(5)}, 'occurrences': occ, 'distinct_observed': distinct, 'example_packets': enum_constraint_samples_by_node.get(int(nid), [])}})
    unsupported_constraint_counts: Counter[Tuple[int, str]] = Counter()
    unsupported_constraint_samples: Dict[Tuple[int, str], List[int]] = defaultdict(list)
    for f in failures_list:
        msg = str(getattr(f, 'message', '') or '')
        if 'Error evaluating constraint' not in msg:
            continue
        nid = _coerce_int_or_none(getattr(f, 'node_id', None))
        if nid is None:
            continue
        m = re.search("Error evaluating constraint '([^']+)'\\s+for node\\s+\\d+", msg)
        if not m:
            continue
        raw_constraint = m.group(1).strip()
        if ':' not in raw_constraint:
            continue
        prefix = raw_constraint.split(':', 1)[0].strip().lower()
        if prefix in {'enum', 'range', 'formula'}:
            continue
        key = (int(nid), raw_constraint)
        unsupported_constraint_counts[key] += 1
        pkt = _coerce_int_or_none(getattr(f, 'packet_index', None))
        if pkt is not None and len(unsupported_constraint_samples[key]) < 8:
            unsupported_constraint_samples[key].append(int(pkt))
    for (nid, constraint), occ in unsupported_constraint_counts.items():
        key = ('remove_constraint', int(nid), constraint)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        hints.append({'kind': 'remove_constraint', 'score': int(occ), 'confidence': 0.98, 'node_id': int(nid), 'constraint': str(constraint), 'description': 'Unsupported constraint syntax caused runtime eval failures. Remove it so traffic parsing can proceed; use `formula:` if you need an executable predicate.', 'target': _node_label(lookup, nid), 'evidence': {'occurrences': int(occ), 'example_packets': unsupported_constraint_samples.get((int(nid), constraint), [])}})
    raw_max = os.getenv('STEP2_TRAFFIC_HINTS_MAX', '50')
    try:
        max_hints = int(str(raw_max).strip())
    except Exception:
        max_hints = 50
    if max_hints <= 0:
        return []

    def _routing_hits(h: Dict[str, Any]) -> int:
        try:
            return int(h.get('routing_failures', 0) or 0)
        except Exception:
            return 0

    def _hint_score(h: Dict[str, Any]) -> int:
        try:
            return int(h.get('score', 0) or 0)
        except Exception:
            return 0

    def _hint_confidence(h: Dict[str, Any]) -> float:
        try:
            return float(h.get('confidence', 0.0) or 0.0)
        except Exception:
            return 0.0

    def _kind_rank(kind: str) -> int:
        kind = (kind or '').strip()
        if kind == 'replace_constraint':
            return 0
        if kind == 'add_length_of':
            return 0
        if kind == 'remove_constraint':
            return 0
        if kind == 'remove_enum_constraint':
            return 0
        if kind == 'set_size_bits':
            return 1
        if kind == 'set_variant_size_bits':
            return 2
        if kind == 'shift_variant_subtree':
            return 3
        return 3
    hints.sort(key=lambda h: (-_hint_score(h), -_hint_confidence(h), -_routing_hits(h), _kind_rank(str(h.get('kind', ''))), str(h.get('kind', '')), str(h.get('target', ''))))
    return hints[:max_hints]
