from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from collections import defaultdict, namedtuple
import re
import copy
from collections import Counter
from framework.b_tree.validation_agent.traffic_errors import TrafficParseFailure
from framework.b_tree.traffic_agent.semantic_validator import SemanticValidator

@dataclass
class SizeBitsCandidate:
    node_id: int
    controlling_field_id: int
    expression: str
    pattern: str
    k: int
    total_error_bits: int
    max_abs_error_bits: int
    num_samples: int

@dataclass
class LengthFieldCandidate:
    node_id: int
    unit_hint: str
    score: float

@dataclass
class PayloadFillCandidate:
    dst_id: int
    src_id: Optional[int]
    bit_start_expr: str
    size_bits_expr: str
    gap_bits: Optional[int] = None
    parent_id: Optional[int] = None

def _coerce_node_id(raw: Any) -> Optional[int]:
    try:
        return int(raw)
    except Exception:
        return None

def _dedup_preserve_order(items: Sequence[Any]) -> List[Any]:
    seen = set()
    result = []
    for item in items:
        key = item
        try:
            if hasattr(item, 'expression'):
                key = (getattr(item, 'node_id', None), getattr(item, 'controlling_field_id', None), getattr(item, 'expression', None))
        except Exception:
            key = item
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result

def _build_node_map(tree: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    nodes = tree.get('nodes', []) if isinstance(tree, dict) else tree.get('protocol_tree', {}).get('nodes', [])
    if not nodes and isinstance(tree, dict):
        nodes = tree.get('protocol_tree', {}).get('nodes', [])
    node_map: Dict[int, Dict[str, Any]] = {}
    for node in nodes or []:
        nid = _coerce_node_id(node.get('node_id'))
        if nid is not None:
            node_map[nid] = node
    return node_map

def _is_container_node(node: Dict[str, Any]) -> bool:
    t = str(node.get('node_type', '') or '').lower()
    return t in {'protocol', 'payload', 'variant', 'container', 'struct', 'message', 'sequence'}

def _is_overflow_failure(failure: TrafficParseFailure) -> bool:
    kind = (getattr(failure, 'failure_kind', '') or '').lower()
    if kind in {'seek_oob', 'bitstart_oob', 'oob_seek', 'oob_read', 'node_overflow'}:
        return True
    msg = str(getattr(failure, 'message', '') or '')
    if 'stream ended' in msg.lower() or 'invalid position' in msg.lower() or 'bit_start' in msg.lower():
        return True
    return False

def _candidate_length_fields_for_node(target_node_id: int, failures: Sequence[TrafficParseFailure], tree: Dict[str, Any], nodes_by_id: Dict[int, Dict[str, Any]]) -> List[int]:
    scores: Dict[int, int] = defaultdict(int)
    for edge in tree.get('edges', []):
        try:
            if edge.get('rel') != 'length_of':
                continue
            dst = _coerce_node_id(edge.get('dst'))
            src = _coerce_node_id(edge.get('src'))
            if dst == target_node_id and src is not None:
                scores[src] += 3
        except Exception:
            continue
    for failure in failures:
        for raw_fid, _val in (getattr(failure, 'context_field_values', {}) or {}).items():
            fid = _coerce_node_id(raw_fid)
            if fid is None:
                continue
            node = nodes_by_id.get(fid)
            if not node:
                continue
            if str(node.get('node_type', '')).lower() != 'field':
                continue
            name = (node.get('name') or '').lower()
            score = 1
            if 'length' in name or 'len' in name:
                score += 2
            if 'byte' in name and 'count' in name:
                score += 2
            scores[fid] += score
    if not scores:
        return []
    sorted_fields = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    return [fid for fid, _ in sorted_fields[:3]]

def _candidate_formulas_for_length_field(field_id: int) -> List[str]:
    formulas: List[str] = []
    for scale in (1, 8):
        for delta in range(-4, 5):
            if delta == 0:
                if scale == 1:
                    formulas.append(f'val({field_id})')
                else:
                    formulas.append(f'val({field_id}) * {scale}')
                continue
            sign = '+' if delta > 0 else '-'
            abs_delta = abs(delta)
            if scale == 1:
                formulas.append(f'(val({field_id}) {sign} {abs_delta})')
            else:
                formulas.append(f'(val({field_id}) {sign} {abs_delta}) * {scale}')
    return formulas

def _failure_path_signature(failure: TrafficParseFailure, nodes_by_id: Dict[int, Dict[str, Any]], max_depth: int=6) -> Tuple[int, ...]:
    sig: List[int] = []
    for pid in getattr(failure, 'path_node_ids', []) or []:
        nid = _coerce_node_id(pid)
        if nid is None:
            continue
        node = nodes_by_id.get(nid)
        if node is None:
            continue
        ntype = str(node.get('node_type', '') or '').lower()
        if _is_container_node(node) or ntype == 'variant':
            sig.append(nid)
        if len(sig) >= max_depth:
            break
    return tuple(sig)

def _bucket_failures_by_shape(failures: Sequence[TrafficParseFailure], tree: Dict[str, Any]) -> Dict[Tuple[int, ...], List[TrafficParseFailure]]:
    nodes_by_id = _build_node_map(tree)
    buckets: Dict[Tuple[int, ...], List[TrafficParseFailure]] = defaultdict(list)
    for f in failures:
        sig = _failure_path_signature(f, nodes_by_id)
        buckets[sig].append(f)
    return buckets

def _eval_linear_formula(formula: str, length_value: int) -> Optional[int]:
    try:
        expr = formula.replace(' ', '')
        scale = 1
        if expr.endswith('*8'):
            scale = 8
            expr = expr[:-2]
        elif expr.endswith('*1'):
            expr = expr[:-2]
        core = expr
        if core.startswith('(') and core.endswith(')'):
            core = core[1:-1]
        if '+' in core:
            left, delta_str = core.split('+', 1)
            delta = int(delta_str)
        elif '-' in core[4:]:
            left, delta_str = core.split('-', 1)
            delta = -int(delta_str)
        else:
            left = core
            delta = 0
        if not left.startswith('val(') or not left.endswith(')'):
            return None
        base = length_value + delta
        return int(base * scale)
    except Exception:
        return None

def infer_size_for_node_with_context(target_node_id: int, failures: Sequence[TrafficParseFailure], tree: Dict[str, Any], nodes_by_id: Dict[int, Dict[str, Any]], max_formulas_per_node: int=5) -> List[SizeBitsCandidate]:
    length_fields = _candidate_length_fields_for_node(target_node_id, failures, tree, nodes_by_id)
    if not length_fields:
        return []
    node_bit_starts: Dict[int, int] = {}
    for f in failures:
        if f.bit_start is None:
            continue
        if _coerce_node_id(f.node_id) == target_node_id:
            node_bit_starts[f.packet_index] = f.bit_start
            continue
        path_ids = [_coerce_node_id(pid) for pid in getattr(f, 'path_node_ids', []) or []]
        if target_node_id in path_ids:
            node_bit_starts[f.packet_index] = f.bit_start
    if not node_bit_starts:
        return []
    FormulaScore = namedtuple('FormulaScore', ['formula', 'good', 'bad', 'avg_slack', 'field_id'])
    scored: List[FormulaScore] = []
    for field_id in length_fields:
        formulas = _candidate_formulas_for_length_field(field_id)
        for formula in formulas:
            good = 0
            bad = 0
            slack_sum = 0.0
            sample_count = 0
            for f in failures:
                if f.packet_index not in node_bit_starts:
                    continue
                L = (f.context_field_values or {}).get(field_id)
                if L is None:
                    continue
                sample_count += 1
                size_bits = _eval_linear_formula(formula, int(L))
                if size_bits is None or size_bits <= 0:
                    bad += 1
                    continue
                start_bit = node_bit_starts[f.packet_index]
                end = start_bit + size_bits
                if end > f.total_bits:
                    bad += 1
                else:
                    good += 1
                    slack_sum += f.total_bits - end
            if sample_count == 0 or good == 0:
                continue
            if sample_count >= 3 and good == 1:
                continue
            avg_slack = slack_sum / max(good, 1)
            clamped_slack = min(avg_slack, 128.0)
            scored.append(FormulaScore(formula, good, bad, clamped_slack, field_id))
    if not scored:
        return []
    scored.sort(key=lambda fs: (-fs.good, fs.bad, fs.avg_slack))
    top = scored[:max_formulas_per_node]
    candidates: List[SizeBitsCandidate] = []
    for fs in top:
        candidates.append(SizeBitsCandidate(node_id=target_node_id, controlling_field_id=fs.field_id, expression=fs.formula, pattern='linear', k=0, total_error_bits=fs.bad, max_abs_error_bits=int(fs.avg_slack), num_samples=fs.good))
    return candidates

def infer_size_bits_candidates_from_report(report: Any, tree: Dict[str, Any], max_patterns_per_node: int=5) -> Dict[int, List[SizeBitsCandidate]]:
    failures: Sequence[TrafficParseFailure] = getattr(report, 'traffic_failures', None) or []
    if not failures:
        return {}
    nodes_by_id = _build_node_map(tree)
    candidates_by_node: Dict[int, List[SizeBitsCandidate]] = defaultdict(list)
    mismatch_groups: Dict[Tuple[int, int], List[TrafficParseFailure]] = defaultdict(list)
    for f in failures:
        if (getattr(f, 'failure_kind', '') or '').lower() != 'length_mismatch':
            continue
        dst = _coerce_node_id(getattr(f, 'length_mismatch_dst', None) or getattr(f, 'node_id', None))
        src = _coerce_node_id(getattr(f, 'length_mismatch_src', None) or getattr(f, 'length_src_node_id', None))
        if dst is None or src is None:
            continue
        mismatch_groups[dst, src].append(f)
    for (dst, src), group in mismatch_groups.items():
        k_counter: Counter[int] = Counter()
        total_error = 0
        max_abs_error = 0
        unit_counter: Counter[int] = Counter()
        for f in group:
            expected = getattr(f, 'length_expected_bits', None)
            actual = getattr(f, 'length_actual_bits', None)
            formula = getattr(f, 'length_formula', '') or ''
            try:
                if expected is not None and actual is not None:
                    diff_bits = abs(int(expected) - int(actual))
                    total_error += diff_bits
                    max_abs_error = max(max_abs_error, diff_bits)
            except Exception:
                pass
            try:
                val_src = (getattr(f, 'context_field_values', {}) or {}).get(src)
                if val_src is None or actual is None:
                    continue
                actual_int = int(actual)
                val_src_int = int(val_src)
            except Exception:
                continue
            unit = 8
            if '*8' in str(formula):
                unit = 8
            elif actual_int % 8 != 0:
                unit = 1
            elif expected is not None:
                try:
                    unit = 8 if int(expected) % 8 == 0 else 1
                except Exception:
                    unit = 8
            unit_counter[unit] += 1
            if unit == 8 and actual_int % 8 == 0:
                k_val = actual_int // 8 - val_src_int
            else:
                k_val = actual_int - val_src_int
            k_counter[k_val] += 1
        if not k_counter:
            continue
        best_k, _ = k_counter.most_common(1)[0]
        unit_guess = unit_counter.most_common(1)[0][0] if unit_counter else 8
        expr_core = f'val({src})'
        if best_k != 0:
            sign = '+' if best_k > 0 else '-'
            expr_core = f'(val({src}) {sign} {abs(best_k)})'
        expression = expr_core if unit_guess == 1 else f'{expr_core} * {unit_guess}'
        candidates_by_node[dst].append(SizeBitsCandidate(node_id=dst, controlling_field_id=src, expression=expression, pattern='length_mismatch_fit', k=int(best_k), total_error_bits=total_error, max_abs_error_bits=max_abs_error, num_samples=len(group)))
    buckets = _bucket_failures_by_shape(failures, tree)
    processed_pairs: Set[Tuple[Tuple[int, ...], int]] = set()
    for sig, bucket_failures in buckets.items():
        for failure in bucket_failures:
            if (getattr(failure, 'failure_kind', '') or '').lower() == 'coverage_gap':
                continue
            nid = _coerce_node_id(getattr(failure, 'node_id', None))
            if nid is None:
                continue
            path_ids = [_coerce_node_id(pid) for pid in getattr(failure, 'path_node_ids', []) or []]
            target_nodes: Set[int] = set()
            target_nodes.add(nid)
            if _is_overflow_failure(failure):
                for pid in path_ids:
                    if pid is None:
                        continue
                    node = nodes_by_id.get(pid)
                    if node and _is_container_node(node):
                        target_nodes.add(pid)
            for target in target_nodes:
                if (sig, target) in processed_pairs:
                    continue
                processed_pairs.add((sig, target))
                node = nodes_by_id.get(target)
                if not node:
                    continue
                node_failures = [f2 for f2 in bucket_failures if _coerce_node_id(f2.node_id) == target or target in (_coerce_node_id(pid) for pid in f2.path_node_ids or [])]
                cands = infer_size_for_node_with_context(target_node_id=target, failures=node_failures, tree=tree, nodes_by_id=nodes_by_id, max_formulas_per_node=max_patterns_per_node)
                if cands:
                    candidates_by_node[target].extend(cands)
    result: Dict[int, List[SizeBitsCandidate]] = {}
    for nid, cand_list in candidates_by_node.items():
        uniq = _dedup_preserve_order(cand_list)
        result[nid] = uniq[:max_patterns_per_node]
    return result

def infer_payload_fill_candidates_from_report(report: Any, tree: Dict[str, Any]) -> Dict[int, List[PayloadFillCandidate]]:
    failures: Sequence[TrafficParseFailure] = getattr(report, 'traffic_failures', None) or []
    if not failures:
        return {}
    nodes_by_id = _build_node_map(tree)
    result: Dict[int, List[PayloadFillCandidate]] = defaultdict(list)

    def _parent_chain(start_id: Optional[int]) -> List[int]:
        out: List[int] = []
        cur = start_id
        seen: Set[int] = set()
        while cur is not None and cur not in seen:
            seen.add(int(cur))
            out.append(int(cur))
            node = nodes_by_id.get(int(cur)) or {}
            cur = _coerce_node_id(node.get('parent_id')) if isinstance(node, dict) else None
        return out

    def _pick_length_controlled_container(path_ids: Sequence[Any], start_node_id: Optional[int], src_hint: Optional[int]) -> Tuple[Optional[int], Optional[str], Optional[int]]:
        candidates: List[int] = []
        if start_node_id is not None:
            candidates.extend(_parent_chain(int(start_node_id)))
        for pid in reversed(list(path_ids) or []):
            pid_int = _coerce_node_id(pid)
            if pid_int is None:
                continue
            candidates.extend(_parent_chain(int(pid_int)))
        seen: Set[int] = set()
        for cid in candidates:
            if cid in seen:
                continue
            seen.add(int(cid))
            formula, src_id = _pick_length_of_formula(int(cid), src_hint)
            if isinstance(formula, str) and formula.strip():
                return (int(cid), formula.strip(), src_id)
        return (None, None, None)

    def _pick_length_of_formula(dst_id: int, src_hint: Optional[int]) -> Tuple[Optional[str], Optional[int]]:
        for edge in tree.get('edges', []) or []:
            try:
                if edge.get('rel') != 'length_of':
                    continue
                if _coerce_node_id(edge.get('dst')) != dst_id:
                    continue
                src_id = _coerce_node_id(edge.get('src'))
                if src_hint is not None and src_id is not None and (src_id != src_hint):
                    continue
                formula = edge.get('formula')
                if isinstance(formula, str) and formula.strip():
                    return (formula.strip(), src_id)
            except Exception:
                continue
        for edge in tree.get('edges', []) or []:
            try:
                if edge.get('rel') != 'length_of':
                    continue
                if _coerce_node_id(edge.get('dst')) != dst_id:
                    continue
                formula = edge.get('formula')
                if isinstance(formula, str) and formula.strip():
                    return (formula.strip(), _coerce_node_id(edge.get('src')))
            except Exception:
                continue
        return (None, None)
    consuming_leaf_types = {'field', 'selector', 'type', 'length', 'checksum'}
    for f in failures:
        kind = (getattr(f, 'failure_kind', '') or '').lower()
        mismatch_kind = (getattr(f, 'length_mismatch_kind', '') or '').lower()
        is_coverage_gap = kind == 'coverage_gap' or mismatch_kind == 'coverage_gap'
        is_tail_gap = kind == 'coverage_tail_gap'
        is_internal_gap = kind == 'coverage_internal_gap'
        if not (is_coverage_gap or is_tail_gap or is_internal_gap):
            continue
        src = _coerce_node_id(getattr(f, 'length_mismatch_src', None) or getattr(f, 'length_src_node_id', None))
        path_ids = [pid for pid in getattr(f, 'path_node_ids', None) or [] if pid is not None]
        dst = _coerce_node_id(getattr(f, 'length_mismatch_dst', None) or getattr(f, 'node_id', None))
        length_formula: Optional[str] = getattr(f, 'length_formula', None)
        if not (isinstance(length_formula, str) and length_formula.strip()):
            if is_tail_gap or is_internal_gap:
                dst, length_formula, inferred_src = _pick_length_controlled_container(path_ids, dst, src)
                if src is None and inferred_src is not None:
                    src = inferred_src
            elif dst is not None:
                length_formula, inferred_src = _pick_length_of_formula(dst, src)
                if src is None and inferred_src is not None:
                    src = inferred_src
        if dst is None:
            continue
        gap_bits = getattr(f, 'length_gap_bits', None)
        if gap_bits is None and getattr(f, 'length_expected_bits', None) is not None and (getattr(f, 'length_content_bits', None) is not None):
            try:
                gap_bits = max(0, int(getattr(f, 'length_expected_bits')) - int(getattr(f, 'length_content_bits')))
            except Exception:
                gap_bits = None
        parent_id: Optional[int] = None
        for pid in reversed(path_ids):
            pid_int = _coerce_node_id(pid)
            if pid_int is None:
                continue
            node = nodes_by_id.get(pid_int)
            if not isinstance(node, dict):
                continue
            if str(node.get('node_type') or '').lower() != 'variant':
                continue
            if _coerce_node_id(node.get('parent_id')) != dst:
                continue
            parent_id = pid_int
            break
        container_node = nodes_by_id.get(dst) or {}
        has_variant_children = False
        if isinstance(container_node, dict):
            for cid in container_node.get('children_ids') or []:
                cid_int = _coerce_node_id(cid)
                child = nodes_by_id.get(cid_int) if cid_int is not None else None
                if child and str(child.get('node_type') or '').lower() == 'variant':
                    has_variant_children = True
                    break
        if has_variant_children and parent_id is None:
            continue
        attach_parent = parent_id if parent_id is not None else dst
        last_consumed_id: Optional[int] = None
        for pid in reversed(path_ids):
            pid_int = _coerce_node_id(pid)
            if pid_int is None:
                continue
            node = nodes_by_id.get(pid_int)
            if not isinstance(node, dict):
                continue
            if str(node.get('node_type') or '').lower() in consuming_leaf_types:
                last_consumed_id = pid_int
                break
        if last_consumed_id is not None:
            bit_start_expr = f'{last_consumed_id}.bit_start + {last_consumed_id}.size_bits'
        else:
            bit_start_expr = f'{attach_parent}.bit_start'
        expected_bits = getattr(f, 'length_expected_bits', None)
        if isinstance(length_formula, str) and length_formula.strip():
            end_expr = f'{dst}.bit_start + ({length_formula.strip()})'
        elif expected_bits is not None:
            try:
                end_expr = f'{dst}.bit_start + {int(expected_bits)}'
            except Exception:
                continue
        else:
            continue
        size_bits_expr = f'({end_expr}) - ({bit_start_expr})'
        result[dst].append(PayloadFillCandidate(dst_id=dst, src_id=src, parent_id=parent_id, bit_start_expr=bit_start_expr, size_bits_expr=size_bits_expr, gap_bits=gap_bits))
    return result

def _section_texts(sections: Sequence[Dict[str, Any]]) -> List[str]:
    texts: List[str] = []
    for sec in sections or []:
        if isinstance(sec, str):
            texts.append(sec)
            continue
        for key in ('text', 'content', 'section_text', 'summary', 'body'):
            val = sec.get(key)
            if isinstance(val, str):
                texts.append(val)
    return texts

def find_length_field_candidates(tree: Dict[str, Any], target_node_id: int, sections: Sequence[Dict[str, Any]]) -> List[LengthFieldCandidate]:
    tokens = ('length', 'len', 'byte_count', 'byte count', 'count', 'num', 'number_of', 'number of')
    byte_hints = ('byte', 'bytes')
    bit_hints = ('bit', 'bits')
    texts = [t.lower() for t in _section_texts(sections)]
    nodes = tree.get('nodes', []) if isinstance(tree, dict) else []
    node_lookup = {n.get('node_id'): n for n in nodes if isinstance(n, dict)}
    target_parent = node_lookup.get(target_node_id, {}).get('parent_id')
    candidates: List[LengthFieldCandidate] = []
    for node in nodes:
        if str(node.get('node_type', '')).lower() != 'field':
            continue
        nid = _coerce_node_id(node.get('node_id'))
        if nid is None:
            continue
        score = 0.0
        if node.get('parent_id') == target_parent:
            score += 2.0
        name = (node.get('name') or '').lower()
        for tok in tokens:
            if tok in name:
                score += 3.0
        unit_hint = 'unknown'
        for txt in texts:
            if name and name in txt:
                score += 1.0
            if any((tok in txt for tok in ('number of bytes following', 'bytes follow', 'length of the pdu', 'byte count indicates'))) and name and (name in txt):
                score += 2.0
            if re.search(f'\\b{name}\\b.*length', txt):
                score += 1.0
            if any((b in txt for b in byte_hints)) and name and (name in txt):
                unit_hint = 'bytes'
            if any((b in txt for b in bit_hints)) and name and (name in txt) and (unit_hint == 'unknown'):
                unit_hint = 'bits'
        if score <= 0:
            continue
        if unit_hint == 'unknown':
            if any((b in name for b in byte_hints)):
                unit_hint = 'bytes'
            elif any((b in name for b in bit_hints)):
                unit_hint = 'bits'
        candidates.append(LengthFieldCandidate(node_id=nid, unit_hint=unit_hint, score=score))
    candidates.sort(key=lambda c: c.score, reverse=True)
    return candidates

def estimate_required_size_bits_for_node(tree: Dict[str, Any], node_id: int, traffic_samples: Sequence[bytes], interpreter_factory) -> Optional[int]:
    if not traffic_samples:
        return None
    validator = SemanticValidator(tree, max_packets=min(3, len(traffic_samples)), stop_on_first_failure=False)
    issues, _extras, failures, _stats = validator.validate_packets(list(traffic_samples[:3]))
    sizes: List[int] = []
    for f in failures:
        if getattr(f, 'failure_kind', '').lower() not in {'oob_seek', 'seek_oob', 'bitstart_oob'}:
            continue
        nid = _coerce_node_id(getattr(f, 'node_id', None))
        path_ids = [_coerce_node_id(pid) for pid in getattr(f, 'path_node_ids', []) or []]
        if nid != node_id and node_id not in path_ids:
            continue
        if f.bit_start is None or f.total_bits is None:
            continue
        sizes.append(int(f.total_bits) - int(f.bit_start))
    if not sizes:
        return None
    counter = Counter(sizes)
    most_common_size, _ = counter.most_common(1)[0]
    return most_common_size

def infer_size_formula_for_node(tree: Dict[str, Any], target_node_id: int, sections: Sequence[Dict[str, Any]], traffic_samples: Sequence[bytes], interpreter_factory) -> Optional[str]:
    if not traffic_samples:
        return None
    length_candidates = find_length_field_candidates(tree, target_node_id, sections)
    if not length_candidates:
        return None
    required_bits = estimate_required_size_bits_for_node(tree, target_node_id, traffic_samples, interpreter_factory)
    if required_bits is None or required_bits <= 0:
        return None
    base_validator = SemanticValidator(tree, max_packets=min(3, len(traffic_samples)), stop_on_first_failure=False)
    base_issues, _extras, base_failures, _stats = base_validator.validate_packets(list(traffic_samples[:3]))

    def _target_fail_count(failures: Sequence[TrafficParseFailure]) -> int:
        count = 0
        for f in failures:
            if _coerce_node_id(f.node_id) == target_node_id or target_node_id in (_coerce_node_id(pid) for pid in getattr(f, 'path_node_ids', []) or []):
                if getattr(f, 'failure_kind', '').lower() in {'oob_seek', 'seek_oob', 'bitstart_oob'}:
                    count += 1
        return count
    baseline_target_fail = _target_fail_count(base_failures)
    baseline_total_issues = len([iss for iss in base_issues if getattr(iss.issue, 'severity', None) and iss.issue.severity.name == 'ERROR'])
    best_expr: Optional[str] = None
    best_fail = baseline_target_fail
    best_total = baseline_total_issues
    for cand in length_candidates:
        unit = cand.unit_hint or 'unknown'
        scales = [1]
        if unit in {'bytes', 'unknown'}:
            scales = [8, 16, 1]
        for a in scales:
            val_L = None
            for f in base_failures:
                if cand.node_id in (getattr(f, 'context_field_values', {}) or {}):
                    val_L = f.context_field_values.get(cand.node_id)
                    break
            if val_L is None:
                continue
            if unit == 'bytes':
                required_units = required_bits // 8
            else:
                required_units = required_bits
            if a == 0:
                continue
            c_units = required_units - a * int(val_L)
            if c_units < -32 or c_units > 32:
                continue
            expr = f'{a} * val({cand.node_id})'
            if c_units != 0:
                sign = '+' if c_units > 0 else '-'
                expr = f'{expr} {sign} {abs(c_units)}'
                temp_tree = copy.deepcopy(tree)
                for node in temp_tree.get('nodes', []):
                    if _coerce_node_id(node.get('node_id')) == target_node_id:
                        node['size_bits'] = expr
                        break
                validator = SemanticValidator(temp_tree, max_packets=min(3, len(traffic_samples)), stop_on_first_failure=False)
                issues, _extras, failures, _stats = validator.validate_packets(list(traffic_samples[:3]))
                target_fail = _target_fail_count(failures)
                total_err = len([iss for iss in issues if getattr(iss.issue, 'severity', None) and iss.issue.severity.name == 'ERROR'])
                if target_fail < best_fail or (target_fail == best_fail and total_err < best_total):
                    best_fail = target_fail
                    best_total = total_err
                    best_expr = expr
    if best_expr and best_fail < baseline_target_fail:
        return best_expr
    return None
