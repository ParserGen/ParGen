from __future__ import annotations
import argparse
import json
import hashlib
import logging
import os
import sys
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, List, Dict, Optional, Tuple, Sequence, Iterable
from types import SimpleNamespace
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from framework.paths import STEP2_CACHE_DIR, STEP2_FIX_CACHE_DIR, DATA_DIR, LOGS_DIR
from framework.b_tree.fix_agent.agent import EnhancedPureAIAgent
from framework.b_tree.fix_agent.refinement import mcts_fix_tree, run_full_validation
from framework.b_tree.fix_agent.modes import get_mode
from framework.b_tree.validation_agent.syntax_validator import validate_protocol_tree, ValidationReport, IssueType, Severity
from framework.b_tree.fix_agent.traffic_length_inference import infer_size_bits_candidates_from_report, infer_size_formula_for_node, infer_payload_fill_candidates_from_report
from framework.b_tree.traffic_agent.semantic_validator import SemanticValidator, _load_packets_from_path, export_parsing_traces
from framework.b_tree.traffic_agent.interpreter import ConstraintViolationError, DynamicTreeInterpreter, LengthMismatchError, NodeParseError, RoutingError
from framework.logging_utils import setup_logging
logger = logging.getLogger(__name__)

def _build_node_lookup(tree: Dict[str, Any]) -> Dict[Any, Dict[str, Any]]:
    nodes = tree.get('nodes', []) if isinstance(tree, dict) else []
    lookup: Dict[Any, Dict[str, Any]] = {}
    for node in nodes:
        nid = node.get('node_id')
        if nid is None:
            continue
        lookup[nid] = node
        lookup[str(nid)] = node
    return lookup

def _is_aggregator_node(node: Optional[Dict[str, Any]], lookup: Dict[Any, Dict[str, Any]]) -> bool:
    if not node:
        return False
    ntype = str(node.get('node_type', '') or '').lower()
    if ntype in {'protocol', 'message'}:
        return True
    children = node.get('children_ids') or []
    for cid in children:
        child = lookup.get(cid) or lookup.get(str(cid))
        if child and str(child.get('node_type', '')).lower() == 'variant':
            return True
    return False

def _setup_logging() -> None:
    try:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        log_path = LOGS_DIR / 'traffic_fix_debug.log'
        setup_logging(console_level=logging.WARNING, file_path=log_path, file_level=logging.DEBUG, replace_existing=True)
        logger.debug('Debug logging initialized at %s', log_path)
    except Exception:
        logger.warning('Failed to initialize debug file logging', exc_info=True)

def _smoke_test_interpreter(tree: Dict[str, Any], samples: List[bytes], max_samples: int=5) -> Optional[str]:
    if not samples:
        return None
    interp = DynamicTreeInterpreter(tree)
    limit = min(max_samples, len(samples))
    for idx in range(limit):
        payload = samples[idx]
        try:
            success, ctx, err = interp.parse(payload)
        except Exception as exc:
            return f'Interpreter exception on packet {idx}: {exc!r}'
        if err:
            msg = str(err)
            if 'not found' in msg.lower():
                return f'Interpreter structural error on packet {idx}: {msg}'
    return None

def _select_diverse_sample_payloads(*, tree: Dict[str, Any], packets: Sequence[bytes], sample_budget: int) -> Tuple[List[bytes], Dict[str, Any]]:
    total = len(packets)
    if total == 0:
        return ([], {'strategy': 'none', 'selected': [], 'groups': 0, 'total': 0})
    if sample_budget <= 0 or sample_budget >= total:
        return (list(packets), {'strategy': 'all', 'selected': list(range(total)), 'groups': total, 'total': total})
    interp = DynamicTreeInterpreter(tree)
    prefix_len = max(1, int(os.getenv('STEP2_TRAFFIC_SAMPLE_PATH_PREFIX_LEN', '16')))

    def _coerce_path(ctx: Any) -> Tuple[int, ...]:
        raw = getattr(ctx, 'parsing_path', None) or []
        out: List[int] = []
        for nid in raw:
            try:
                out.append(int(nid))
            except Exception:
                continue
        return tuple(out)

    def _failure_kind(err: Any) -> str:
        if err is None:
            return 'ok'
        if isinstance(err, RoutingError):
            return 'routing'
        if isinstance(err, ConstraintViolationError):
            return 'constraint'
        if isinstance(err, LengthMismatchError):
            return 'length_mismatch'
        if isinstance(err, NodeParseError):
            return 'node_error'
        if isinstance(err, str):
            if err.startswith('Incomplete parse:'):
                return 'coverage_tail_gap'
            return 'error'
        return type(err).__name__.lower()
    PacketKey = Tuple[str, Optional[int], Optional[int], Tuple[int, ...], Tuple[int, ...]]
    groups: Dict[PacketKey, List[int]] = defaultdict(list)
    ok_count = 0
    fail_count = 0
    for idx, payload in enumerate(packets):
        success, ctx, err = interp.parse(payload)
        kind = _failure_kind(err)
        if success and err is None:
            ok_count += 1
        else:
            fail_count += 1
        path = _coerce_path(ctx)
        path_prefix = path[:prefix_len]
        node_id: Optional[int] = None
        selector_id: Optional[int] = None
        candidates: Tuple[int, ...] = tuple()
        if isinstance(err, RoutingError):
            try:
                node_id = int(getattr(err, 'node_id', None))
            except Exception:
                node_id = None
            try:
                selector_id_raw = getattr(err, 'selector_id', None)
                selector_id = int(selector_id_raw) if selector_id_raw is not None else None
            except Exception:
                selector_id = None
            raw_cands = getattr(err, 'candidate_variants', None) or []
            try:
                candidates = tuple((int(x) for x in raw_cands))
            except Exception:
                candidates = tuple()
        else:
            try:
                node_id_raw = getattr(err, 'node_id', None)
                node_id = int(node_id_raw) if node_id_raw is not None else None
            except Exception:
                node_id = None
        groups[kind, node_id, selector_id, candidates, path_prefix].append(idx)
    group_items = sorted(groups.items(), key=lambda kv: (0 if kv[0][0] != 'ok' else 1, -len(kv[1]), kv[1][0]))
    selected_indices: List[int] = []
    for _key, indices in group_items:
        selected_indices.append(indices[0])
        if len(selected_indices) >= sample_budget:
            break
    selected_indices = sorted(set(selected_indices))
    selected_payloads = [packets[i] for i in selected_indices]
    debug = {'strategy': 'diverse_parse_path', 'total': total, 'ok': ok_count, 'failed': fail_count, 'groups': len(groups), 'selected': selected_indices, 'prefix_len': prefix_len}
    return (selected_payloads, debug)

def _coerce_int_or_none(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int) and (not isinstance(value, bool)):
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

def _traffic_failed_samples(report: Any) -> int:
    try:
        total = int(getattr(report, 'traffic_total_samples', 0) or 0)
        succ = int(getattr(report, 'traffic_successful_samples', 0) or 0)
        if total:
            return max(0, total - succ)
    except Exception:
        pass
    try:
        return len(getattr(report, 'traffic_failures', []) or [])
    except Exception:
        return 0

def _traffic_coverage_ratio(report: Any) -> float:
    ratios = getattr(report, 'traffic_content_coverage_ratio_per_sample', None) or ()
    if ratios:
        try:
            vals = [float(x) for x in ratios if x is not None]
            if vals:
                return sum(vals) / float(len(vals))
        except Exception:
            pass
    content_bits = getattr(report, 'traffic_content_covered_bits_per_sample', None) or ()
    total_bits = getattr(report, 'traffic_total_bits_per_sample', None) or ()
    if content_bits and total_bits:
        cov_sum = 0.0
        count = 0
        for cb, tb in zip(content_bits, total_bits):
            try:
                cb_val = float(cb)
                tb_val = float(tb)
            except Exception:
                continue
            if tb_val <= 0:
                continue
            cov_sum += min(1.0, cb_val / tb_val)
            count += 1
        if count:
            return cov_sum / float(count)
    return 0.0

def _traffic_error_issue_count(report: Any) -> int:
    try:
        return sum((1 for issue in (getattr(report, 'issues', {}) or {}).values() if getattr(issue, 'severity', None) == Severity.ERROR))
    except Exception:
        return 0

def _traffic_accept_score(report: Any) -> Tuple[int, float, int, int, int, int]:
    failed = _traffic_failed_samples(report)
    coverage = _traffic_coverage_ratio(report)
    try:
        gap_bits = int(getattr(report, 'traffic_total_coverage_gap_bits', 0) or 0)
    except Exception:
        gap_bits = 0
    try:
        len_err = int(getattr(report, 'traffic_length_total_abs_error_bits', 0) or 0)
    except Exception:
        len_err = 0
    try:
        overflow = int(getattr(report, 'traffic_overflow_length_bits', 0) or 0)
    except Exception:
        overflow = 0
    return (failed, -coverage, gap_bits, len_err, overflow, _traffic_error_issue_count(report))

def _traffic_scalar_score(report: Any) -> float:
    try:
        total = int(getattr(report, 'traffic_total_samples', 0) or 0)
    except Exception:
        total = 0
    failed = _traffic_failed_samples(report)
    succ = max(0, total - failed)
    cov = _traffic_coverage_ratio(report)
    try:
        gap_bits = float(getattr(report, 'traffic_total_coverage_gap_bits', 0) or 0)
    except Exception:
        gap_bits = 0.0
    try:
        len_err = float(getattr(report, 'traffic_length_total_abs_error_bits', 0) or 0)
    except Exception:
        len_err = 0.0
    try:
        overflow = float(getattr(report, 'traffic_overflow_length_bits', 0) or 0)
    except Exception:
        overflow = 0.0

    def _w(env: str, default: float) -> float:
        raw = os.getenv(env)
        if raw is None or not str(raw).strip():
            return float(default)
        try:
            return float(raw)
        except Exception:
            return float(default)
    w_success = _w('STEP2_MCTS_TRAFFIC_WEIGHT_SUCCESS', 5.0)
    w_cov = _w('STEP2_MCTS_TRAFFIC_WEIGHT_COVERAGE', 1.0)
    w_gap = _w('STEP2_MCTS_TRAFFIC_WEIGHT_GAP', 0.02)
    w_len = _w('STEP2_MCTS_TRAFFIC_WEIGHT_LENGTH_ERROR', 0.05)
    w_new = _w('STEP2_MCTS_TRAFFIC_WEIGHT_NEW', 0.5)
    w_overflow = _w('STEP2_MCTS_TRAFFIC_WEIGHT_OVERFLOW', 0.0)
    return w_success * float(succ) + w_cov * float(cov) - w_gap * float(gap_bits) - w_len * float(len_err) - w_new * float(failed) - w_overflow * float(overflow)

def _format_traffic_accept_score(score: Tuple[int, float, int, int, int, int]) -> str:
    failed, neg_cov, gap_bits, len_err, overflow, issue_cnt = score
    return f'failed={failed} cov={-neg_cov:.3f} gap_bits={gap_bits} len_abs_err_bits={len_err} overflow_bits={overflow} error_issues={issue_cnt}'

def _traffic_apply_repair_hints_bundle(tree: Dict[str, Any], hints: Sequence[Dict[str, Any]], *, allow_shifts: bool) -> Tuple[Dict[str, Any], List[str]]:
    candidate = json.loads(json.dumps(tree))
    lookup = _build_node_lookup(candidate)
    nodes = candidate.get('nodes')
    if not isinstance(nodes, list):
        nodes = []
        candidate['nodes'] = nodes
    edges = candidate.get('edges')
    if not isinstance(edges, list):
        edges = []
        candidate['edges'] = edges
    nodes_by_id: Dict[int, Dict[str, Any]] = {}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        nid = _coerce_int_or_none(node.get('node_id'))
        if nid is None:
            continue
        nodes_by_id[nid] = node
    changes: List[str] = []

    def _find_edge(src_id: int, dst_id: int, rel: str) -> Optional[Dict[str, Any]]:
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            if str(edge.get('rel') or '') != rel:
                continue
            if _coerce_int_or_none(edge.get('src')) != src_id:
                continue
            if _coerce_int_or_none(edge.get('dst')) != dst_id:
                continue
            return edge
        return None

    def _ensure_length_of(src_id: int, dst_id: int, formula: str) -> None:
        existing = _find_edge(src_id, dst_id, 'length_of')
        if existing is None:
            edges.append({'src': src_id, 'dst': dst_id, 'rel': 'length_of', 'formula': formula})
            changes.append(f'add_length_of {src_id}->{dst_id} formula={formula}')
            return
        current = str(existing.get('formula') or '')
        if current.strip() != formula.strip():
            existing['formula'] = formula
            changes.append(f'update_length_of {src_id}->{dst_id} formula={formula}')

    def _walk_subtree(root_id: int) -> List[int]:
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
                out.append(cid_int)
                stack.append(cid_int)
        return out
    for hint in hints or ():
        if not isinstance(hint, dict):
            continue
        kind = str(hint.get('kind', '') or '').strip()
        if kind == 'add_length_of':
            src_id = _coerce_int_or_none(hint.get('src_id'))
            dst_id = _coerce_int_or_none(hint.get('dst_id'))
            formula = str(hint.get('formula') or '').strip()
            if src_id is None or dst_id is None or (not formula):
                continue
            _ensure_length_of(src_id, dst_id, formula)
            continue
        if kind == 'set_variant_size_bits':
            vid = _coerce_int_or_none(hint.get('variant_id'))
            suggested = str(hint.get('suggested_size_bits') or '').strip()
            if vid is None or not suggested:
                continue
            node = nodes_by_id.get(vid)
            if not node:
                continue
            if str(node.get('size_bits') or '').strip() == suggested:
                continue
            node['size_bits'] = suggested
            changes.append(f'set_size_bits node={vid} size_bits={suggested}')
            continue
        if kind == 'set_size_bits':
            nid = _coerce_int_or_none(hint.get('node_id'))
            raw_suggested = hint.get('suggested_size_bits')
            if nid is None or raw_suggested is None:
                continue
            suggested: Any
            if isinstance(raw_suggested, (int, float)) and (not isinstance(raw_suggested, bool)):
                suggested = int(raw_suggested)
            else:
                suggested = str(raw_suggested).strip()
                if not suggested:
                    continue
            node = nodes_by_id.get(nid)
            if not node:
                continue
            if node.get('size_bits') == suggested:
                continue
            node['size_bits'] = suggested
            changes.append(f'set_size_bits node={nid} size_bits={suggested}')
            continue
        if kind == 'set_bit_start':
            nid = _coerce_int_or_none(hint.get('node_id'))
            raw_suggested = hint.get('suggested_bit_start')
            if raw_suggested is None:
                raw_suggested = hint.get('bit_start')
            if nid is None or raw_suggested is None:
                continue
            suggested: Any
            if isinstance(raw_suggested, (int, float)) and (not isinstance(raw_suggested, bool)):
                suggested = int(raw_suggested)
            else:
                suggested = str(raw_suggested).strip()
                if not suggested:
                    continue
            node = nodes_by_id.get(nid)
            if not node:
                continue
            if node.get('bit_start') == suggested:
                continue
            node['bit_start'] = suggested
            changes.append(f'set_bit_start node={nid} bit_start={suggested}')
            continue
        if kind == 'set_condition_on_formula':
            src_id = _coerce_int_or_none(hint.get('src_id'))
            dst_id = _coerce_int_or_none(hint.get('dst_id'))
            formula = str(hint.get('formula') or '').strip()
            if src_id is None or dst_id is None or (not formula):
                continue
            existing = _find_edge(src_id, dst_id, 'condition_on')
            if existing is None:
                msg_type = str(hint.get('message_type') or 'bidirectional').strip() or 'bidirectional'
                edges.append({'src': int(src_id), 'dst': int(dst_id), 'rel': 'condition_on', 'formula': formula, 'message_type': msg_type})
                changes.append(f'add_condition_on {src_id}->{dst_id} formula={formula}')
            else:
                current = str(existing.get('formula') or '').strip()
                if current != formula:
                    existing['formula'] = formula
                    changes.append(f'set_condition_on {src_id}->{dst_id} formula={formula}')
            continue
        if kind == 'add_tlv_generic_variant':
            selector_id = _coerce_int_or_none(hint.get('selector_id'))
            variant_parent_id = _coerce_int_or_none(hint.get('variant_parent_id'))
            variant_bit_start = hint.get('variant_bit_start')
            cond_formula = str(hint.get('formula') or '').strip()
            message_type = str(hint.get('message_type') or 'bidirectional').strip() or 'bidirectional'
            length_size_bits = _coerce_int_or_none(hint.get('length_size_bits')) or 8
            if selector_id is None or variant_parent_id is None or (not cond_formula):
                continue
            parent = nodes_by_id.get(int(variant_parent_id))
            if not parent:
                continue

            def _subtree_has_payload(root_id: int) -> bool:
                for nid in [int(root_id)] + _walk_subtree(int(root_id)):
                    node = nodes_by_id.get(int(nid))
                    if not node:
                        continue
                    if str(node.get('node_type') or '').strip().lower() == 'payload':
                        return True
                return False
            already_has_generic = False
            for edge in edges:
                if not isinstance(edge, dict) or str(edge.get('rel') or '') != 'condition_on':
                    continue
                if _coerce_int_or_none(edge.get('src')) != int(selector_id):
                    continue
                dst = _coerce_int_or_none(edge.get('dst'))
                if dst is None:
                    continue
                if _subtree_has_payload(int(dst)):
                    already_has_generic = True
                    break
            if already_has_generic:
                continue
            max_node_id = max(nodes_by_id.keys(), default=-1)
            generic_vid = int(max_node_id + 1)
            len_id = int(max_node_id + 2)
            data_id = int(max_node_id + 3)
            sel_node = nodes_by_id.get(int(selector_id)) or {}
            byte_order = sel_node.get('byte_order') or parent.get('byte_order') or 'big'
            if isinstance(variant_bit_start, (int, float)) and (not isinstance(variant_bit_start, bool)):
                generic_bit_start: Any = int(variant_bit_start)
            else:
                generic_bit_start = str(variant_bit_start or '').strip()
                if not generic_bit_start:
                    sel_size = _coerce_int_or_none(sel_node.get('size_bits')) or 8
                    generic_bit_start = f'{int(selector_id)}.bit_start + {int(sel_size)}'
            generic_variant = {'node_id': generic_vid, 'name': 'Generic_TLV', 'node_type': 'variant', 'message_type': message_type, 'bit_start': generic_bit_start, 'size_bits': 'variable', 'data_type': 'binary', 'byte_order': byte_order, 'parent_id': int(variant_parent_id), 'children_ids': [len_id, data_id], 'constraints': [], 'dependencies': []}
            length_node = {'node_id': len_id, 'name': 'Option_Length', 'node_type': 'length', 'message_type': message_type, 'bit_start': f'{generic_vid}.bit_start + 0', 'size_bits': int(length_size_bits), 'data_type': 'uint8', 'byte_order': byte_order, 'parent_id': generic_vid, 'children_ids': [], 'constraints': [], 'dependencies': []}
            data_node = {'node_id': data_id, 'name': 'Option_Data', 'node_type': 'payload', 'message_type': message_type, 'bit_start': f'{len_id}.bit_start + {len_id}.size_bits', 'size_bits': 'variable', 'data_type': 'bytes', 'byte_order': byte_order, 'parent_id': generic_vid, 'children_ids': [], 'constraints': [], 'dependencies': []}
            nodes.extend([generic_variant, length_node, data_node])
            nodes_by_id[generic_vid] = generic_variant
            nodes_by_id[len_id] = length_node
            nodes_by_id[data_id] = data_node
            lookup[generic_vid] = generic_variant
            lookup[str(generic_vid)] = generic_variant
            lookup[len_id] = length_node
            lookup[str(len_id)] = length_node
            lookup[data_id] = data_node
            lookup[str(data_id)] = data_node
            parent_children = parent.get('children_ids')
            if not isinstance(parent_children, list):
                parent_children = []
                parent['children_ids'] = parent_children
            parent_children.append(generic_vid)
            edges.append({'src': int(selector_id), 'dst': int(generic_vid), 'rel': 'condition_on', 'formula': cond_formula, 'message_type': message_type})
            edges.append({'src': int(len_id), 'dst': int(data_id), 'rel': 'length_of', 'formula': f'val({int(len_id)})*8', 'message_type': message_type})
            changes.append(f'add_tlv_generic_variant selector={selector_id} variant_id={generic_vid} len_id={len_id} data_id={data_id}')
            continue
        if kind == 'make_semantic_only':
            nid = _coerce_int_or_none(hint.get('node_id'))
            if nid is None:
                continue
            node = nodes_by_id.get(nid)
            if not node:
                continue
            if node.get('size_bits') != 0:
                node['size_bits'] = 0
            node['constraints'] = []
            changes.append(f'make_semantic_only node={nid}')
            continue
        if kind == 'remove_constraint':
            nid = _coerce_int_or_none(hint.get('node_id'))
            constraint = str(hint.get('constraint') or '').strip()
            if nid is None or not constraint:
                continue
            node = nodes_by_id.get(nid)
            if not node:
                continue
            constraints = node.get('constraints')
            if not isinstance(constraints, list) or not constraints:
                continue

            def _norm(c: Any) -> str:
                return str(c).strip().lower().replace(' ', '')
            target = _norm(constraint)
            removed = 0
            new_constraints: List[Any] = []
            for c in constraints:
                if _norm(c) == target:
                    removed += 1
                    continue
                new_constraints.append(c)
            if removed <= 0:
                continue
            node['constraints'] = new_constraints
            changes.append(f'remove_constraint node={nid} removed={removed}')
            continue
        if kind == 'remove_enum_constraint':
            nid = _coerce_int_or_none(hint.get('node_id'))
            constraint = str(hint.get('constraint') or '').strip()
            if nid is None:
                continue
            node = nodes_by_id.get(nid)
            if not node:
                continue
            constraints = node.get('constraints')
            if not isinstance(constraints, list) or not constraints:
                continue

            def _norm(c: Any) -> str:
                return str(c).strip().lower().replace(' ', '')
            removed = 0
            if constraint:
                target = _norm(constraint)
                new_constraints = []
                for c in constraints:
                    if _norm(c) == target:
                        removed += 1
                        continue
                    new_constraints.append(c)
                constraints = new_constraints
            else:
                new_constraints = []
                for c in constraints:
                    if str(c).strip().lower().startswith('enum:'):
                        removed += 1
                        continue
                    new_constraints.append(c)
                constraints = new_constraints
            if removed <= 0:
                continue
            node['constraints'] = constraints
            changes.append(f'remove_enum_constraint node={nid} removed={removed}')
            continue
        if kind == 'replace_constraint':
            nid = _coerce_int_or_none(hint.get('node_id'))
            remove = str(hint.get('remove') or '').strip()
            add = str(hint.get('add') or '').strip()
            if nid is None or not add:
                continue
            node = nodes_by_id.get(nid)
            if not node:
                continue
            constraints = node.get('constraints')
            if not isinstance(constraints, list):
                constraints = []

            def _norm(c: Any) -> str:
                return str(c).strip().lower().replace(' ', '')
            new_constraints: List[Any] = []
            removed = 0
            if remove:
                target = _norm(remove)
                for c in constraints:
                    if _norm(c) == target:
                        removed += 1
                        continue
                    new_constraints.append(c)
            else:
                new_constraints = list(constraints)
            if all((_norm(c) != _norm(add) for c in new_constraints)):
                new_constraints.append(add)
            node['constraints'] = new_constraints
            changes.append(f'replace_constraint node={nid} removed={removed} add={add}')
            continue
        if kind == 'shift_variant_subtree' and allow_shifts:
            vid = _coerce_int_or_none(hint.get('variant_id'))
            shift_bits = _coerce_int_or_none(hint.get('shift_bits'))
            if vid is None or shift_bits is None or shift_bits == 0:
                continue
            for nid in _walk_subtree(vid):
                node = nodes_by_id.get(nid)
                if not node:
                    continue
                raw = node.get('bit_start')
                if raw is None:
                    continue
                if isinstance(raw, (int, float)) and (not isinstance(raw, bool)):
                    node['bit_start'] = int(raw) + int(shift_bits)
                elif isinstance(raw, str):
                    try:
                        node['bit_start'] = int(raw.strip(), 0) + int(shift_bits)
                    except Exception:
                        continue
                else:
                    continue
            changes.append(f'shift_variant_subtree node={vid} shift_bits={shift_bits}')
    return (candidate, changes)

def _traffic_apply_heuristic_repairs(tree: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    candidate = json.loads(json.dumps(tree))
    lookup = _build_node_lookup(candidate)
    edges = candidate.get('edges')
    if not isinstance(edges, list):
        edges = []
        candidate['edges'] = edges
    changes: List[str] = []
    leaf_types = {'field', 'selector', 'type', 'length', 'checksum'}
    variable_tokens = {'variable', 'unknown', 'dynamic'}
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
                sel_node = lookup.get(sid) or lookup.get(str(sid)) or {}
                if str(sel_node.get('node_type') or '').lower() == 'selector':
                    return sid
        return None

    def _walk_subtree(root_id: Any) -> List[int]:
        rid = _coerce_int_or_none(root_id)
        if rid is None:
            return []
        seen: set[int] = {rid}
        out: List[int] = []
        stack: List[int] = [rid]
        while stack:
            nid = stack.pop()
            node = lookup.get(nid) or lookup.get(str(nid)) or {}
            for cid in node.get('children_ids') or []:
                cid_int = _coerce_int_or_none(cid)
                if cid_int is None or cid_int in seen:
                    continue
                seen.add(cid_int)
                out.append(cid_int)
                stack.append(cid_int)
        return out
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
        prev_size = _coerce_int_or_none(prev_node.get('size_bits'))
        prev_name = str(prev_node.get('name') or '').lower()
        if prev_size != 8:
            continue
        if 'byte_count' not in prev_name and 'byte count' not in prev_name:
            continue
        src_id = _coerce_int_or_none(prev_node.get('node_id'))
        dst_id = _coerce_int_or_none(nid)
        if src_id is None or dst_id is None:
            continue
        if any((isinstance(e, dict) and e.get('rel') == 'length_of' and (_coerce_int_or_none(e.get('src')) == src_id) and (_coerce_int_or_none(e.get('dst')) == dst_id) for e in edges)):
            continue
        edges.append({'src': int(src_id), 'dst': int(dst_id), 'rel': 'length_of', 'formula': f'val({int(src_id)})*8', 'message_type': node.get('message_type') or prev_node.get('message_type') or 'bidirectional'})
        incoming_length_of[dst_id].append(edges[-1])
        changes.append(f'add length_of {src_id}->{dst_id}')
    for node in list(candidate.get('nodes') or []):
        if not isinstance(node, dict):
            continue
        if str(node.get('node_type') or '').lower() != 'variant':
            continue
        vid = _coerce_int_or_none(node.get('node_id'))
        if vid is None:
            continue
        sid = _find_selector_for_variant(vid)
        if sid is None:
            continue
        sel_node = lookup.get(sid) or lookup.get(str(sid)) or {}
        sel_start = _coerce_int_or_none(sel_node.get('bit_start'))
        sel_size = _coerce_int_or_none(sel_node.get('size_bits'))
        var_start = _coerce_int_or_none(node.get('bit_start'))
        if sel_start is None or sel_size is None or var_start is None:
            continue
        parent_id = node.get('parent_id')
        parent_len_formula = _first_length_of_formula(parent_id)
        if not parent_len_formula:
            continue
        selector_end = sel_start + sel_size
        new_size_expr: Optional[str] = None
        if var_start == selector_end:
            new_size_expr = f'({parent_len_formula}) - {sel_size}'
        elif var_start == sel_start:
            new_size_expr = str(parent_len_formula)
        if new_size_expr is not None:
            cur_size = node.get('size_bits')
            cur_size_str = str(cur_size).strip().lower() if isinstance(cur_size, str) else None
            should_override = False
            if cur_size is None:
                should_override = True
            elif isinstance(cur_size, (int, float)) and (not isinstance(cur_size, bool)):
                should_override = True
            elif isinstance(cur_size, str) and (cur_size_str in variable_tokens or 'val(' not in cur_size.lower()):
                should_override = True
            if should_override and cur_size != new_size_expr:
                node['size_bits'] = new_size_expr
                changes.append(f'set variant {vid}.size_bits={new_size_expr}')
        children_ids = node.get('children_ids') or []
        child_starts: List[int] = []
        for cid in children_ids:
            cnode = lookup.get(cid) or lookup.get(str(cid)) or {}
            cstart = _coerce_int_or_none(cnode.get('bit_start'))
            if cstart is not None:
                child_starts.append(cstart)
        if not child_starts:
            continue
        if min(child_starts) != var_start + sel_size:
            continue
        for did in _walk_subtree(vid):
            dnode = lookup.get(did) or lookup.get(str(did)) or {}
            dstart = _coerce_int_or_none(dnode.get('bit_start'))
            if dstart is None:
                continue
            dnode['bit_start'] = int(dstart - sel_size)
        changes.append(f'shift subtree of variant {vid} by -{sel_size} bits')
    return (candidate, changes)

def _find_latest_fixed_tree() -> Tuple[Optional[Path], str]:
    candidate_dirs = [DATA_DIR / 'modbus' / 'outputs' / 'stage_b' / 'step2_results', DATA_DIR / 'modbus' / 'step2_results']
    for candidate_dir in candidate_dirs:
        if not candidate_dir.exists():
            continue
        fixed_files = sorted(candidate_dir.glob('fixed_protocol_tree_*.json'), key=lambda p: p.stat().st_mtime, reverse=True)
        if fixed_files:
            return (fixed_files[0], f'latest_step2_results@{candidate_dir}')
    return (None, 'fallback_final_cache')

def _load_tree(tree_path: Path) -> Dict[str, Any]:
    payload = json.loads(tree_path.read_text(encoding='utf-8'))
    if isinstance(payload, dict) and 'protocol_tree' in payload:
        return payload['protocol_tree']
    return payload

def _load_sections(sections_path: Path | None) -> List[dict]:

    def _try_load(path: Path) -> Optional[List[dict]]:
        try:
            payload = json.loads(path.read_text(encoding='utf-8'))
        except Exception:
            return None
        if isinstance(payload, dict) and 'sections' in payload:
            sections = payload.get('sections') or []
            return list(sections) if isinstance(sections, list) else []
        if isinstance(payload, list):
            return list(payload)
        return None
    if sections_path and sections_path.exists():
        parsed = _try_load(sections_path)
        if parsed is not None:
            return parsed
        logger.warning('Unrecognized sections format in %s (using fallback search)', sections_path)
    candidates = [DATA_DIR / 'modbus' / 'outputs' / 'stage_a' / 'modbus_document_sections_subset.json', DATA_DIR / 'modbus' / 'sections' / 'modbus_document_sections_subset.json']
    for cand in candidates:
        if cand.exists():
            parsed = _try_load(cand)
            if parsed is not None:
                logger.warning('Sections file not found/invalid at %s; using fallback %s', sections_path, cand)
                return parsed
    logger.error('Sections file not found or invalid: %s', sections_path)
    raise FileNotFoundError(f'Sections file not found or invalid: {sections_path}')

def _build_dfs_order_map(tree: Dict[str, Any]) -> Dict[str, int]:
    nodes_map: Dict[str, Dict[str, Any]] = {}
    for node in tree.get('nodes', []):
        if not isinstance(node, dict):
            continue
        nid = node.get('node_id')
        if nid is None:
            continue
        nodes_map[str(nid)] = node
    order_map: Dict[str, int] = {}
    counter = [0]

    def _dfs(nid: str) -> None:
        if nid in order_map:
            return
        order_map[nid] = counter[0]
        counter[0] += 1
        node = nodes_map.get(nid)
        if not node:
            return
        for child_id in node.get('children_ids', []):
            _dfs(str(child_id))
    root_id = tree.get('root_node_id')
    root_key = str(root_id) if root_id is not None else None
    if root_key and root_key in nodes_map:
        _dfs(root_key)
    for leftover in nodes_map:
        if leftover not in order_map:
            _dfs(leftover)
    return order_map

def parse_args() -> argparse.Namespace:
    auto_tree, auto_source = _find_latest_fixed_tree()
    fallback_tree = STEP2_CACHE_DIR / 'final_complete_protocol_tree.json'
    default_tree = auto_tree or fallback_tree
    traffic_candidates = [DATA_DIR / 'modbus' / 'inputs' / 'traffic' / 'traffic_modbus.txt', DATA_DIR / 'modbus' / 'traffic_modbus.txt', DATA_DIR / 'modbus' / 'traffic.txt']
    default_traffic = next((p for p in traffic_candidates if p.exists()), traffic_candidates[0])
    sections_candidates = [DATA_DIR / 'modbus' / 'outputs' / 'stage_a' / 'modbus_document_sections_subset.json', DATA_DIR / 'modbus' / 'sections' / 'modbus_document_sections_subset.json']
    default_sections = next((p for p in sections_candidates if p.exists()), sections_candidates[0])
    parser = argparse.ArgumentParser(description='Traffic-aware MCTS fix loop')
    parser.add_argument('--tree', type=Path, default=default_tree, help='Path to protocol tree JSON. Defaults to latest fixed_protocol_tree_*.json under data/modbus/outputs/stage_b/step2_results if present, otherwise falls back to data/_artifacts/step2_cache/final_complete_protocol_tree.json')
    parser.add_argument('--traffic', type=Path, default=default_traffic, help='Path to traffic hex dump (one frame per line, default: modbus traffic_modbus.txt)')
    parser.add_argument('--sections', type=Path, default=default_sections, help='Optional sections file for prompt context (default: modbus subset if present)')
    parser.add_argument('--batch-size', type=int, default=1, help='Batch size for MCTS refinement (traffic fix prefers 1)')
    parser.add_argument('--max-llm-calls', type=int, default=20, help='Maximum LLM calls for the fix loop')
    parser.add_argument('--max-packets', type=int, default=0, help='Max traffic samples to evaluate (0 = no limit)')
    parser.add_argument('--output', type=Path, default=STEP2_FIX_CACHE_DIR / 'traffic_fixed_tree.json', help='Where to save the refined tree')
    parser.add_argument('--per-issue-mcts', dest='per_issue_mcts', action='store_true', default=True, help='Run a full MCTS pass per highest-priority issue (default: on for traffic fix)')
    parser.add_argument('--no-per-issue-mcts', dest='per_issue_mcts', action='store_false', help='Process all issues in one MCTS run (legacy behaviour)')
    args = parser.parse_args()
    args._auto_tree_source = auto_source
    args._auto_tree_default = default_tree
    return args

def run_traffic_fix(tree_path: Path, traffic_path: Path, sections_path: Path | None, output_path: Path, max_llm_calls: int=20, max_packets: int=0, per_issue_mcts: bool=True, batch_size: int=1) -> Path:
    _setup_logging()
    tree = _load_tree(tree_path)
    digest_before = hashlib.sha256(json.dumps(tree, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')).hexdigest()
    sections = _load_sections(sections_path)
    logger.info('Loaded %s sections for traffic fix (source=%s)', len(sections), sections_path)
    if not sections:
        raise RuntimeError(f'No sections available for traffic fix (checked {sections_path})')
    agent = EnhancedPureAIAgent(cache_dir=STEP2_FIX_CACHE_DIR)
    packets = _load_packets_from_path(traffic_path, max_packets=0)
    total_packets = len(packets)
    logger.info('Starting traffic-focused refinement with traffic=%s (packets=%s)', traffic_path, total_packets)
    smoke_error = _smoke_test_interpreter(tree, packets)
    if smoke_error:
        logger.error('Aborting traffic fixing: %s', smoke_error)
        raise RuntimeError(smoke_error)
    shared_fix_history: List[Dict[str, Any]] = []
    sample_budget = total_packets if max_packets <= 0 else min(total_packets, max_packets)
    sample_payloads, sample_debug = _select_diverse_sample_payloads(tree=tree, packets=packets, sample_budget=sample_budget)
    logger.info('Traffic sample selection: strategy=%s selected=%s/%s groups=%s ok=%s failed=%s prefix_len=%s', sample_debug.get('strategy'), len(sample_payloads), total_packets, sample_debug.get('groups'), sample_debug.get('ok'), sample_debug.get('failed'), sample_debug.get('prefix_len'))

    def _static_validator(candidate_tree: Dict[str, Any]) -> ValidationReport:
        try:
            serialized = json.dumps(candidate_tree, ensure_ascii=False)
        except TypeError:
            serialized = json.dumps({'protocol_tree': candidate_tree}, ensure_ascii=False)
        report = validate_protocol_tree(serialized)
        extras = list(report.extras or [])
        extras.append('TRAFFIC_VALIDATION_SKIPPED')
        report.extras = extras
        return report

    def _needs_static_fix(report: ValidationReport) -> bool:
        return any((iss.severity == Severity.ERROR for iss in report.issues.values()))

    def _has_fatal_structure_error(report: ValidationReport) -> bool:
        for issue in report.issues.values():
            if issue.type == IssueType.STRUCTURE and issue.severity == Severity.ERROR:
                return True
        return False

    def _traffic_candidates(report: ValidationReport, current_tree: Dict[str, Any], payloads: Sequence[bytes]) -> Dict[int, Any]:
        try:
            raw = infer_size_bits_candidates_from_report(report, current_tree)
            lookup = _build_node_lookup(current_tree)
            root_id = current_tree.get('root_node_id')
            filtered: Dict[int, Any] = {}
            for nid, cands in raw.items():
                node = lookup.get(nid) or lookup.get(str(nid))
                if root_id is not None and (nid == root_id or str(nid) == str(root_id)):
                    continue
                if _is_aggregator_node(node, lookup):
                    continue
                filtered[nid] = cands
            for failure in getattr(report, 'traffic_failures', []) or []:
                nid = failure.node_id
                if _is_aggregator_node(lookup.get(nid) or lookup.get(str(nid)), lookup):
                    continue
                inferred = infer_size_formula_for_node(current_tree, nid, sections, payloads, interpreter_factory=DynamicTreeInterpreter)
                if inferred:
                    entry = SimpleNamespace(expression=inferred, controlling_field_id=None)
                    filtered.setdefault(nid, []).insert(0, entry)
            return filtered
        except Exception as exc:
            logger.debug('Failed to derive traffic length candidates: %s', exc, exc_info=True)
            return {}

    def _traffic_payload_fill_candidates(report: ValidationReport, current_tree: Dict[str, Any]) -> Dict[int, Any]:
        try:
            return infer_payload_fill_candidates_from_report(report, current_tree)
        except Exception as exc:
            logger.debug('Failed to derive traffic payload fill candidates: %s', exc, exc_info=True)
            return {}
    static_report = _static_validator(tree)
    if _needs_static_fix(static_report):
        tree = mcts_fix_tree(agent, tree, sections, raw_sections=None, batch_size=max(1, batch_size), max_llm_calls=max_llm_calls, validator_fn=_static_validator, prompt_mode='fix', fix_history=shared_fix_history)
        static_report = _static_validator(tree)
    if _needs_static_fix(static_report):
        raise RuntimeError('Static fixing still has errors; aborting traffic fix.')
    logger.info('======= TRAFFIC SEMANTIC FIXING (sampled packets=%s/%s) =======', len(sample_payloads), total_packets)

    def packet_validator(candidate_tree: Dict[str, Any]) -> ValidationReport:
        try:
            serialized = json.dumps(candidate_tree, ensure_ascii=False)
        except TypeError:
            serialized = json.dumps({'protocol_tree': candidate_tree}, ensure_ascii=False)
        static_report = validate_protocol_tree(serialized)
        has_static_errors = any((iss.severity == Severity.ERROR for iss in static_report.issues.values()))
        if _has_fatal_structure_error(static_report) or has_static_errors:
            try:
                extras = list(static_report.extras or [])
                extras.append('TRAFFIC_VALIDATION_SKIPPED_STATIC_ERRORS')
                static_report.extras = extras
                static_report.errors = list(static_report.errors) + ['TRAFFIC_VALIDATION_SKIPPED_STATIC_ERRORS']
            except Exception:
                pass
            try:
                setattr(static_report, 'traffic_total_samples', int(len(sample_payloads)))
                setattr(static_report, 'traffic_successful_samples', 0)
                setattr(static_report, 'traffic_coverage_gap_samples', int(len(sample_payloads)))
                setattr(static_report, 'traffic_total_coverage_gap_bits', 0)
                setattr(static_report, 'traffic_length_total_abs_error_bits', 0)
                setattr(static_report, 'traffic_overflow_length_bits', 0)
                setattr(static_report, 'traffic_repair_hints', [])
            except Exception:
                pass
            return static_report
        traffic_validator = SemanticValidator(candidate_tree, max_packets=len(sample_payloads), stop_on_first_failure=False, coverage_issue_grouping=os.getenv('STEP2_TRAFFIC_COVERAGE_ISSUE_GROUPING', 'prefix'))
        dynamic_issues, dynamic_extras, traffic_failures, traffic_stats = traffic_validator.validate_packets(list(sample_payloads))
        merged_issues = {issue_id: issue for issue_id, issue in static_report.issues.items() if issue.severity == Severity.ERROR}
        blocking_dynamic = [ctx for ctx in dynamic_issues if getattr(ctx.issue, 'severity', Severity.ERROR) == Severity.ERROR]
        warning_dynamic = [ctx for ctx in dynamic_issues if getattr(ctx.issue, 'severity', Severity.ERROR) != Severity.ERROR]
        for ctx in blocking_dynamic:
            merged_issues[ctx.issue.id] = ctx.issue
        ok = static_report.ok and len(blocking_dynamic) == 0
        errors = list(static_report.errors)
        warnings = list(getattr(static_report, 'warnings', []))
        if blocking_dynamic:
            errors.extend([ctx.message for ctx in blocking_dynamic])
        if warning_dynamic:
            warnings.extend([f'WARNING: {ctx.message}' for ctx in warning_dynamic])
        extras = list(static_report.extras) if static_report.extras else []
        extras.extend(dynamic_extras)
        extras.append(f'traffic_total_packets={total_packets}')
        extras.append(f'traffic_sample_packets={len(sample_payloads)}')
        extras.append(f"traffic_sample_strategy={sample_debug.get('strategy')}")
        extras.append(f"traffic_sample_groups={sample_debug.get('groups')}")
        return ValidationReport(ok=ok, errors=errors, warnings=warnings, extras=extras, issues=merged_issues, traffic_failures=traffic_failures, traffic_repair_hints=list(traffic_stats.get('repair_hints', []) or []))
    report = packet_validator(tree)
    try:
        baseline_traffic_ok = f"{int(getattr(report, 'traffic_successful_samples', 0) or 0)}/{int(getattr(report, 'traffic_total_samples', 0) or 0)}"
    except Exception:
        baseline_traffic_ok = '?'
    try:
        baseline_error_issues = sum((1 for iss in (getattr(report, 'issues', {}) or {}).values() if getattr(iss, 'severity', None) == Severity.ERROR))
    except Exception:
        baseline_error_issues = 0
    try:
        hints = list(getattr(report, 'traffic_repair_hints', []) or [])
        kind_counts = Counter((str(h.get('kind', '')) for h in hints if isinstance(h, dict))) if hints else Counter()
        try:
            preview_n = int(os.getenv('STEP2_TRAFFIC_HINTS_PREVIEW', '3').strip())
        except Exception:
            preview_n = 3
        if hints and preview_n > 0:
            preview: List[str] = []
            for hint in hints[:preview_n]:
                if not isinstance(hint, dict):
                    continue
                kind = str(hint.get('kind', '') or '')
                if kind == 'add_length_of':
                    preview.append(f"add_length_of src={hint.get('src_id')} dst={hint.get('dst_id')} formula={hint.get('formula')}")
                elif kind == 'set_variant_size_bits':
                    preview.append(f"set_variant_size_bits variant_id={hint.get('variant_id')} size_bits={hint.get('suggested_size_bits')}")
                elif kind == 'shift_variant_subtree':
                    preview.append(f"shift_variant_subtree variant_id={hint.get('variant_id')} shift_bits={hint.get('shift_bits')}")
                else:
                    preview.append(f"{kind} target={hint.get('target')}")
            if preview:
                pass
    except Exception:
        pass
    heur_flag = os.getenv('STEP2_TRAFFIC_HEURISTIC_PREPASS', '0').strip().lower()
    if not report.ok and heur_flag in {'1', 'true', 'yes', 'y', 'on'}:
        heuristic_tree, heuristic_changes = _traffic_apply_heuristic_repairs(tree)
        if heuristic_changes:
            heuristic_report = packet_validator(heuristic_tree)
            baseline_score = _traffic_accept_score(report)
            candidate_score = _traffic_accept_score(heuristic_report)
            baseline_scalar = _traffic_scalar_score(report)
            candidate_scalar = _traffic_scalar_score(heuristic_report)
            baseline_total = int(getattr(report, 'traffic_total_samples', 0) or 0)
            candidate_total = int(getattr(heuristic_report, 'traffic_total_samples', 0) or 0)
            accept = candidate_total == baseline_total and candidate_scalar > baseline_scalar + 1e-09
            if accept:
                tree = heuristic_tree
                report = heuristic_report
    hint_flag = os.getenv('STEP2_TRAFFIC_HINT_PREPASS', '1').strip().lower()
    if not report.ok and hint_flag not in {'0', 'false', 'no', 'off'}:
        try:
            max_iters = int(os.getenv('STEP2_TRAFFIC_HINT_PREPASS_MAX_ITERS', '3').strip())
        except Exception:
            max_iters = 3
        max_iters = max(0, max_iters)
        allow_shifts = os.getenv('STEP2_TRAFFIC_HINT_PREPASS_ALLOW_SHIFT', '0').strip().lower() in {'1', 'true', 'yes', 'on'}
        baseline_score = _traffic_accept_score(report)
        baseline_scalar = _traffic_scalar_score(report)
        try:
            max_failed_increase = int(os.getenv('STEP2_TRAFFIC_ACCEPT_MAX_FAILED_INCREASE', '10').strip())
        except Exception:
            max_failed_increase = 10
        max_failed_increase = max(0, max_failed_increase)
        for iter_idx in range(max_iters):
            if report.ok:
                break
            hints = list(getattr(report, 'traffic_repair_hints', []) or [])
            if not hints:
                break
            bundled_tree, bundled_changes = _traffic_apply_repair_hints_bundle(tree, hints, allow_shifts=allow_shifts)
            if bundled_changes:
                bundled_report = packet_validator(bundled_tree)
                bundled_score = _traffic_accept_score(bundled_report)
                bundled_scalar = _traffic_scalar_score(bundled_report)
                improved = bundled_score < baseline_score or bundled_scalar > baseline_scalar + 1e-09
                within_failed_slack = bundled_score[0] <= baseline_score[0] + max_failed_increase
                accept = improved and within_failed_slack
                if accept:
                    tree = bundled_tree
                    report = bundled_report
                    baseline_score = bundled_score
                    baseline_scalar = bundled_scalar
                    continue
            accepted_single = False
            for hint in hints:
                single_tree, single_changes = _traffic_apply_repair_hints_bundle(tree, [hint], allow_shifts=allow_shifts)
                if not single_changes:
                    continue
                single_report = packet_validator(single_tree)
                single_score = _traffic_accept_score(single_report)
                single_scalar = _traffic_scalar_score(single_report)
                improved = single_score < baseline_score or single_scalar > baseline_scalar + 1e-09
                within_failed_slack = single_score[0] <= baseline_score[0] + max_failed_increase
                accept = improved and within_failed_slack
                if not accept:
                    continue
                tree = single_tree
                report = single_report
                baseline_score = single_score
                baseline_scalar = single_scalar
                accepted_single = True
                break
            if not accepted_single:
                break
    if not report.ok:
        logger.info('Traffic sample failed; invoking traffic-focused MCTS.')
        try:
            env_rounds = os.getenv('STEP2_TRAFFIC_MCTS_ROUNDS')
            max_rounds = int(env_rounds) if env_rounds is not None else 3 if per_issue_mcts else 1
        except Exception:
            max_rounds = 3 if per_issue_mcts else 1
        max_rounds = max(1, max_rounds)
        baseline_score = _traffic_accept_score(report)
        baseline_scalar = _traffic_scalar_score(report)
        for round_idx in range(max_rounds):
            if report.ok:
                break
            size_candidates_by_node = _traffic_candidates(report, tree, sample_payloads)
            payload_fill_candidates = _traffic_payload_fill_candidates(report, tree)
            candidate_tree = mcts_fix_tree(agent, tree, sections, raw_sections=None, batch_size=max(1, batch_size), max_llm_calls=max(0, int(max_llm_calls)), validator_fn=packet_validator, prompt_mode='traffic_fix', fix_history=shared_fix_history, size_bits_candidates=size_candidates_by_node, payload_fill_candidates=payload_fill_candidates)
            candidate_report = packet_validator(candidate_tree)
            candidate_score = _traffic_accept_score(candidate_report)
            candidate_scalar = _traffic_scalar_score(candidate_report)
            improved = candidate_score < baseline_score or candidate_scalar > baseline_scalar + 1e-09
            try:
                max_failed_increase = int(os.getenv('STEP2_TRAFFIC_ACCEPT_MAX_FAILED_INCREASE', '10').strip())
            except Exception:
                max_failed_increase = 10
            max_failed_increase = max(0, max_failed_increase)
            within_failed_slack = candidate_score[0] <= baseline_score[0] + max_failed_increase
            improved = improved and within_failed_slack
            if not improved:
                break
            tree = candidate_tree
            report = candidate_report
            baseline_score = candidate_score
            baseline_scalar = candidate_scalar
    syntax_rounds = 0
    max_syntax_rounds = 3
    while syntax_rounds < max_syntax_rounds:
        syntax_report = run_full_validation(tree)
        syntax_errors = [iss for iss in syntax_report.issues.values() if iss.severity == Severity.ERROR]
        if not syntax_errors:
            break
        logger.warning('Syntax errors detected after traffic fix (round %s/%s); invoking syntax fix agent.', syntax_rounds + 1, max_syntax_rounds)
        llm_budget = max(0, int(max_llm_calls))
        if llm_budget <= 0:
            logger.warning('Skipping syntax fix agent because traffic LLM budget is 0 (set STEP2_TRAFFIC_MAX_LLM_CALLS to enable).')
            break
        tree = mcts_fix_tree(agent, tree, sections, raw_sections=None, batch_size=max(1, batch_size), max_llm_calls=llm_budget, validator_fn=run_full_validation, prompt_mode='fix', fix_history=shared_fix_history)
        post_report = packet_validator(tree)
        if not post_report.ok:
            logger.warning('Traffic sample failed again after syntax fixes; re-running traffic fix.')
            size_candidates_by_node = _traffic_candidates(post_report, tree, sample_payloads)
            payload_fill_candidates = _traffic_payload_fill_candidates(post_report, tree)
            tree = mcts_fix_tree(agent, tree, sections, raw_sections=None, batch_size=max(1, batch_size), max_llm_calls=llm_budget, validator_fn=packet_validator, prompt_mode='traffic_fix', fix_history=shared_fix_history, size_bits_candidates=size_candidates_by_node, payload_fill_candidates=payload_fill_candidates)
        syntax_rounds += 1
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(tree, ensure_ascii=False, indent=2), encoding='utf-8')
    digest_after = hashlib.sha256(json.dumps(tree, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')).hexdigest()
    tree_changed = digest_after != digest_before
    final_eval_payloads: List[bytes] = list(packets) if max_packets <= 0 else list(sample_payloads)
    final_validator = SemanticValidator(tree, max_packets=len(final_eval_payloads), stop_on_first_failure=False, coverage_issue_grouping=os.getenv('STEP2_TRAFFIC_COVERAGE_ISSUE_GROUPING', 'prefix'))
    _final_issues, _final_extras, _final_failures, final_stats = final_validator.validate_packets(final_eval_payloads)
    ok_packets = int(final_stats.get('success_count', 0) or 0)
    processed = int(final_stats.get('processed', 0) or 0)
    logger.info('Traffic-aware refinement complete. Saved to %s (traffic_ok=%s/%s)', output_path, ok_packets, processed)
    try:
        coverage_gap_samples = int(final_stats.get('coverage_gap_samples', 0) or 0)
    except Exception:
        coverage_gap_samples = 0
    try:
        coverage_gap_bits = int(final_stats.get('coverage_gap_bits', 0) or 0)
    except Exception:
        coverage_gap_bits = 0
    try:
        length_error_bits = int(final_stats.get('length_error_total_bits', 0) or 0)
    except Exception:
        length_error_bits = 0
    try:
        overflow_bits = int(final_stats.get('overflow_length_bits', 0) or 0)
    except Exception:
        overflow_bits = 0
    strict_cache = STEP2_FIX_CACHE_DIR / 'strict_validator_loop.json'
    traces_path = output_path.with_name('traffic_parsing_traces.jsonl')
    try:
        logger.info('Exporting parsing traces to %s', traces_path)
        export_parsing_traces(tree=tree, traffic_path=traffic_path, output_path=traces_path, max_packets=max_packets, payloads=sample_payloads)
        logger.info('Parsing traces exported to %s', traces_path)
    except Exception as exc:
        logger.warning('Failed to export parsing traces to %s: %s', traces_path, exc, exc_info=True)
    return output_path

def main() -> None:
    args = parse_args()
    _setup_logging()
    source_label = 'user-specified'
    if args.tree == getattr(args, '_auto_tree_default', None):
        source_label = getattr(args, '_auto_tree_source', 'auto')
    logger.info('Loading protocol tree from %s (source=%s)', args.tree, source_label)
    run_traffic_fix(tree_path=args.tree, traffic_path=args.traffic, sections_path=args.sections, output_path=args.output, max_llm_calls=args.max_llm_calls, max_packets=args.max_packets, per_issue_mcts=args.per_issue_mcts, batch_size=args.batch_size)
if __name__ == '__main__':
    main()
