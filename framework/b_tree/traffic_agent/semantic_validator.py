from __future__ import annotations
import json
import os
import re
import logging
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from collections import Counter
from framework.paths import LOGS_DIR
from ..validation_agent.syntax_validator import Issue, IssueType, Severity, TargetRef, ValidationReport, validate_protocol_tree
from .interpreter import ConstraintViolationError, DynamicTreeInterpreter, LEAF_TYPES, LengthMismatchError, RuntimeContext, RoutingError, NodeParseError, IncompleteStreamError
from ..validation_agent.traffic_errors import TrafficParseFailure
from .repair_hints import infer_repair_hints
logger = logging.getLogger(__name__)

@dataclass
class TrafficIssueContext:
    issue: Issue
    message: str
    packet_index: int
    hex_preview: Optional[str] = None
    severity: Severity = Severity.ERROR

@dataclass
class CoverageResult:
    merged_intervals: List[Tuple[int, int]]
    coverage_bits: int
    gap_bits: int
    tail_leftover_bits: int

class SemanticValidator:

    def __init__(self, protocol_tree: Dict[str, Any], max_packets: int=0, target_message_type: Optional[str]=None, stop_on_first_failure: Optional[bool]=None, coverage_issue_grouping: Optional[str]=None):
        self.protocol_tree = protocol_tree
        self.max_packets = max_packets
        self.interpreter = DynamicTreeInterpreter(protocol_tree, target_message_type=target_message_type)
        self._issue_counter = 0
        self.max_issue_examples_per_node = 5
        self._example_map: Dict[Tuple[str, str, Optional[str], str], Dict[str, Any]] = {}
        env_flag = os.getenv('TRAFFIC_STOP_ON_FIRST_FAILURE')
        if stop_on_first_failure is None:
            if env_flag is None:
                self.stop_on_first_failure = True
            else:
                self.stop_on_first_failure = env_flag.strip().lower() in {'1', 'true', 'yes', 'y', 'on'}
        else:
            self.stop_on_first_failure = bool(stop_on_first_failure)
        if coverage_issue_grouping is None:
            coverage_issue_grouping = os.getenv('STEP2_TRAFFIC_COVERAGE_ISSUE_GROUPING', 'bytes')
        self.coverage_issue_grouping = str(coverage_issue_grouping).strip().lower()
        nodes = protocol_tree.get('nodes', []) if isinstance(protocol_tree, dict) else []
        self.nodes_by_id: Dict[Any, Dict[str, Any]] = {n.get('node_id'): n for n in nodes if isinstance(n, dict)}
        for n in nodes:
            nid = n.get('node_id')
            if nid is not None:
                self.nodes_by_id[str(nid)] = n
        self.selector_for_dst: Dict[Any, Any] = {}
        for e in protocol_tree.get('edges', []) if isinstance(protocol_tree, dict) else []:
            if e.get('rel') == 'condition_on':
                self.selector_for_dst[e.get('dst')] = e.get('src')

    def _coverage_group_signature(self, ctx: RuntimeContext) -> str:
        max_selectors = max(1, int(os.getenv('STEP2_TRAFFIC_COVERAGE_ISSUE_SELECTOR_PREFIX_LEN', '3')))
        prefix_len = max(1, int(os.getenv('STEP2_TRAFFIC_COVERAGE_ISSUE_PATH_PREFIX_LEN', '8')))
        active_variants = getattr(ctx, 'active_variants', None) or {}
        if active_variants:
            ordered_selectors: List[int] = []
            for nid in getattr(ctx, 'parsing_path', None) or []:
                try:
                    nid_int = int(nid)
                except Exception:
                    continue
                if nid_int in active_variants and nid_int not in ordered_selectors:
                    ordered_selectors.append(nid_int)
                if len(ordered_selectors) >= max_selectors:
                    break
            if not ordered_selectors:
                for raw in active_variants.keys():
                    try:
                        ordered_selectors.append(int(raw))
                    except Exception:
                        continue
                ordered_selectors = ordered_selectors[:max_selectors]
            pairs: List[str] = []
            for sid in ordered_selectors:
                variants = active_variants.get(sid) or active_variants.get(str(sid)) or []
                chosen = variants[0] if variants else None
                try:
                    chosen_int = int(chosen) if chosen is not None else None
                except Exception:
                    chosen_int = None
                if chosen_int is None:
                    pairs.append(f'{sid}->?')
                else:
                    pairs.append(f'{sid}->{chosen_int}')
            if pairs:
                return f"selector_variants={','.join(pairs)}"
        path_prefix: List[int] = []
        for nid in (getattr(ctx, 'parsing_path', None) or [])[:prefix_len]:
            try:
                path_prefix.append(int(nid))
            except Exception:
                continue
        if path_prefix:
            return f'path_prefix={path_prefix}'
        return 'path_prefix=-'

    def _pick_coverage_anchor_node(self, ctx: Optional[RuntimeContext]) -> Optional[int]:
        if not ctx:
            return None
        raw_path = getattr(ctx, 'parsing_path', None) or []
        for nid in reversed(raw_path):
            node = self._node_lookup(nid)
            if not node:
                continue
            ntype = str(node.get('node_type') or '').lower()
            if ntype in LEAF_TYPES:
                continue
            if node.get('children_ids'):
                try:
                    return int(nid)
                except Exception:
                    continue
        root_id = self.protocol_tree.get('root_node_id')
        if root_id is not None:
            try:
                return int(root_id)
            except Exception:
                return None
        return None

    def _emit_variant_trial_failures(self, ctx: RuntimeContext, issues: List[TrafficIssueContext], traffic_failures: List[TrafficParseFailure], per_node_failures: Counter[int], *, packet_index: int, total_bits: int, hex_preview: Optional[str], packet_hex: Optional[str]=None, packet_len_bytes: Optional[int]=None, group_signature: Optional[str]=None) -> None:
        raw = getattr(ctx, 'variant_trial_errors', None) or []
        if not isinstance(raw, list) or not raw:
            return
        max_per_packet = max(1, int(os.getenv('STEP2_TRAFFIC_MAX_VARIANT_TRIAL_FAILURES_PER_PACKET', '8')))

        def _infer_kind(rec: Dict[str, Any]) -> str:
            err_type = str(rec.get('error_type') or '')
            msg = str(rec.get('message') or '')
            if err_type == 'ConstraintViolationError':
                return 'constraint'
            if err_type == 'IncompleteStreamError':
                if rec.get('error_bit_pos') is not None:
                    return 'oob_seek'
                if rec.get('error_bits_needed') is not None:
                    return 'oob_read'
                if 'seeking' in msg.lower():
                    return 'oob_seek'
                return 'oob_read'
            if err_type == 'NodeParseError':
                cause_type = str(rec.get('cause_type') or '')
                cause_msg = str(rec.get('cause_message') or '')
                if cause_type == 'IncompleteStreamError':
                    if rec.get('cause_bit_pos') is not None:
                        return 'oob_seek'
                    if rec.get('cause_bits_needed') is not None:
                        return 'oob_read'
                    if 'seeking' in cause_msg.lower():
                        return 'oob_seek'
                    return 'oob_read'
                if 'Not enough bits' in msg or 'read past end' in msg:
                    return 'oob_read'
            if 'Stream ended' in msg or 'IncompleteStream' in msg:
                return 'oob_seek'
            return 'node_error'
        for rec in raw[:max_per_packet]:
            if not isinstance(rec, dict):
                continue
            var_id = self._coerce_int(rec.get('variant_id'))
            if var_id is None:
                continue
            kind = _infer_kind(rec)
            bit_start_eval = self._coerce_int(rec.get('bit_start_eval'))
            size_bits_eval = self._coerce_int(rec.get('size_bits_eval'))
            selector_id = self._coerce_int(rec.get('selector_id'))
            parent_id = self._coerce_int(rec.get('group_parent_id'))
            candidates = rec.get('candidate_variants')
            if isinstance(candidates, list):
                try:
                    candidates = [int(x) for x in candidates if x is not None]
                except Exception:
                    candidates = None
            else:
                candidates = None
            msg = str(rec.get('message') or '')
            ctx_field_values: Dict[int, int] = {}
            try:
                for k, v in (ctx.values or {}).items():
                    if not str(k).lstrip('-').isdigit():
                        continue
                    coerced_val = self._coerce_int(v)
                    if coerced_val is None:
                        continue
                    ctx_field_values[int(k)] = int(coerced_val)
            except Exception:
                ctx_field_values = {}
            traffic_failures.append(TrafficParseFailure(packet_index=packet_index, node_id=int(var_id), failure_kind=kind, bit_start=bit_start_eval, size_bits_eval=size_bits_eval, total_bits=total_bits, max_bit_reached=self._compute_max_bit_reached(ctx, total_bits), path_node_ids=[int(x) for x in getattr(ctx, 'parsing_path', None) or [] if str(x).lstrip('-').isdigit()], context_field_values=ctx_field_values, message=f'speculative_candidate_failure: {msg}', routing_selector_id=int(selector_id) if selector_id is not None else None, routing_candidate_variant_ids=candidates, packet_hex=packet_hex, packet_len_bytes=packet_len_bytes, group_signature=group_signature))
            per_node_failures[int(var_id)] += 1
            if kind not in {'oob_seek', 'oob_read'}:
                continue
            escalate = os.getenv('STEP2_TRAFFIC_ESCALATE_SPECULATIVE_CANDIDATE_FAILURES', '0').strip().lower() in {'1', 'true', 'yes', 'y', 'on'}
            if not escalate:
                continue
            if getattr(self.interpreter, 'target_message_type', None) is None and selector_id is not None:
                try:
                    active = getattr(ctx, 'active_variants', None) or {}
                    winner_list = active.get(selector_id) or active.get(str(selector_id)) or []
                    winner_id = winner_list[0] if winner_list else None
                except Exception:
                    winner_id = None

                def _norm_msg_type(raw: Any) -> Optional[str]:
                    if raw is None:
                        return None
                    s = str(raw).strip().lower()
                    if not s:
                        return None
                    if s in {'bidirectional', 'both', 'any', 'unknown'}:
                        return None
                    return s
                try:
                    winner_mt = _norm_msg_type((self._node_lookup(winner_id) or {}).get('message_type'))
                    cand_mt = _norm_msg_type((self._node_lookup(var_id) or {}).get('message_type'))
                except Exception:
                    winner_mt = None
                    cand_mt = None
                if winner_mt is not None and cand_mt is not None and (winner_mt != cand_mt):
                    continue
            declared_end = self._coerce_int(rec.get('declared_end_bit'))
            desc_parts = [f'Candidate variant {int(var_id)} fails during speculative parsing ({kind}).']
            if selector_id is not None:
                desc_parts.append(f'selector={int(selector_id)}')
            if parent_id is not None:
                desc_parts.append(f'group_parent={int(parent_id)}')
            if bit_start_eval is not None:
                desc_parts.append(f'bit_start={int(bit_start_eval)}')
            if size_bits_eval is not None:
                desc_parts.append(f'size_bits={int(size_bits_eval)}')
            if declared_end is not None:
                desc_parts.append(f'end={int(declared_end)}')
            desc_parts.append('This typically indicates incorrect size_bits/bit_start alignment (e.g., double-counted prefix) or a missing length_of binding.')
            desc = ' | '.join(desc_parts)
            issue = self._make_issue(IssueType.STRUCTURE, Severity.ERROR, desc, str(int(var_id)), packet_index=None, hex_preview=None)
            self._record_issue(issues, TrafficIssueContext(issue=issue, message=f'packet #{packet_index}: candidate_variant_failure var={int(var_id)} kind={kind}', packet_index=packet_index, hex_preview=hex_preview))

    def _emit_node_overflow_failures(self, ctx: RuntimeContext, issues: List[TrafficIssueContext], traffic_failures: List[TrafficParseFailure], per_node_failures: Counter[int], *, packet_index: int, total_bits: int, max_bit_reached: int, hex_preview: Optional[str], packet_hex: Optional[str]=None, packet_len_bytes: Optional[int]=None, group_signature: Optional[str]=None) -> None:
        wire_sizes = getattr(ctx, 'wire_sizes', None) or {}
        declared_sizes = getattr(ctx, 'sizes', None) or {}
        bit_starts = getattr(ctx, 'bit_starts', None) or {}
        values = getattr(ctx, 'values', None) or {}
        if not isinstance(wire_sizes, dict) or not isinstance(declared_sizes, dict):
            return
        max_per_packet = max(1, int(os.getenv('STEP2_TRAFFIC_MAX_NODE_OVERFLOWS_PER_PACKET', '6')))
        path_node_ids: List[int] = []
        for nid in getattr(ctx, 'parsing_path', None) or []:
            try:
                path_node_ids.append(int(nid))
            except Exception:
                continue
        context_field_values: Dict[int, int] = {}
        try:
            for nid, val in values.items():
                nid_int = self._coerce_int(nid)
                val_int = self._coerce_int(val)
                if nid_int is None or val_int is None:
                    continue
                context_field_values[int(nid_int)] = int(val_int)
        except Exception:
            context_field_values = {}
        emitted = 0
        for raw_nid, raw_wire_bits in sorted(wire_sizes.items(), key=lambda kv: str(kv[0])):
            if emitted >= max_per_packet:
                break
            nid = self._coerce_int(raw_nid)
            if nid is None:
                continue
            try:
                wire_bits = int(raw_wire_bits)
            except Exception:
                continue
            raw_declared = declared_sizes.get(raw_nid)
            if raw_declared is None:
                raw_declared = declared_sizes.get(str(nid))
            try:
                declared_bits = int(raw_declared) if raw_declared is not None else 0
            except Exception:
                declared_bits = 0
            if declared_bits <= 0 or wire_bits <= declared_bits:
                continue
            node = self._node_lookup(nid) or {}
            node_type = str(node.get('node_type') or '').lower()
            if node_type not in {'protocol', 'header', 'payload', 'variant', 'container', 'tlv_seq'}:
                continue
            raw_start = bit_starts.get(raw_nid)
            if raw_start is None:
                raw_start = bit_starts.get(str(nid))
            try:
                start_bit = int(raw_start) if raw_start is not None else None
            except Exception:
                start_bit = None
            overflow_bits = int(wire_bits - declared_bits)
            name = str(node.get('name') or nid)
            size_expr = node.get('size_bits')
            msg_parts = [f'packet #{packet_index}: node_overflow node={nid}', f'declared_bits={declared_bits}', f'wire_bits={wire_bits}', f'overflow_bits={overflow_bits}']
            if start_bit is not None:
                msg_parts.append(f'start_bit={start_bit}')
                msg_parts.append(f'declared_end={start_bit + declared_bits}')
                msg_parts.append(f'actual_end={start_bit + wire_bits}')
            message = ' '.join(msg_parts)
            traffic_failures.append(TrafficParseFailure(packet_index=packet_index, node_id=int(nid), failure_kind='node_overflow', bit_start=start_bit, size_bits_eval=int(declared_bits), total_bits=total_bits, max_bit_reached=max_bit_reached, path_node_ids=list(path_node_ids), context_field_values=dict(context_field_values), message=message, packet_hex=packet_hex, packet_len_bytes=packet_len_bytes, group_signature=group_signature))
            per_node_failures[int(nid)] += 1
            desc = f'Layout: Node {name}(ID:{nid}) children may exceed parent size during traffic parsing'
            if size_expr is not None:
                desc += f' | size_bits={size_expr!r}'
            self._record_issue(issues, TrafficIssueContext(issue=self._make_issue(IssueType.STRUCTURE, Severity.ERROR, desc, str(nid), packet_index=packet_index, hex_preview=hex_preview), message=message, packet_index=packet_index, hex_preview=hex_preview))
            emitted += 1
        return

    @staticmethod
    def _compute_max_bit_reached(ctx: Optional[RuntimeContext], total_bits: int) -> int:
        if not ctx:
            return 0
        spans = getattr(ctx, 'field_spans', None) or []
        if isinstance(spans, list) and spans:
            max_end = 0
            for span in spans:
                if not isinstance(span, dict):
                    continue
                start = span.get('bit_start')
                size = span.get('wire_size_bits')
                if size is None:
                    size = span.get('content_size_bits')
                try:
                    start_i = int(start)
                    size_i = int(size)
                except Exception:
                    continue
                if size_i <= 0:
                    continue
                end = start_i + size_i
                if end > max_end:
                    max_end = end
            return min(max_end, total_bits) if total_bits > 0 else max_end
        max_bit = 0
        try:
            for nid, start in (ctx.bit_starts or {}).items():
                size = 0
                if hasattr(ctx, 'actual_sizes') and ctx.actual_sizes is not None:
                    size = ctx.actual_sizes.get(nid) or ctx.actual_sizes.get(str(nid)) or 0
                if not size and hasattr(ctx, 'sizes') and (ctx.sizes is not None):
                    size = ctx.sizes.get(nid) or ctx.sizes.get(str(nid)) or 0
                candidate = int(start) + int(size)
                if candidate > max_bit:
                    max_bit = candidate
        except Exception:
            return min(max_bit, total_bits)
        return min(max_bit, total_bits)

    @staticmethod
    def _coerce_int(value: Any) -> Optional[int]:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)):
            try:
                return int(value)
            except Exception:
                return None
        return None

    def _build_failure_record(self, packet_index: int, total_bits: int, context: Optional[RuntimeContext], error: Exception, *, packet_hex: Optional[str]=None, packet_len_bytes: Optional[int]=None, group_signature: Optional[str]=None) -> List[TrafficParseFailure]:
        failures: List[TrafficParseFailure] = []
        node_id_raw: Optional[Any] = getattr(error, 'node_id', None)
        if node_id_raw is None and context and getattr(context, 'parsing_path', None):
            node_id_raw = context.parsing_path[-1]
        msg = str(error)

        def _lookup(mapping: Optional[Dict[Any, Any]], key: Any) -> Optional[Any]:
            if not mapping:
                return None
            if key in mapping:
                return mapping.get(key)
            skey = str(key)
            if skey in mapping:
                return mapping.get(skey)
            return None
        path_node_ids: List[int] = []
        context_field_values: Dict[int, int] = {}
        if context:
            for nid in getattr(context, 'parsing_path', []) or []:
                try:
                    path_node_ids.append(int(nid))
                except Exception:
                    continue
            for nid, val in (context.values or {}).items():
                coerced_val = self._coerce_int(val)
                if coerced_val is None:
                    continue
                try:
                    nid_int = int(nid)
                except Exception:
                    continue
                context_field_values[nid_int] = coerced_val
        max_bit_reached = self._compute_max_bit_reached(context, total_bits)
        inferred_group_signature = group_signature
        if inferred_group_signature is None and context is not None:
            try:
                inferred_group_signature = self._coverage_group_signature(context)
            except Exception:
                inferred_group_signature = None

        def _append_failure(node_id: Optional[int], failure_kind: str, *, message: str, bit_start_override: Optional[int]=None, size_bits_override: Optional[int]=None, **extra_fields: Any) -> None:
            if node_id is None:
                return
            group_sig = extra_fields.pop('group_signature', inferred_group_signature)
            pkt_hex = extra_fields.pop('packet_hex', packet_hex)
            pkt_len = extra_fields.pop('packet_len_bytes', packet_len_bytes)
            failures.append(TrafficParseFailure(packet_index=packet_index, node_id=node_id, failure_kind=failure_kind, bit_start=bit_start_override if bit_start_override is not None else _lookup(getattr(context, 'bit_starts', {}), node_id), size_bits_eval=size_bits_override if size_bits_override is not None else _lookup(getattr(context, 'sizes', {}), node_id), total_bits=total_bits, max_bit_reached=max_bit_reached, path_node_ids=list(path_node_ids), context_field_values=dict(context_field_values), message=message, packet_hex=pkt_hex, packet_len_bytes=pkt_len, group_signature=group_sig, **extra_fields))
        if isinstance(error, LengthMismatchError):
            for detail in getattr(error, 'mismatches', []) or []:
                try:
                    dst_id = int(detail.dst)
                except Exception:
                    continue
                expected = self._coerce_int(getattr(detail, 'expected_bits', None))
                wire_bits = self._coerce_int(getattr(detail, 'wire_bits', None))
                content_bits = self._coerce_int(getattr(detail, 'content_bits', None) or getattr(detail, 'actual_bits', None))
                gap_bits = 0
                overflow_bits = 0
                if expected is not None and content_bits is not None:
                    if content_bits < expected:
                        gap_bits = expected - content_bits
                    elif content_bits > expected:
                        overflow_bits = content_bits - expected
                mismatch_kind = getattr(detail, 'mismatch_kind', None) or 'length_mismatch'
                if mismatch_kind == 'coverage_gap':
                    failure_kind = 'coverage_gap'
                elif mismatch_kind == 'overflow':
                    failure_kind = 'length_overflow'
                else:
                    failure_kind = 'length_mismatch'
                _append_failure(dst_id, failure_kind, message=str(error), length_mismatch_src=self._coerce_int(detail.src), length_mismatch_dst=self._coerce_int(detail.dst), length_src_node_id=self._coerce_int(detail.src), length_expected_bits=expected, length_actual_bits=self._coerce_int(getattr(detail, 'actual_bits', None)), length_content_bits=content_bits, length_wire_bits=wire_bits, length_gap_bits=gap_bits or None, length_overflow_bits=overflow_bits or None, length_mismatch_kind=mismatch_kind, length_formula=getattr(detail, 'formula', None))
            return failures
        if isinstance(error, ConstraintViolationError):
            try:
                nid = int(getattr(error, 'node_id', None))
            except Exception:
                nid = None
            _append_failure(nid, 'constraint', message=str(error), constraint_text=getattr(error, 'constraint_text', None), constraint_value=self._coerce_int(getattr(error, 'value', None)), constraint_kind=getattr(error, 'kind', None))
            return failures
        if isinstance(error, RoutingError):
            try:
                nid = int(getattr(error, 'node_id', None))
            except Exception:
                nid = None

            def _coerce_tree_int(raw: Any) -> Optional[int]:
                if raw is None:
                    return None
                if isinstance(raw, bool):
                    return None
                if isinstance(raw, (int, float)):
                    try:
                        return int(raw)
                    except Exception:
                        return None
                if isinstance(raw, str):
                    s = raw.strip()
                    if not s:
                        return None
                    if s.isdigit() or (s.startswith('-') and s[1:].isdigit()):
                        try:
                            return int(s)
                        except Exception:
                            return None
                return None

            def _variant_failure_kind(exc: Any) -> str:
                if isinstance(exc, ConstraintViolationError):
                    return 'constraint'
                if isinstance(exc, LengthMismatchError):
                    return 'length_mismatch'
                if isinstance(exc, NodeParseError):
                    cause = getattr(exc, 'cause', None)
                    if isinstance(cause, IncompleteStreamError):
                        return 'oob_seek'
                    msg_lower = str(exc).lower()
                    if 'not enough bits' in msg_lower or 'read past end' in msg_lower:
                        return 'oob_read'
                    return 'node_error'
                if isinstance(exc, IncompleteStreamError):
                    return 'oob_seek'
                if isinstance(exc, RoutingError):
                    return 'routing'
                return 'routing_variant_error'
            selector_id = self._coerce_int(getattr(error, 'selector_id', None))
            candidate_variants: List[int] = []
            for raw in getattr(error, 'candidate_variants', None) or []:
                coerced = self._coerce_int(raw)
                if coerced is None:
                    continue
                try:
                    candidate_variants.append(int(coerced))
                except Exception:
                    continue
            if not candidate_variants:
                for entry in getattr(error, 'variant_errors', []) or []:
                    if isinstance(entry, (tuple, list)) and len(entry) == 2:
                        coerced = self._coerce_int(entry[0])
                        if coerced is None:
                            continue
                        try:
                            candidate_variants.append(int(coerced))
                        except Exception:
                            continue
            variant_details: List[Dict[str, Any]] = []
            max_variant_errors = max(1, int(os.getenv('STEP2_TRAFFIC_ROUTING_VARIANT_ERRORS', '6')))
            for entry in getattr(error, 'variant_errors', []) or []:
                var_id: Optional[int] = None
                exc: Any = entry
                if isinstance(entry, (tuple, list)) and len(entry) == 2:
                    var_id = self._coerce_int(entry[0])
                    exc = entry[1]
                err_type = type(exc).__name__
                err_msg = str(exc)
                err_node_id: Optional[int] = None
                if isinstance(exc, NodeParseError):
                    err_node_id = self._coerce_int(getattr(exc, 'node_id', None))
                elif isinstance(exc, ConstraintViolationError):
                    err_node_id = self._coerce_int(getattr(exc, 'node_id', None))
                elif isinstance(exc, LengthMismatchError):
                    err_node_id = self._coerce_int(getattr(exc, 'node_id', None))
                elif isinstance(exc, RoutingError):
                    err_node_id = self._coerce_int(getattr(exc, 'node_id', None))
                else:
                    m = re.search('node\\s+([\\w-]+)', err_msg)
                    if m:
                        err_node_id = self._coerce_int(m.group(1))
                detail: Dict[str, Any] = {'variant_id': var_id, 'variant_name': (self.nodes_by_id.get(var_id) or self.nodes_by_id.get(str(var_id), {}) or {}).get('name') if var_id is not None else None, 'error_type': err_type, 'node_id': err_node_id, 'message': err_msg}
                if isinstance(exc, RoutingError):
                    detail['routing_selector_id'] = self._coerce_int(getattr(exc, 'selector_id', None))
                    raw = getattr(exc, 'candidate_variants', None) or []
                    try:
                        detail['routing_candidate_variant_ids'] = [int(x) for x in raw]
                    except Exception:
                        pass
                variant_details.append(detail)
                if len(variant_details) >= max_variant_errors:
                    break
            route_group_signature = inferred_group_signature
            if route_group_signature is None:
                parts: List[str] = []
                if selector_id is not None:
                    parts.append(f'selector={selector_id}')
                if candidate_variants:
                    parts.append(f'candidates={candidate_variants[:10]}')
                if parts:
                    route_group_signature = 'routing:' + ' '.join(parts)
            _append_failure(nid, 'routing', message=str(error), routing_selector_id=selector_id, routing_candidate_variant_ids=candidate_variants or None, routing_variant_errors=variant_details or None, group_signature=route_group_signature)
            emitted = 0
            for entry in getattr(error, 'variant_errors', []) or []:
                if emitted >= max_variant_errors:
                    break
                var_id: Optional[int] = None
                exc: Any = entry
                if isinstance(entry, (tuple, list)) and len(entry) == 2:
                    var_id = self._coerce_int(entry[0])
                    exc = entry[1]
                elif isinstance(entry, dict):
                    var_id = self._coerce_int(entry.get('variant_id'))
                    exc = entry.get('error') or entry.get('exception') or entry
                if var_id is None:
                    continue
                var_node = self.nodes_by_id.get(var_id) or self.nodes_by_id.get(str(var_id)) or {}
                bit_start_eval = _coerce_tree_int(var_node.get('bit_start') if isinstance(var_node, dict) else None)
                size_bits_eval = _coerce_tree_int(var_node.get('size_bits') if isinstance(var_node, dict) else None)
                declared_end = bit_start_eval + size_bits_eval if bit_start_eval is not None and size_bits_eval is not None else None
                failure_kind = _variant_failure_kind(exc)
                if declared_end is not None and declared_end > total_bits and (failure_kind not in {'oob_seek', 'oob_read'}):
                    failure_kind = 'oob_seek'
                vname = ''
                if isinstance(var_node, dict):
                    vname = str(var_node.get('name') or '')
                msg = str(exc)
                if isinstance(exc, IncompleteStreamError):
                    bit_pos = getattr(exc, 'bit_pos', None)
                    tot = getattr(exc, 'total_bits', None)
                    if bit_pos is not None or tot is not None:
                        msg = f'{msg} (bit_pos={bit_pos}, total_bits={tot})'
                detail_msg = f'routing_candidate_failed variant={vname}({var_id}): {msg}'
                if declared_end is not None:
                    detail_msg += f' | declared_end={declared_end} packet_total_bits={total_bits}'
                variant_path = list(path_node_ids)
                if var_id not in variant_path:
                    variant_path.append(var_id)
                variant_max_bit = max_bit_reached
                if isinstance(exc, IncompleteStreamError) and getattr(exc, 'bit_pos', None) is not None:
                    try:
                        variant_max_bit = min(int(getattr(exc, 'bit_pos')), total_bits)
                    except Exception:
                        pass
                failures.append(TrafficParseFailure(packet_index=packet_index, node_id=int(var_id), failure_kind=failure_kind, bit_start=bit_start_eval, size_bits_eval=size_bits_eval, total_bits=total_bits, max_bit_reached=variant_max_bit, path_node_ids=variant_path, context_field_values=dict(context_field_values), message=detail_msg, routing_selector_id=selector_id, routing_candidate_variant_ids=candidate_variants or None, packet_hex=packet_hex, packet_len_bytes=packet_len_bytes, group_signature=route_group_signature))
                emitted += 1
            return failures
        node_id_int: Optional[int] = None
        try:
            if node_id_raw is not None:
                node_id_int = int(node_id_raw)
        except Exception:
            node_id_int = None
        failure_kind = 'unknown'
        if isinstance(error, RoutingError):
            failure_kind = 'routing'
        elif isinstance(error, NodeParseError):
            if isinstance(getattr(error, 'cause', None), IncompleteStreamError):
                failure_kind = 'oob_seek'
            elif 'Not enough bits' in msg:
                failure_kind = 'oob_read'
            elif 'read past end' in msg:
                failure_kind = 'oob_read'
            else:
                failure_kind = 'node_error'
        elif 'Stream ended' in msg or 'IncompleteStream' in msg:
            failure_kind = 'oob_seek'
        elif msg.startswith('Incomplete parse:'):
            failure_kind = 'coverage_tail_gap'
        extra_fields: Dict[str, Any] = {}
        if failure_kind == 'coverage_tail_gap':
            try:
                m = re.search('^Incomplete parse:\\s*(\\d+)\\s*bits\\b', msg)
                if m:
                    extra_fields['coverage_tail_leftover_bits'] = int(m.group(1))
            except Exception:
                pass
        _append_failure(node_id_int, failure_kind, message=msg, **extra_fields)
        return failures

    def validate_packets(self, packets: Iterable[bytes]) -> Tuple[List[TrafficIssueContext], List[str], List[TrafficParseFailure], Dict[str, Any]]:
        issues: List[TrafficIssueContext] = []
        extras: List[str] = []
        processed = 0
        success_count = 0
        traffic_failures: List[TrafficParseFailure] = []
        per_node_failures: Counter[int] = Counter()
        first_failure_idx: Optional[int] = None
        protocol_name = self.protocol_tree.get('protocol_name', 'unknown')
        log_dir = LOGS_DIR / 'traffic_fix' / protocol_name
        log_dir.mkdir(parents=True, exist_ok=True)
        trace_log_path = log_dir / 'parsing.log'
        detail_log_path = log_dir / 'traffic_packet_check.log'
        try:
            trace_log_path.unlink()
        except FileNotFoundError:
            pass
        try:
            detail_log_path.unlink()
        except FileNotFoundError:
            pass
        with trace_log_path.open('w', encoding='utf-8') as trace_log, detail_log_path.open('w', encoding='utf-8') as detail_log:
            trace_log.write(f"\n--- Batch Validation: {self.protocol_tree.get('protocol_name', 'unknown')} ---\n")
            detail_log.write(f"\n--- Packet Details: {self.protocol_tree.get('protocol_name', 'unknown')} ---\n")
            for idx, payload in enumerate(packets):
                if self.max_packets and idx >= self.max_packets:
                    break
                processed += 1
                packet_len_bytes = len(payload)
                total_bits = packet_len_bytes * 8
                preview_len_bytes = max(1, int(os.getenv('STEP2_TRAFFIC_HEX_PREVIEW_BYTES', '16')))
                hex_preview = payload[:preview_len_bytes].hex()
                packet_hex = payload.hex()
                logger.debug('Packet #%s start len=%s hex-preview=%s', idx, len(payload), hex_preview)
                try:
                    success, context, error = self.interpreter.parse(payload)
                except RoutingError as exc:
                    logger.debug('Packet #%s routing failure: %s', idx, exc, exc_info=True)
                    trace_log.write(f'Packet {idx}: FAIL[{exc}] | Path: -\n')
                    routing_issue = TrafficIssueContext(issue=self._make_issue(IssueType.STRUCTURE, Severity.ERROR, f'Routing failed on packet #{idx}: {exc}', getattr(exc, 'node_id', None), packet_index=idx, hex_preview=hex_preview), message=f'packet #{idx}: {exc}', packet_index=idx, hex_preview=hex_preview)
                    issues.append(routing_issue)
                    failure_records = self._build_failure_record(idx, total_bits, None, exc, packet_hex=packet_hex, packet_len_bytes=packet_len_bytes)
                    if not failure_records:
                        group_sig = None
                        selector_id = getattr(exc, 'selector_id', None)
                        candidates = getattr(exc, 'candidate_variants', None) or []
                        parts: List[str] = []
                        if selector_id is not None:
                            parts.append(f'selector={selector_id}')
                        if candidates:
                            parts.append(f'candidates={list(candidates)[:10]}')
                        if parts:
                            group_sig = 'routing:' + ' '.join(parts)
                        failure_records = [TrafficParseFailure(packet_index=idx, node_id=getattr(exc, 'node_id', None) or -1, failure_kind='routing', bit_start=None, size_bits_eval=None, total_bits=total_bits, max_bit_reached=0, path_node_ids=[], context_field_values={}, message=str(exc), packet_hex=packet_hex, packet_len_bytes=packet_len_bytes, group_signature=group_sig)]
                    for record in failure_records:
                        traffic_failures.append(record)
                        per_node_failures[getattr(record, 'node_id', -1)] += 1
                    if first_failure_idx is None:
                        first_failure_idx = idx
                    if self.stop_on_first_failure:
                        extras.append(f'validation_stopped_at_packet={idx}')
                        logger.info('Validation stopped early due to routing failure in packet #%s', idx)
                        break
                    continue
                except Exception as exc:
                    logger.debug('Packet #%s crashed interpreter: %s', idx, exc, exc_info=True)
                    trace_log.write(f'Packet {idx}: CRASH[{exc}] | Path: -\n')
                    crash_issue = TrafficIssueContext(issue=self._make_issue(IssueType.SEMANTICS, Severity.ERROR, f'Interpreter crashed on packet #{idx}: {exc}', None), message=f'packet #{idx}: {exc}', packet_index=idx, hex_preview=hex_preview)
                    issues.append(crash_issue)
                    failure = TrafficParseFailure(packet_index=idx, node_id=-1, failure_kind='structure', bit_start=None, size_bits_eval=None, total_bits=total_bits, max_bit_reached=0, path_node_ids=[], context_field_values={}, packet_hex=packet_hex, packet_len_bytes=packet_len_bytes, group_signature='crash')
                    traffic_failures.append(failure)
                    if first_failure_idx is None:
                        first_failure_idx = idx
                    if self.stop_on_first_failure:
                        extras.append(f'validation_stopped_at_packet={idx}')
                        logger.info('Validation stopped early due to crash in packet #%s', idx)
                        break
                    continue
                path_names: List[str] = []
                ctx_path = context.parsing_path if context else []
                for nid in ctx_path:
                    n_obj = self.nodes_by_id.get(nid) or self.nodes_by_id.get(str(nid), {}) or {}
                    path_names.append(f"{n_obj.get('name', nid)}({nid})")
                status_str = 'PASS' if success else f'FAIL[{error}]'
                trace_log.write(f"Packet {idx}: {status_str} | Path: {' -> '.join(path_names)}\n")
                if context:
                    detail_log.write(f'Packet {idx}: {status_str}\n')
                    detail_log.write(f'Hex preview: {payload[:32].hex()} (len_bytes={len(payload)})\n')
                    detail_log.write(f'Visited nodes: {list(context.visited_nodes)}\n')
                    detail_log.write('Values:\n')
                    for nid, val in context.values.items():
                        n_obj = self.nodes_by_id.get(nid) or self.nodes_by_id.get(str(nid), {}) or {}
                        detail_log.write(f"  {n_obj.get('name', nid)}({nid}) = {val}\n")
                    detail_log.write('Sizes (bits):\n')
                    for nid, sz in context.sizes.items():
                        n_obj = self.nodes_by_id.get(nid) or self.nodes_by_id.get(str(nid), {}) or {}
                        detail_log.write(f"  {n_obj.get('name', nid)}({nid}) = {sz}\n")
                    detail_log.write('Bit starts:\n')
                    for nid, bs in context.bit_starts.items():
                        n_obj = self.nodes_by_id.get(nid) or self.nodes_by_id.get(str(nid), {}) or {}
                        detail_log.write(f"  {n_obj.get('name', nid)}({nid}) = {bs}\n")
                    detail_log.write('\n')
                if success:
                    success_count += 1
                    group_sig: Optional[str] = None
                    if context is not None:
                        try:
                            group_sig = self._coverage_group_signature(context)
                        except Exception:
                            group_sig = None
                    max_bits = self._compute_max_bit_reached(context, total_bits)
                    if getattr(context, 'length_gaps', None):
                        gap_records = self._build_failure_record(idx, total_bits, context, LengthMismatchError(list(context.length_gaps)), packet_hex=packet_hex, packet_len_bytes=packet_len_bytes, group_signature=group_sig)
                        for record in gap_records:
                            traffic_failures.append(record)
                            per_node_failures[record.node_id] += 1
                        for record in gap_records:
                            if (record.failure_kind or '').lower() != 'coverage_gap':
                                continue
                            dst_id = record.node_id
                            src_id = record.length_mismatch_src or record.length_src_node_id
                            formula = record.length_formula or ''
                            desc = f"Coverage gap under length_of edge src={src_id} dst={dst_id}{(f' formula={formula!r}' if formula else '')}: parsed content is smaller than the length-controlled region. This usually means missing leaf fields; consider adding an opaque bytes field to fill the gap or modelling the missing payload structure."
                            msg_bits = []
                            if record.length_expected_bits is not None:
                                msg_bits.append(f'expected_bits={record.length_expected_bits}')
                            if record.length_content_bits is not None:
                                msg_bits.append(f'content_bits={record.length_content_bits}')
                            if record.length_gap_bits is not None:
                                msg_bits.append(f'gap_bits={record.length_gap_bits}')
                            if record.length_wire_bits is not None:
                                msg_bits.append(f'wire_bits={record.length_wire_bits}')
                            msg = f'packet #{idx}: coverage_gap edge {src_id}->{dst_id}' + (f" ({', '.join(msg_bits)})" if msg_bits else '')
                            self._record_issue(issues, TrafficIssueContext(issue=self._make_issue(IssueType.SEMANTICS, Severity.ERROR, desc, str(dst_id), hex_preview=hex_preview, packet_index=idx), message=msg, packet_index=idx, hex_preview=hex_preview))
                    logger.debug('Packet #%s parsed successfully: visited=%s active_variants=%s visit_order=%s', idx, list(context.visited_nodes), context.active_variants, context.visit_log)
                    self._check_parse_path(context, issues, idx, len(payload) * 8, hex_preview)
                    self._emit_variant_trial_failures(context, issues, traffic_failures, per_node_failures, packet_index=idx, total_bits=total_bits, hex_preview=hex_preview, packet_hex=packet_hex, packet_len_bytes=packet_len_bytes, group_signature=group_sig)
                    try:
                        self._emit_node_overflow_failures(context, issues, traffic_failures, per_node_failures, packet_index=idx, total_bits=total_bits, max_bit_reached=max_bits, hex_preview=hex_preview, packet_hex=packet_hex, packet_len_bytes=packet_len_bytes, group_signature=group_sig)
                    except Exception:
                        logger.debug('Failed to emit node overflow failures', exc_info=True)
                    coverage = self._compute_coverage(context, total_bits)
                    if coverage.tail_leftover_bits > 0 or coverage.gap_bits > 0:
                        path_node_ids: List[int] = []
                        context_field_values: Dict[int, int] = {}
                        for nid in getattr(context, 'parsing_path', []) or []:
                            try:
                                path_node_ids.append(int(nid))
                            except Exception:
                                continue
                        for nid, val in (context.values or {}).items():
                            coerced_val = self._coerce_int(val)
                            if coerced_val is None:
                                continue
                            try:
                                nid_int = int(nid)
                            except Exception:
                                continue
                            context_field_values[nid_int] = coerced_val
                        anchor = self._pick_coverage_anchor_node(context)
                        if anchor is None and path_node_ids:
                            anchor = path_node_ids[-1]
                        if anchor is not None:

                            def _lookup(mapping: Dict[Any, Any], key: Any) -> Optional[Any]:
                                if key in mapping:
                                    return mapping.get(key)
                                skey = str(key)
                                if skey in mapping:
                                    return mapping.get(skey)
                                return None
                            bit_start = _lookup(getattr(context, 'bit_starts', {}) or {}, anchor)
                            size_bits_eval = _lookup(getattr(context, 'sizes', {}) or {}, anchor)
                            if coverage.tail_leftover_bits > 0:
                                leftover_bytes = (coverage.tail_leftover_bits + 7) // 8
                                traffic_failures.append(TrafficParseFailure(packet_index=idx, node_id=int(anchor), failure_kind='coverage_tail_gap', bit_start=bit_start if bit_start is None else int(bit_start), size_bits_eval=size_bits_eval if size_bits_eval is None else int(size_bits_eval), total_bits=total_bits, max_bit_reached=max_bits, path_node_ids=path_node_ids, context_field_values=context_field_values, message=f'packet #{idx}: coverage_tail_gap leftover_bytes={leftover_bytes} leftover_bits={coverage.tail_leftover_bits}', coverage_tail_leftover_bits=int(coverage.tail_leftover_bits), packet_hex=packet_hex, packet_len_bytes=packet_len_bytes, group_signature=group_sig))
                                per_node_failures[int(anchor)] += 1
                            if coverage.gap_bits > 0:
                                traffic_failures.append(TrafficParseFailure(packet_index=idx, node_id=int(anchor), failure_kind='coverage_internal_gap', bit_start=bit_start if bit_start is None else int(bit_start), size_bits_eval=size_bits_eval if size_bits_eval is None else int(size_bits_eval), total_bits=total_bits, max_bit_reached=max_bits, path_node_ids=path_node_ids, context_field_values=context_field_values, message=f'packet #{idx}: coverage_internal_gap gap_bits={coverage.gap_bits}', coverage_internal_gap_bits=int(coverage.gap_bits), packet_hex=packet_hex, packet_len_bytes=packet_len_bytes, group_signature=group_sig))
                                per_node_failures[int(anchor)] += 1
                    continue
                self._record_issue(issues, TrafficIssueContext(issue=self._issue_from_error(error, context, packet_index=idx, hex_preview=hex_preview), message=f'packet #{idx}: {error}', packet_index=idx, hex_preview=hex_preview))
                group_sig: Optional[str] = None
                if context is not None:
                    try:
                        group_sig = self._coverage_group_signature(context)
                    except Exception:
                        group_sig = None
                try:
                    if context is not None:
                        self._emit_node_overflow_failures(context, issues, traffic_failures, per_node_failures, packet_index=idx, total_bits=total_bits, max_bit_reached=self._compute_max_bit_reached(context, total_bits), hex_preview=hex_preview, packet_hex=packet_hex, packet_len_bytes=packet_len_bytes, group_signature=group_sig)
                except Exception:
                    logger.debug('Failed to emit node overflow failures (failure path)', exc_info=True)
                failure_records = self._build_failure_record(idx, total_bits, context, error, packet_hex=packet_hex, packet_len_bytes=packet_len_bytes, group_signature=group_sig)
                for record in failure_records:
                    traffic_failures.append(record)
                    per_node_failures[record.node_id] += 1
                if first_failure_idx is None:
                    first_failure_idx = idx
                if self.stop_on_first_failure:
                    extras.append(f'validation_stopped_at_packet={idx}')
                    logger.info('Validation stopped early due to failure in packet #%s', idx)
                    if context:
                        logger.debug('Packet #%s failure: visited=%s visit_order=%s bit_starts=%s sizes=%s active_variants=%s error=%s', idx, list(context.visited_nodes), context.visit_log, {k: context.bit_starts.get(k) for k in context.visited_nodes}, {k: context.sizes.get(k) for k in context.visited_nodes}, context.active_variants, error)
                    break
        if first_failure_idx is not None and (not any((e.startswith('validation_stopped_at_packet') for e in extras))):
            extras.append(f'first_failure_packet={first_failure_idx}')
        extras.append(f'traffic_batch_samples_checked={processed}')
        if processed and success_count == 0:
            issues.append(TrafficIssueContext(issue=self._make_issue(IssueType.SEMANTICS, Severity.ERROR, 'All sampled traffic frames failed to parse.', None), message='all_samples_failed', packet_index=0))
        issues = self._downgrade_coverage_warnings(issues)
        return (issues, extras, traffic_failures, {'processed': processed, 'success_count': success_count, 'repair_hints': infer_repair_hints(self.protocol_tree, traffic_failures)})

    def _downgrade_coverage_warnings(self, issues: List[TrafficIssueContext]) -> List[TrafficIssueContext]:
        if not issues:
            return issues
        has_error = False
        for ctx in issues:
            if ctx.issue.type != IssueType.COVERAGE:
                has_error = True
                break
            if ctx.issue.severity == Severity.ERROR and ctx.severity == Severity.ERROR:
                continue
        if has_error:
            return issues
        downgraded: List[TrafficIssueContext] = []
        for ctx in issues:
            try:
                downgraded_issue = Issue(id=ctx.issue.id, type=ctx.issue.type, severity=Severity.WARN, code=ctx.issue.code, description=ctx.issue.description, target=ctx.issue.target, suggestions=ctx.issue.suggestions)
            except Exception:
                downgraded_issue = ctx.issue
            downgraded.append(TrafficIssueContext(issue=downgraded_issue, message=ctx.message, packet_index=ctx.packet_index, hex_preview=ctx.hex_preview, severity=Severity.WARN))
        return downgraded

    def _node_lookup(self, node_id: Any) -> Optional[Dict[str, Any]]:
        if node_id in self.nodes_by_id:
            return self.nodes_by_id[node_id]
        if str(node_id) in self.nodes_by_id:
            return self.nodes_by_id[str(node_id)]
        try:
            as_int = int(node_id)
            if as_int in self.nodes_by_id:
                return self.nodes_by_id[as_int]
        except Exception:
            pass
        return None

    def _is_under_tlv_seq(self, node_id: Any) -> bool:
        current = self._node_lookup(node_id)
        seen: set[str] = set()
        while current is not None:
            parent_id = current.get('parent_id')
            if parent_id is None:
                return False
            key = str(parent_id)
            if key in seen:
                return False
            seen.add(key)
            parent = self._node_lookup(parent_id)
            if parent is None:
                return False
            if str(parent.get('node_type') or '').strip().lower() == 'tlv_seq':
                return True
            current = parent

    def _check_parse_path(self, ctx: RuntimeContext, issues: List[TrafficIssueContext], packet_idx: int, total_bits: int, hex_preview: Optional[str]) -> None:
        root_id = self.protocol_tree.get('root_node_id')
        if root_id is not None and root_id not in ctx.visited_nodes and (str(root_id) not in ctx.visited_nodes):
            logger.debug('Root %s not visited; visited=%s', root_id, ctx.visited_nodes)
            self._record_issue(issues, TrafficIssueContext(issue=self._make_issue(IssueType.SEMANTICS, Severity.ERROR, f'Internal error: root node {root_id} not visited during parse.', root_id, hex_preview=hex_preview, packet_index=packet_idx), message=f'packet #{packet_idx}: root_not_visited', packet_index=packet_idx, hex_preview=hex_preview))
            return
        for selector_id, variants in ctx.active_variants.items():
            if len(variants) > 1 and (not self._is_under_tlv_seq(selector_id)):
                self._record_issue(issues, TrafficIssueContext(issue=self._make_issue(IssueType.SEMANTICS, Severity.ERROR, f'Ambiguous parse path: selector {selector_id} matched multiple variants {variants} for this packet.', selector_id, hex_preview=hex_preview, packet_index=packet_idx), message=f'packet #{packet_idx}: ambiguous_variant', packet_index=packet_idx, hex_preview=hex_preview))
                return
        coverage = self._compute_coverage(ctx, total_bits)
        logger.debug('Coverage result: merged=%s coverage_bits=%s gap_bits=%s tail_leftover_bits=%s', coverage.merged_intervals, coverage.coverage_bits, coverage.gap_bits, coverage.tail_leftover_bits)
        if coverage.tail_leftover_bits > 0:
            leftover_bytes = (coverage.tail_leftover_bits + 7) // 8
            node_id: Optional[Any] = None
            desc: str
            if self.coverage_issue_grouping == 'bytes':
                desc = f'Parsing finished but {leftover_bytes} bytes remain unparsed.'
            else:
                node_id = self._pick_coverage_anchor_node(ctx)
                sig = self._coverage_group_signature(ctx)
                desc = f'Trailing bytes unparsed (coverage_tail_gap) | {sig}'
            self._record_issue(issues, TrafficIssueContext(issue=self._make_issue(IssueType.COVERAGE, Severity.ERROR, desc, node_id, hex_preview=hex_preview, packet_index=packet_idx), message=f'packet #{packet_idx}: coverage_tail_gap leftover_bytes={leftover_bytes} leftover_bits={coverage.tail_leftover_bits}', packet_index=packet_idx, hex_preview=hex_preview, severity=Severity.ERROR))
        elif coverage.gap_bits > 0:
            node_id2: Optional[Any] = None
            desc2: str
            if self.coverage_issue_grouping == 'bytes':
                desc2 = f'Parsing has internal gap of {coverage.gap_bits} bits on visited path.'
            else:
                node_id2 = self._pick_coverage_anchor_node(ctx)
                sig2 = self._coverage_group_signature(ctx)
                desc2 = f'Internal gap on visited path (coverage_internal_gap) | {sig2}'
            self._record_issue(issues, TrafficIssueContext(issue=self._make_issue(IssueType.COVERAGE, Severity.ERROR, desc2, node_id2, hex_preview=hex_preview, packet_index=packet_idx), message=f'packet #{packet_idx}: coverage_internal_gap gap_bits={coverage.gap_bits}', packet_index=packet_idx, hex_preview=hex_preview, severity=Severity.ERROR))

    def _compute_coverage(self, ctx: RuntimeContext, total_bits: int) -> CoverageResult:
        intervals: List[Tuple[int, int]] = []
        spans = getattr(ctx, 'field_spans', None) or []
        if isinstance(spans, list) and spans:
            for span in spans:
                if not isinstance(span, dict):
                    continue
                start = span.get('bit_start')
                size = span.get('wire_size_bits')
                if size is None:
                    size = span.get('content_size_bits')
                try:
                    start_i = int(start)
                    size_i = int(size)
                except Exception:
                    continue
                if size_i <= 0:
                    continue
                intervals.append((start_i, start_i + size_i))
        else:
            consuming_types = {'field', 'selector', 'type', 'length', 'checksum', 'variant', 'payload'}
            for nid in ctx.visited_nodes:
                start = ctx.bit_starts.get(nid)
                size = ctx.actual_sizes.get(nid) if hasattr(ctx, 'actual_sizes') else None
                if size is None:
                    size = ctx.actual_sizes.get(str(nid)) if hasattr(ctx, 'actual_sizes') else None
                if size is None:
                    size = ctx.sizes.get(nid)
                if size is None:
                    size = ctx.sizes.get(str(nid))
                if start is None or size is None or size <= 0:
                    continue
                node = self._node_lookup(nid)
                if node is not None:
                    ntype = str(node.get('node_type') or '').lower()
                    if ntype and ntype not in consuming_types:
                        continue
                intervals.append((start, start + size))
        if not intervals:
            return CoverageResult(merged_intervals=[], coverage_bits=0, gap_bits=total_bits, tail_leftover_bits=total_bits)
        intervals.sort(key=lambda x: x[0])
        merged: List[Tuple[int, int]] = []
        cur_s, cur_e = intervals[0]
        for s, e in intervals[1:]:
            if s <= cur_e:
                cur_e = max(cur_e, e)
            else:
                merged.append((cur_s, cur_e))
                cur_s, cur_e = (s, e)
        merged.append((cur_s, cur_e))
        coverage_bits = sum((e - s for s, e in merged))
        gap_bits = 0
        cursor = 0
        for s, e in merged:
            if s > cursor:
                gap_bits += s - cursor
            cursor = max(cursor, e)
        if cursor < total_bits:
            gap_bits += total_bits - cursor
        max_end = merged[-1][1] if merged else 0
        tail_leftover_bits = total_bits - max_end if max_end < total_bits else 0
        return CoverageResult(merged_intervals=merged, coverage_bits=coverage_bits, gap_bits=gap_bits, tail_leftover_bits=tail_leftover_bits)

    def _record_issue(self, issues: List[TrafficIssueContext], issue_ctx: TrafficIssueContext) -> None:
        target_id = None
        if issue_ctx.issue.target and issue_ctx.issue.target.identifier is not None:
            target_id = str(issue_ctx.issue.target.identifier)
        base_desc = issue_ctx.issue.description
        key = (issue_ctx.issue.type.value, issue_ctx.issue.severity.value, target_id, base_desc)
        entry = self._example_map.get(key)
        if entry is None:
            entry = {'issue': issue_ctx.issue, 'examples': [], 'base_desc': base_desc, 'hit_count': 0, 'representative_ctx': issue_ctx}
            self._example_map[key] = entry
            issues.append(issue_ctx)
        examples = entry['examples']
        if len(examples) < self.max_issue_examples_per_node:
            examples.append((issue_ctx.packet_index, issue_ctx.hex_preview))
        entry['hit_count'] += 1
        summary = '; '.join((f'pkt#{idx} hex={hx}' if hx else f'pkt#{idx}' for idx, hx in examples[:self.max_issue_examples_per_node]))
        new_desc = entry['base_desc']
        if summary:
            new_desc = f"{entry['base_desc']} | examples: {summary}"
        if entry['hit_count'] > len(examples):
            new_desc += f" | total_hits={entry['hit_count']}"
        issue_obj = Issue(id=entry['issue'].id, type=issue_ctx.issue.type, severity=issue_ctx.issue.severity, description=new_desc, target=issue_ctx.issue.target, suggestions=issue_ctx.issue.suggestions)
        entry['issue'] = issue_obj
        rep_ctx: TrafficIssueContext = entry['representative_ctx']
        rep_ctx.issue = issue_obj

    def _issue_from_error(self, error: Any, context: Any, *, packet_index: Optional[int]=None, hex_preview: Optional[str]=None) -> Issue:
        if isinstance(error, NodeParseError):
            msg = str(error)
            issue_type = IssueType.STRUCTURE if error.kind == 'structure' else IssueType.SEMANTICS
            return self._make_issue(issue_type, Severity.ERROR, msg, str(error.node_id), packet_index=packet_index, hex_preview=hex_preview)
        if isinstance(error, RoutingError):
            node_raw = getattr(error, 'node_id', None)
            node_id = str(node_raw) if node_raw is not None else None
            selector_id = self._coerce_int(getattr(error, 'selector_id', None))
            candidate_variants: List[int] = []
            for raw in getattr(error, 'candidate_variants', None) or []:
                coerced = self._coerce_int(raw)
                if coerced is None:
                    continue
                candidate_variants.append(int(coerced))
            prefix_len = max(1, int(os.getenv('STEP2_TRAFFIC_ROUTING_ISSUE_PATH_PREFIX_LEN', '8')))
            path_prefix: List[int] = []
            if context and getattr(context, 'parsing_path', None):
                for nid in (context.parsing_path or [])[:prefix_len]:
                    try:
                        path_prefix.append(int(nid))
                    except Exception:
                        continue
            parts = [f'Routing failed: {error}']
            if selector_id is not None:
                parts.append(f'selector={selector_id}')
            if candidate_variants:
                parts.append(f'candidates={candidate_variants}')
            if path_prefix:
                parts.append(f'path_prefix={path_prefix}')
            desc = ' | '.join(parts)
            return self._make_issue(IssueType.STRUCTURE, Severity.ERROR, desc, node_id, packet_index=packet_index, hex_preview=hex_preview)

        def _format_path(ctx: Any) -> str:
            if not ctx or not getattr(ctx, 'parsing_path', None):
                return '-'
            names = []
            for nid in ctx.parsing_path:
                n_obj = self.nodes_by_id.get(nid) or self.nodes_by_id.get(str(nid), {}) or {}
                names.append(f"{n_obj.get('name', nid)}({nid})")
            return '->'.join(names)

        def _append_context(desc: str, *, node_id: Optional[str], kind: str) -> str:
            path_str = _format_path(context)
            selector_id = self.selector_for_dst.get(node_id) or self.selector_for_dst.get(str(node_id)) if node_id else None
            selector_txt = f' selector={selector_id}' if selector_id is not None else ''
            variants_txt = ''
            if context and getattr(context, 'active_variants', None):
                variants_txt = f' active_variants={context.active_variants}'
            return f"{desc} | packet={packet_index} node={node_id or 'unknown'} failure_kind={kind} path={path_str}{selector_txt}{variants_txt}"
        msg = str(error) if error is not None else 'Unknown parsing error'
        node_id: Optional[str] = None
        constraint_expr: Optional[str] = None
        value: Optional[str] = None
        if isinstance(error, LengthMismatchError):
            try:
                node_id = str(error.node_id) if error.node_id is not None else None
            except Exception:
                node_id = None
            first_detail = None
            if getattr(error, 'mismatches', None):
                first_detail = error.mismatches[0]
                if node_id is None:
                    try:
                        node_id = str(first_detail.dst)
                    except Exception:
                        node_id = None
            expected_bits = None
            actual_bits = None
            if first_detail is not None:
                expected_bits = getattr(first_detail, 'expected_bits', None)
                actual_bits = getattr(first_detail, 'actual_bits', None)
            desc = f'Length field mismatch: {msg}'
            desc = _append_context(desc, node_id=node_id, kind='length_mismatch')
            if expected_bits is not None and actual_bits is not None:
                desc += f' expected={expected_bits} actual={actual_bits}'
            return self._make_issue(IssueType.SEMANTICS, Severity.ERROR, desc, node_id, packet_index=packet_index, hex_preview=hex_preview)
        if 'Container overflow' in msg:
            m = re.search('node\\s+([\\w-]+)', msg)
            if m:
                node_id = m.group(1)
            desc = f'Container overflow detected: {msg}'
            desc = _append_context(desc, node_id=node_id, kind='overflow')
            return self._make_issue(IssueType.SEMANTICS, Severity.ERROR, desc, node_id, packet_index=packet_index, hex_preview=hex_preview)
        if isinstance(error, ConstraintViolationError):
            node_id = str(getattr(error, 'node_id', None)) if getattr(error, 'node_id', None) is not None else None
            constraint_expr = getattr(error, 'constraint_text', '') or ''
            value = getattr(error, 'value', None)
        else:
            m = re.search('Constraint violation at node ([\\w-]+):\\s*(.*)\\(value=([^)]*)\\)', msg)
            if m:
                node_id = m.group(1)
                constraint_expr = m.group(2).strip()
                value = m.group(3).strip()
        if node_id and constraint_expr is not None and (value is not None):
            desc = f'Constraint failed for node {node_id}: value {value} violated {constraint_expr}. Tree definition may not match traffic.'
            desc = _append_context(desc, node_id=node_id, kind='constraint_violation')
            return self._make_issue(IssueType.SEMANTICS, Severity.ERROR, desc, node_id, packet_index=packet_index, hex_preview=hex_preview)
        if 'Not enough bits' in msg or 'IncompleteStream' in msg or 'Stream ended' in msg:
            node_match = re.search('node ([\\w-]+)', msg)
            if node_match:
                node_id = node_match.group(1)
            elif context.parsing_path:
                node_id = str(context.parsing_path[-1])
            desc = f"Parsing blocked at node {node_id or 'unknown'}: Stream ended unexpectedly. Check size_bits logic."
            desc = _append_context(desc, node_id=node_id, kind='oob_seek')
            return self._make_issue(IssueType.SEMANTICS, Severity.ERROR, desc, node_id, packet_index=packet_index, hex_preview=hex_preview)
        if 'Incomplete parse' in msg or 'remain unconsumed' in msg:
            bits_left: Optional[str] = None
            m_bits = re.search('(\\d+)\\s+bits\\s+remain\\s+unconsumed', msg)
            if m_bits:
                bits_left = m_bits.group(1)
            anchor_id = None
            if context and getattr(context, 'parsing_path', None):
                anchor_id = str(context.parsing_path[-1])
            desc = f"Parser finished at node {anchor_id or 'unknown'}{(f' but {bits_left} bits remain' if bits_left else ' with unconsumed trailer')}. This implies the tree covers the beginning but not the tail. Check payload nodes for missing variants or size_bits."
            desc = _append_context(desc, node_id=anchor_id, kind='trailer')
            return self._make_issue(IssueType.SEMANTICS, Severity.ERROR, desc, None, packet_index=packet_index, hex_preview=hex_preview)
        if context.parsing_path:
            node_id = str(context.parsing_path[-1])
        desc = f"Parsing failed near node {node_id or 'unknown'}: {msg}"
        desc = _append_context(desc, node_id=node_id, kind='unknown')
        return self._make_issue(IssueType.SEMANTICS, Severity.ERROR, desc, node_id, packet_index=packet_index, hex_preview=hex_preview)

    def _make_issue(self, issue_type: IssueType, severity: Severity, description: str, node_id: Optional[str], *, packet_index: Optional[int]=None, hex_preview: Optional[str]=None) -> Issue:
        target = TargetRef('node', str(node_id)) if node_id is not None else None
        digest = hashlib.sha1(description.encode('utf-8')).hexdigest()[:8]
        issue_id = f"traffic_{issue_type.value.lower()}_{severity.value.lower()}_{node_id or 'global'}_{digest}"
        return Issue(id=issue_id, type=issue_type, severity=severity, description=description, target=target)

def _load_packets_from_path(path: Path, max_packets: int=0) -> List[bytes]:
    payloads = []
    with path.open('r', encoding='utf-8') as handle:
        for line in handle:
            if max_packets and len(payloads) >= max_packets:
                break
            hex_str = line.strip()
            if not hex_str:
                continue
            try:
                payloads.append(bytes.fromhex(hex_str))
            except ValueError:
                continue
    return payloads

def _has_fatal_structure_error(report: ValidationReport) -> bool:
    for issue in report.issues.values():
        if issue.type == IssueType.STRUCTURE and issue.severity == Severity.ERROR:
            return True
    return False

def run_hybrid_validation(tree: Dict[str, Any], traffic_path: Path, max_packets: int=5, target_message_type: Optional[str]=None) -> ValidationReport:
    try:
        serialized = json.dumps(tree, ensure_ascii=False)
    except TypeError:
        serialized = json.dumps({'protocol_tree': tree}, ensure_ascii=False)
    static_report = validate_protocol_tree(serialized)
    if _has_fatal_structure_error(static_report):
        return static_report
    try:
        packets = _load_packets_from_path(Path(traffic_path), max_packets=max_packets)
    except Exception as exc:
        errors = list(static_report.errors)
        errors.append(str(exc))
        warnings = list(getattr(static_report, 'warnings', []))
        extras = list(static_report.extras) if static_report.extras else []
        extras.append(f'Failed to load traffic from {traffic_path}: {exc}')
        return ValidationReport(ok=False, errors=errors, warnings=warnings, extras=extras, issues=dict(static_report.issues))
    if not packets:
        extras = list(static_report.extras) if static_report.extras else []
        extras.append(f'No packets loaded from {traffic_path}')
        return ValidationReport(ok=False, errors=list(static_report.errors) + [f'No packets loaded from {traffic_path}'], warnings=list(getattr(static_report, 'warnings', [])), extras=extras, issues=dict(static_report.issues))
    traffic_validator = SemanticValidator(tree, max_packets=max_packets, target_message_type=target_message_type)
    dynamic_issues, dynamic_extras, traffic_failures, traffic_stats = traffic_validator.validate_packets(packets)
    merged_issues = dict(static_report.issues)
    for ctx in dynamic_issues:
        merged_issues[ctx.issue.id] = ctx.issue
    ok = static_report.ok and len(dynamic_issues) == 0
    errors = list(static_report.errors)
    warnings = list(getattr(static_report, 'warnings', []))
    if dynamic_issues:
        errors.extend([ctx.message for ctx in dynamic_issues])
    extras = list(static_report.extras) if static_report.extras else []
    extras.extend(dynamic_extras)
    if target_message_type:
        extras.append(f'traffic_target_message_type={target_message_type}')
    return ValidationReport(ok=ok, errors=errors, warnings=warnings, extras=extras, issues=merged_issues, traffic_failures=traffic_failures, traffic_repair_hints=list(traffic_stats.get('repair_hints', []) or []))

def _serialize_value(value: Any, seen: set[int]) -> Any:
    if isinstance(value, (int, float, bool, str)) or value is None:
        return value
    if isinstance(value, bytes):
        return value.hex()
    obj_id = id(value)
    if obj_id in seen:
        return repr(value)
    if isinstance(value, dict):
        seen.add(obj_id)
        return {str(k): _serialize_value(v, seen) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        seen.add(obj_id)
        return [_serialize_value(v, seen) for v in value]
    return repr(value)

def _serialize_value_with_type(value: Any, data_type: str, size_bits: Optional[int]) -> Any:
    dt = (data_type or '').lower()
    numeric_keywords = ('int', 'uint', 'sint', 'float', 'double', 'enum')
    if any((kw in dt for kw in numeric_keywords)):
        if isinstance(value, (int, float)) and (not isinstance(value, bool)):
            return value
        if isinstance(value, (bytes, bytearray)):
            try:
                return int.from_bytes(bytes(value), 'big', signed=False)
            except Exception:
                return _serialize_value(value, set())
        return _serialize_value(value, set())
    if dt in {'string', 'ascii', 'utf8', 'utf-8'}:
        if isinstance(value, str):
            return value
        if isinstance(value, (bytes, bytearray)):
            try:
                return bytes(value).decode('utf-8', errors='replace')
            except Exception:
                return bytes(value).decode('latin1', errors='replace')
        if isinstance(value, int) and size_bits is not None and (size_bits > 0):
            nbytes = (size_bits + 7) // 8
            try:
                raw_bytes = value.to_bytes(nbytes, 'big', signed=False)
                return raw_bytes.decode('utf-8', errors='replace')
            except Exception:
                return '0x' + value.to_bytes(nbytes, 'big', signed=False).hex()
        return _serialize_value(value, set())
    if isinstance(value, (bytes, bytearray)):
        return '0x' + bytes(value).hex()
    if isinstance(value, int) and size_bits is not None and (size_bits > 0):
        nbytes = (size_bits + 7) // 8
        try:
            raw_bytes = value.to_bytes(nbytes, 'big', signed=False)
            return '0x' + raw_bytes.hex()
        except OverflowError:
            return f'0x{value:x}'
    if isinstance(value, str):
        hex_str = value.strip()
        if hex_str and all((c in '0123456789abcdefABCDEF' for c in hex_str)):
            return '0x' + hex_str
        return value
    return _serialize_value(value, set())

def _build_trace_layout(ctx: RuntimeContext, nodes_by_id: Dict[Any, Dict[str, Any]], values: Dict[str, Any], typed_values: Dict[str, Any], bit_starts: Dict[str, int], sizes: Dict[str, int]) -> Optional[Dict[str, Any]]:
    if not ctx.visit_log:
        return None
    layout_nodes: Dict[str, Dict[str, Any]] = {}
    parents: Dict[str, Optional[str]] = {}
    for nid, parent in ctx.visit_log:
        nid_str = str(nid)
        parent_str = str(parent) if parent is not None else None
        parents[nid_str] = parent_str
        node_meta = nodes_by_id.get(nid) or nodes_by_id.get(nid_str) or {}
        name = node_meta.get('name', nid_str)
        node_type = node_meta.get('node_type')
        data_type = node_meta.get('data_type')
        start_bit = bit_starts.get(nid_str)
        size_bits = sizes.get(nid_str)
        value_raw = values.get(nid_str)
        value_typed = typed_values.get(nid_str)
        byte_start: Optional[int] = None
        byte_end: Optional[int] = None
        if start_bit is not None and size_bits is not None:
            try:
                byte_start = start_bit // 8
                byte_end = (start_bit + size_bits + 7) // 8
            except Exception:
                byte_start = None
                byte_end = None
        summary = name
        if value_typed is not None and isinstance(value_typed, (int, float, str)):
            if isinstance(value_typed, int):
                summary = f'{name} = {value_typed} (0x{value_typed:x})'
            else:
                summary = f'{name} = {value_typed}'
        elif size_bits is not None:
            summary = f'{name} ({size_bits} bits)'
        layout_nodes[nid_str] = {'id': nid_str, 'name': name, 'node_type': node_type, 'data_type': data_type, 'bit_start': start_bit, 'size_bits': size_bits, 'byte_start': byte_start, 'byte_end': byte_end, 'value_raw': value_raw, 'value_typed': value_typed, 'summary': summary, 'children': []}
    roots: List[Dict[str, Any]] = []
    for nid_str, parent_str in parents.items():
        node = layout_nodes.get(nid_str)
        if node is None:
            continue
        if parent_str is None or parent_str not in layout_nodes:
            roots.append(node)
        else:
            layout_nodes[parent_str]['children'].append(node)
    if not roots:
        return None
    if len(roots) == 1:
        return roots[0]
    return {'id': '__multi_root__', 'name': 'Root', 'node_type': 'virtual_root', 'data_type': None, 'bit_start': None, 'size_bits': None, 'byte_start': None, 'byte_end': None, 'value_raw': None, 'value_typed': None, 'summary': 'Multiple roots', 'children': roots}

def _ctx_to_record(packet_index: int, payload: bytes, success: bool, ctx: Optional[RuntimeContext], error: Any, nodes_by_id: Optional[Dict[Any, Dict[str, Any]]]=None) -> Dict[str, Any]:
    error_str: Optional[str] = str(error) if error is not None else None
    visited_nodes: List[str] = [str(nid) for nid in ctx.visited_nodes] if ctx else []
    parsing_path: List[str] = [str(nid) for nid in ctx.parsing_path] if ctx else []
    visit_log: List[List[Optional[str]]] = []
    if ctx:
        visit_log = [[str(n), str(parent) if parent is not None else None] for n, parent in ctx.visit_log]
    active_variants: Dict[str, List[str]] = {}
    if ctx:
        active_variants = {str(sel): [str(v) for v in variants] for sel, variants in ctx.active_variants.items()}
    values: Dict[str, Any] = {}
    if ctx:
        seen: set[int] = set()
        values = {str(k): _serialize_value(v, seen) for k, v in ctx.values.items()}
    bit_starts: Dict[str, int] = {}
    sizes: Dict[str, int] = {}
    if ctx:
        bit_starts = {str(k): int(v) for k, v in ctx.bit_starts.items() if v is not None}
        sizes = {str(k): int(v) for k, v in ctx.sizes.items() if v is not None}
    typed_values: Dict[str, Any] = {}
    if ctx and nodes_by_id:
        sizes_str: Dict[str, int] = {str(k): int(v) for k, v in ctx.sizes.items() if v is not None}
        for nid, raw_val in ctx.values.items():
            nid_str = str(nid)
            node = nodes_by_id.get(nid) or nodes_by_id.get(nid_str)
            data_type = ''
            if isinstance(node, dict):
                data_type = str(node.get('data_type') or '')
            size_bits = sizes_str.get(nid_str)
            typed_values[nid_str] = _serialize_value_with_type(raw_val, data_type, size_bits)
    elif ctx:
        typed_values = dict(values)
    return {'packet_index': packet_index, 'success': success, 'error': error_str, 'raw_hex': payload.hex(), 'visited_nodes': visited_nodes, 'parsing_path': parsing_path, 'visit_log': visit_log, 'active_variants': active_variants, 'values': values, 'typed_values': typed_values, 'bit_starts': bit_starts, 'sizes': sizes}

def export_parsing_traces(tree: Dict[str, Any], traffic_path: Path, output_path: Path, max_packets: int=0, *, payloads: Optional[Iterable[bytes]]=None) -> Path:
    packets = list(payloads) if payloads is not None else _load_packets_from_path(Path(traffic_path), max_packets)
    interpreter = DynamicTreeInterpreter(tree, target_message_type=None)
    nodes_by_id: Dict[Any, Dict[str, Any]] = {}
    if isinstance(tree, dict):
        nodes = tree.get('nodes', [])
        if isinstance(nodes, list):
            for n in nodes:
                if not isinstance(n, dict):
                    continue
                nid = n.get('node_id')
                if nid is None:
                    continue
                nodes_by_id[nid] = n
                nodes_by_id[str(nid)] = n
    output_path.parent.mkdir(parents=True, exist_ok=True)
    layout_records: List[Dict[str, Any]] = []
    with output_path.open('w', encoding='utf-8') as handle:
        for idx, payload in enumerate(packets):
            try:
                success, ctx, error = interpreter.parse(payload)
            except RoutingError as exc:
                success, ctx, error = (False, None, f'RoutingError: {exc}')
            except Exception as exc:
                success, ctx, error = (False, None, f'InterpreterCrash: {exc}')
            record = _ctx_to_record(idx, payload, success, ctx, error, nodes_by_id=nodes_by_id)
            handle.write(json.dumps(record, ensure_ascii=False))
            handle.write('\n')
            layout = None
            if ctx is not None and nodes_by_id:
                layout = _build_trace_layout(ctx=ctx, nodes_by_id=nodes_by_id, values=record.get('values', {}), typed_values=record.get('typed_values', {}), bit_starts=record.get('bit_starts', {}), sizes=record.get('sizes', {}))
            layout_records.append({'packet_index': idx, 'trace_layout': layout})
    layout_path = output_path.with_name('trace_layout.json')
    layout_path.write_text(json.dumps(layout_records, ensure_ascii=False, indent=2), encoding='utf-8')
    return output_path
