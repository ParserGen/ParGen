import copy
import logging
import os
import struct
import math
import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union, Tuple, Set
import re
logger = logging.getLogger(__name__)
LEAF_TYPES = {'field', 'selector', 'type', 'length', 'checksum'}

@dataclass
class ConstraintViolationError(Exception):
    node_id: int
    constraint_text: str
    value: Any
    kind: str = 'expr'

    def __post_init__(self) -> None:
        super().__init__(str(self))

    def __str__(self) -> str:
        return f'Constraint violation at node {self.node_id}: {self.constraint_text} (value={self.value})'

class IncompleteStreamError(Exception):

    def __init__(self, message: str, *, bit_pos: Optional[int]=None, total_bits: Optional[int]=None, bits_needed: Optional[int]=None, bits_remaining: Optional[int]=None) -> None:
        super().__init__(message)
        self.bit_pos = bit_pos
        self.total_bits = total_bits
        self.bits_needed = bits_needed
        self.bits_remaining = bits_remaining

class UnresolvedReferenceError(Exception):
    pass

class NodeParseError(Exception):

    def __init__(self, node_id: int, message: str, *, kind: str='structure', cause: Optional[Exception]=None):
        super().__init__(message)
        self.node_id = node_id
        self.kind = kind
        self.cause = cause

class RoutingError(Exception):

    def __init__(self, node_id: int, message: str, variant_errors: Optional[List[Any]]=None, *, selector_id: Optional[int]=None, candidate_variants: Optional[List[int]]=None):
        super().__init__(message)
        self.node_id = node_id
        self.variant_errors = variant_errors or []
        self.selector_id = selector_id
        self.candidate_variants = candidate_variants or []

@dataclass
class NodeSizeInfo:
    has_declared_size: bool
    declared_size_bits: Optional[int]

@dataclass
class LengthMismatchDetail:
    src: int
    dst: int
    expected_bits: int
    actual_bits: int
    content_bits: Optional[int] = None
    wire_bits: Optional[int] = None
    mismatch_kind: str = 'wire_mismatch'
    formula: Optional[str] = None
    message_type: Optional[str] = None

class LengthMismatchError(Exception):

    def __init__(self, mismatches: List[LengthMismatchDetail]):
        self.mismatches = mismatches
        super().__init__(str(self))

    @property
    def node_id(self) -> Optional[int]:
        if not self.mismatches:
            return None
        return self.mismatches[0].dst

    def __str__(self) -> str:
        if not self.mismatches:
            return 'Length mismatch'
        if len(self.mismatches) == 1:
            m = self.mismatches[0]
            return f'Length mismatch at edge {m.src}->{m.dst}: expected {m.expected_bits} bits, actual {m.actual_bits} bits'
        parts = [f'edge {m.src}->{m.dst}: expected {m.expected_bits} bits, actual {m.actual_bits} bits' for m in self.mismatches]
        return 'Length mismatches: ' + '; '.join(parts)

def _coerce_node_id(raw: Any) -> Union[int, Any]:
    try:
        return int(raw)
    except (TypeError, ValueError):
        return raw

@dataclass
class RuntimeContext:
    values: Dict[Union[str, int], Any] = field(default_factory=dict)
    bit_starts: Dict[Union[str, int], int] = field(default_factory=dict)
    sizes: Dict[Union[str, int], int] = field(default_factory=dict)
    actual_sizes: Dict[Union[str, int], int] = field(default_factory=dict)
    wire_sizes: Dict[Union[str, int], int] = field(default_factory=dict)
    field_spans: List[Dict[str, Any]] = field(default_factory=list)
    length_gaps: List['LengthMismatchDetail'] = field(default_factory=list)
    parsing_path: List[Union[str, int]] = field(default_factory=list)
    visited_nodes: Set[Union[str, int]] = field(default_factory=set)
    parent_on_path: Dict[Union[str, int], Optional[Union[str, int]]] = field(default_factory=dict)
    visit_log: List[Tuple[Union[str, int], Optional[Union[str, int]]]] = field(default_factory=list)
    active_variants: Dict[Union[str, int], List[Union[str, int]]] = field(default_factory=dict)
    variant_trial_errors: List[Dict[str, Any]] = field(default_factory=list)

    def get_value(self, node_id: Union[str, int]) -> Any:
        return self.values.get(node_id)

class BitStream:

    def __init__(self, data: bytes):
        self.data = data
        self.total_bits = len(data) * 8
        self.cursor = 0

    def seek(self, bit_pos: int):
        if bit_pos < 0 or bit_pos > self.total_bits:
            raise IncompleteStreamError(f'Stream ended while seeking: invalid position {bit_pos}, total_bits={self.total_bits}', bit_pos=bit_pos, total_bits=self.total_bits)
        self.cursor = bit_pos

    def read_bits(self, count: int) -> int:
        if count == 0:
            return 0
        if self.cursor + count > self.total_bits:
            raise IncompleteStreamError(f'Not enough bits: need {count}, have {self.total_bits - self.cursor}', bits_needed=count, bits_remaining=self.total_bits - self.cursor, total_bits=self.total_bits)
        value = 0
        for _ in range(count):
            byte_idx = self.cursor // 8
            bit_idx = 7 - self.cursor % 8
            bit = self.data[byte_idx] >> bit_idx & 1
            value = value << 1 | bit
            self.cursor += 1
        return value

    def read_bytes(self, count: int) -> bytes:
        if self.cursor % 8 != 0:
            pass
        if self.cursor % 8 == 0:
            byte_start = self.cursor // 8
            if byte_start + count > len(self.data):
                raise IncompleteStreamError(f'Not enough bytes: need {count}, have {len(self.data) - byte_start}', bits_needed=count * 8, bits_remaining=(len(self.data) - byte_start) * 8, total_bits=self.total_bits)
            self.cursor += count * 8
            return self.data[byte_start:byte_start + count]
        val = self.read_bits(count * 8)
        return val.to_bytes(count, 'big')

class ExpressionEvaluator:
    _ALLOWED_FUNCS = {'min': min, 'max': max, 'abs': abs, 'ceil': math.ceil}

    def __init__(self, context: RuntimeContext):
        self.context = context

    @staticmethod
    def _coerce_node_id(raw: str) -> Union[str, int]:
        return int(raw) if raw.lstrip('-').isdigit() else raw

    def evaluate(self, expr: Union[str, int, float], current_node_id: Optional[Union[str, int]]=None, current_value: Optional[Any]=None) -> Any:
        if isinstance(expr, (int, float)):
            return expr
        if not isinstance(expr, str):
            return expr
        raw_expr = expr
        expr = expr.replace('\uFF1A', ':').replace('\u2264', '<=').replace('\u2265', '>=').replace('\u2260', '!=').replace('\xa0', ' ').replace('\u202f', ' ').replace('\u200b', '').replace('\u200c', '').replace('\u200d', '').replace('\ufeff', '').replace('\u2060', '').strip()
        expr = re.sub('!\\s*=', '!=', expr)
        if not expr:
            return 0
        lower_expr = expr.lower()
        if lower_expr.startswith('formula:'):
            expr_body = expr.split(':', 1)[1].strip()
            expr_body = re.sub('(?<![<>=!])=(?!=)', '==', expr_body, count=1)
            expr = expr_body

        def unresolved(message: str) -> UnresolvedReferenceError:
            prefix = f'while evaluating node {current_node_id}: ' if current_node_id is not None else ''
            return UnresolvedReferenceError(prefix + message)

        def replace_val(match):
            nid = self._coerce_node_id(match.group(1))
            val = self.context.get_value(nid)
            if val is None:
                raise unresolved(f'reference to unparsed node val({nid})')
            return repr(val)
        parsed_expr = re.sub('val\\(([\\w-]+)\\)', replace_val, expr)

        def replace_attr(match):
            nid = self._coerce_node_id(match.group(1))
            attr = match.group(2)
            if attr == 'bit_start':
                val = self.context.bit_starts.get(nid)
            elif attr == 'size_bits':
                val = self.context.sizes.get(nid)
            else:
                val = None
            if val is None:
                raise unresolved(f'reference to unknown attribute {nid}.{attr}')
            return repr(val)
        parsed_expr = re.sub('([\\w-]+)\\.(bit_start|size_bits)', replace_attr, parsed_expr)
        parsed_expr = parsed_expr.replace('root.bit_start', '0')
        if current_value is not None:
            parsed_expr = re.sub('\\bvalue\\b', repr(current_value), parsed_expr)
        parsed_expr = parsed_expr.replace('&&', ' and ').replace('||', ' or ')
        parsed_expr = re.sub('!(?!=)', ' not ', parsed_expr)
        try:
            parsed_ast = ast.parse(parsed_expr, mode='eval')
            for node in ast.walk(parsed_ast):
                if isinstance(node, ast.Call):
                    if not isinstance(node.func, ast.Name) or node.func.id not in self._ALLOWED_FUNCS:
                        raise ValueError('Invalid expression: unexpected function call. This usually indicates a missing boolean operator between clauses (use `and`/`or`).')
            return eval(parsed_expr, {'__builtins__': None}, self._ALLOWED_FUNCS)
        except Exception as e:
            logger.error('Failed to evaluate expression. Details:\n  Original expression: %s\n  Parsed expression: %s\n  Node ID: %s\n  Exception type: %s\n  Exception message: %s\n  Available values in context: %s\n  Available bit_starts: %s\n  Available sizes: %s', raw_expr, parsed_expr, current_node_id, type(e).__name__, str(e), dict(self.context.values), dict(self.context.bit_starts), dict(self.context.sizes))
            raise ValueError(f"Failed to evaluate expression '{expr}' (parsed: '{parsed_expr}') for node {current_node_id}: {e}")

class DynamicTreeInterpreter:

    def __init__(self, protocol_tree: Dict[str, Any], target_message_type: Optional[str]=None):
        self.tree = protocol_tree
        self.nodes: Dict[Union[str, int], Dict[str, Any]] = {}
        for n in self.tree.get('nodes', []):
            raw_id = n.get('node_id')
            if raw_id is None:
                continue
            self.nodes[raw_id] = n
            coerced = _coerce_node_id(raw_id)
            self.nodes[coerced] = n
        root_raw = self.tree.get('root_node_id')
        try:
            self.root_id = _coerce_node_id(root_raw)
        except Exception:
            self.root_id = root_raw
        self.target_message_type = (target_message_type or '').lower() or None
        self._log_node_overflow = os.getenv('STEP2_TRAFFIC_LOG_NODE_OVERFLOW', '0').strip().lower() in {'1', 'true', 'yes', 'y', 'on'}
        self._node_overflow_warned: Set[Tuple[int, int]] = set()
        self.edges = self.tree.get('edges', [])
        self.condition_edges = {}
        for e in self.edges:
            if e.get('rel') == 'condition_on':
                src = _coerce_node_id(e.get('src'))
                if src not in self.condition_edges:
                    self.condition_edges[src] = []
                self.condition_edges[src].append(e)

    def parse(self, data: bytes) -> Tuple[bool, Optional[RuntimeContext], Optional[Any]]:
        stream = BitStream(data)
        context = RuntimeContext()
        evaluator = ExpressionEvaluator(context)
        try:
            self._parse_node(self.root_id, stream, context, evaluator, parent_id=None)
            remaining = stream.total_bits - stream.cursor
            if remaining > 0:
                return (False, context, f'Incomplete parse: {remaining} bits remain unconsumed at end of stream. This usually indicates missing payload fields/variants or incorrect size_bits.')
            mismatches = self._validate_length_edges(context, evaluator)
            if mismatches:
                return (False, context, LengthMismatchError(mismatches))
            return (True, context, None)
        except RoutingError as e:
            logger.debug('Routing failed at node %s: %s', getattr(e, 'node_id', '?'), e)
            return (False, context, e)
        except NodeParseError as e:
            if os.getenv('STEP2_TRAFFIC_LOG_PARSE_WARNINGS', '0').strip().lower() in {'1', 'true', 'yes', 'y', 'on'}:
                logger.warning('Parsing failed at node %s: %s', e.node_id, e)
            else:
                logger.debug('Parsing failed at node %s: %s', e.node_id, e)
            return (False, context, e)
        except ConstraintViolationError as e:
            node_id = getattr(e, 'node_id', '?')
            if os.getenv('STEP2_TRAFFIC_LOG_PARSE_WARNINGS', '0').strip().lower() in {'1', 'true', 'yes', 'y', 'on'}:
                logger.warning('Constraint violation at node %s: %s', node_id, e)
            else:
                logger.debug('Constraint violation at node %s: %s', node_id, e)
            return (False, context, e)
        except LengthMismatchError as e:
            if os.getenv('STEP2_TRAFFIC_LOG_PARSE_WARNINGS', '0').strip().lower() in {'1', 'true', 'yes', 'y', 'on'}:
                logger.warning('Length mismatch: %s', e)
            else:
                logger.debug('Length mismatch: %s', e)
            return (False, context, e)
        except Exception as e:
            if os.getenv('STEP2_TRAFFIC_LOG_PARSE_WARNINGS', '0').strip().lower() in {'1', 'true', 'yes', 'y', 'on'}:
                logger.warning('Parsing failed: %s', e)
            else:
                logger.debug('Parsing failed: %s', e)
            return (False, context, str(e))

    def _parse_node(self, node_id: Union[str, int], stream: BitStream, context: RuntimeContext, evaluator: ExpressionEvaluator, parent_id: Optional[Union[str, int]]=None, *, force_current_bit_start: bool=False):
        node_id = _coerce_node_id(node_id)
        parent_id = _coerce_node_id(parent_id) if parent_id is not None else None
        node = self.nodes.get(node_id)
        if not node:
            raise ValueError(f'Node {node_id} not found')
        context.visited_nodes.add(node_id)
        context.parent_on_path[node_id] = parent_id
        context.visit_log.append((node_id, parent_id))
        logger.debug('Enter node %s (parent=%s)', node_id, parent_id)
        node_type = str(node.get('node_type', 'field')).lower()
        is_leaf = node_type in LEAF_TYPES
        bit_start_expr = node.get('bit_start')
        if force_current_bit_start:
            context.bit_starts[node_id] = stream.cursor
        elif bit_start_expr is not None:
            try:
                calc_start = int(evaluator.evaluate(bit_start_expr, node_id))
                if calc_start != stream.cursor:
                    try:
                        stream.seek(calc_start)
                    except IncompleteStreamError as exc:
                        raise NodeParseError(node_id, f'bit_start expression leads to seek past end of packet (node={node_id}, bit_pos={calc_start}, total_bits={stream.total_bits})', kind='structure', cause=exc) from exc
                context.bit_starts[node_id] = calc_start
                logger.debug('Node %s bit_start=%s (cursor now %s)', node_id, calc_start, stream.cursor)
            except NodeParseError:
                raise
            except Exception as exc:
                raise NodeParseError(node_id, f'Error calculating bit_start for node {node_id}: {exc}', kind='structure', cause=exc) from exc
        else:
            context.bit_starts[node_id] = stream.cursor
        node_start_cursor = stream.cursor
        consumed_before_padding = 0
        size_expr = node.get('size_bits')
        size_bits = 0
        size_info = self._compute_declared_size_bits(node_id, parent_id, stream, context, evaluator)
        if size_info.has_declared_size and size_info.declared_size_bits is not None:
            if size_info.declared_size_bits < 0:
                raise NodeParseError(node_id, f'invalid size_bits expression: evaluated to negative {size_info.declared_size_bits} for node {node_id}', kind='structure')
            size_bits = size_info.declared_size_bits
            context.sizes[node_id] = size_bits
            logger.debug('Node %s declared size_bits=%s', node_id, size_bits)
        else:
            context.sizes[node_id] = size_bits
        node_type = node.get('node_type', 'field')
        val_int = None
        if node_type in ['field', 'selector', 'type', 'length', 'checksum']:
            if size_bits > 0:
                remaining = stream.total_bits - stream.cursor
                if size_bits > remaining:
                    raise NodeParseError(node_id, f'size_bits expression leads to read past end of packet (node={node_id}, bits_needed={size_bits}, bits_remaining={remaining})', kind='structure', cause=IncompleteStreamError(f'Not enough bits for node {node_id}: need {size_bits}, have {remaining}'))
                val_int = stream.read_bits(size_bits)
                context.values[node_id] = val_int
                logger.debug('Node %s value=%s (size_bits=%s)', node_id, val_int, size_bits)
            else:
                context.values[node_id] = 0
                val_int = 0
        constraints = node.get('constraints', [])
        if constraints and val_int is not None:
            for constraint in constraints:
                if not constraint:
                    continue
                constraint_str = constraint.strip() if isinstance(constraint, str) else constraint
                try:
                    if isinstance(constraint_str, str):
                        normalized_cs = constraint_str.replace('\uFF1A', ':').replace('\u2264', '<=').replace('\u2265', '>=').replace('\xa0', ' ')
                        lower = normalized_cs.lower()
                        if lower.startswith('enum:'):
                            enum_part = normalized_cs.split(':', 1)[1]
                            allowed = []
                            for token in enum_part.replace(',', '|').split('|'):
                                token = token.strip()
                                if not token:
                                    continue
                                try:
                                    allowed.append(int(token, 0))
                                except ValueError:
                                    continue
                            if not allowed:
                                raise ValueError(f'Malformed enum constraint for node {node_id}: {constraint}')
                            if val_int not in allowed:
                                raise ConstraintViolationError(node_id=node_id, constraint_text=f'enum {allowed}', value=val_int, kind='enum')
                            continue
                        if lower.startswith('range:'):
                            import re as _re
                            nums = []
                            for m in _re.finditer('-?\\d+', normalized_cs):
                                try:
                                    nums.append(int(m.group(0), 0))
                                except Exception:
                                    continue
                            if len(nums) < 2:
                                raise ValueError(f'Malformed range constraint for node {node_id}: {constraint}')
                            lo, hi = (nums[0], nums[1])
                            target_kind = 'value'
                            target_val = val_int
                            if _re.search('\\bsize_bits\\b', lower):
                                target_kind = 'size_bits'
                                target_val = context.sizes.get(node_id)
                            elif _re.search('\\bbit_start\\b', lower):
                                target_kind = 'bit_start'
                                target_val = context.bit_starts.get(node_id)
                            if target_val is None:
                                raise ValueError(f'Malformed range constraint for node {node_id}: {constraint} (missing {target_kind})')
                            if not lo <= int(target_val) <= hi:
                                raise ConstraintViolationError(node_id=node_id, constraint_text=f'range {lo}..{hi} ({target_kind})', value=target_val, kind='range')
                            continue
                    result = evaluator.evaluate(constraint_str, node_id, current_value=val_int)
                except ConstraintViolationError:
                    raise
                except Exception as e:
                    raise ValueError(f"Error evaluating constraint '{constraint}' for node {node_id}: {e}")
                if not result:
                    raise ConstraintViolationError(node_id=node_id, constraint_text=str(constraint), value=val_int, kind='expr')
                logger.debug('Node %s constraint ok: %s (value=%s)', node_id, constraint, val_int)
        context.parsing_path.append(node_id)
        children_ids = node.get('children_ids', [])
        node_type_lower = str(node_type).lower() if node_type is not None else ''
        if node_type_lower == 'tlv_seq':
            stop_formula = node.get('stop_condition') or node.get('repeat_until')
            try:
                max_items = int(node.get('max_items') or os.getenv('TLV_SEQ_MAX_ITEMS', '1024'))
            except Exception:
                max_items = 1024
            max_items = max(1, max_items)
            limit_end: Optional[int] = None
            if size_info.has_declared_size and size_info.declared_size_bits is not None:
                try:
                    declared_bits = int(size_info.declared_size_bits)
                    if declared_bits >= 0:
                        limit_end = node_start_cursor + declared_bits
                except Exception:
                    limit_end = None
            iterations = 0
            while True:
                if iterations >= max_items:
                    raise NodeParseError(int(node_id), f'tlv_seq exceeded max_items={max_items}', kind='structure')
                if limit_end is not None and stream.cursor >= limit_end:
                    break
                remaining_bits = limit_end - stream.cursor if limit_end is not None else stream.total_bits - stream.cursor
                if remaining_bits < 8:
                    break
                before = stream.cursor
                for child_id in children_ids:
                    child_id = _coerce_node_id(child_id)
                    if not self._is_node_active(child_id, context, evaluator):
                        continue
                    self._parse_node(child_id, stream, context, evaluator, parent_id=node_id, force_current_bit_start=True)
                if stream.cursor <= before:
                    raise NodeParseError(int(node_id), 'tlv_seq item consumed 0 bits (stuck)', kind='structure')
                iterations += 1
                if stop_formula:
                    try:
                        if bool(evaluator.evaluate(stop_formula, node_id)):
                            break
                    except UnresolvedReferenceError:
                        pass
                    except Exception as exc:
                        raise NodeParseError(int(node_id), f'tlv_seq stop_condition failed to evaluate: {exc}', kind='semantics', cause=exc) from exc
            actual_consumed_bits = stream.cursor - node_start_cursor
            context.sizes[node_id] = int(actual_consumed_bits)
            context.actual_sizes[node_id] = int(actual_consumed_bits)
            context.wire_sizes[node_id] = int(actual_consumed_bits)
            return

        def _selector_for_child(cid: Union[str, int]) -> Optional[Union[str, int]]:
            return self._find_selector_for_variant(cid)

        def _is_variant_member(cid: Union[str, int]) -> Tuple[bool, Optional[Union[str, int]]]:
            cid = _coerce_node_id(cid)
            child = self.nodes.get(cid) or {}
            node_type = str(child.get('node_type') or '').lower()
            has_children = bool(child.get('children_ids'))
            selector_id = _selector_for_child(cid)
            if node_type == 'variant':
                return (True, selector_id)
            if selector_id is not None and has_children:
                return (True, selector_id)
            return (False, selector_id)
        active_sequence: List[Tuple[str, List[Union[str, int]]]] = []
        current_group_selector: Optional[Union[str, int]] = None
        current_group_members: List[Union[str, int]] = []
        for child_id in children_ids:
            child_id = _coerce_node_id(child_id)
            child_node = self.nodes.get(child_id)
            if not child_node:
                continue
            is_variant_like, sel_id = _is_variant_member(child_id)
            if not is_variant_like:
                if current_group_members:
                    active_sequence.append(('group', current_group_members))
                    current_group_members = []
                    current_group_selector = None
                active_sequence.append(('single', [child_id]))
                continue
            if current_group_selector is None:
                current_group_selector = sel_id
                current_group_members = [child_id]
            elif sel_id == current_group_selector:
                current_group_members.append(child_id)
            else:
                active_sequence.append(('group', current_group_members))
                current_group_members = [child_id]
                current_group_selector = sel_id
        if current_group_members:
            active_sequence.append(('group', current_group_members))
        for item_type, item_data in active_sequence:
            if item_type == 'single':
                child_id = item_data[0]
                if not self._is_node_active(child_id, context, evaluator):
                    continue
                self._parse_node(child_id, stream, context, evaluator, parent_id=node_id)
            elif item_type == 'group':
                candidates = [cid for cid in item_data if self._is_node_active(cid, context, evaluator)]
                if not candidates:
                    continue
                if len(candidates) == 1:
                    variant_id = candidates[0]
                    selector_id = self._find_selector_for_variant(variant_id)
                    if selector_id is not None:
                        variants_list = context.active_variants.setdefault(selector_id, [])
                        if variant_id not in variants_list:
                            variants_list.append(variant_id)
                    self._parse_node(variant_id, stream, context, evaluator, parent_id=node_id)
                    continue
                start_cursor = stream.cursor
                base_context = copy.deepcopy(context)
                best_candidate = None
                best_score: Tuple[int, int] = (-1, -1)
                last_error: Optional[Exception] = None
                variant_errors: List[Any] = []
                selector_id_for_group: Optional[int] = None
                try:
                    selector_id_for_group = self._find_selector_for_variant(candidates[0]) if candidates else None
                    if selector_id_for_group is not None:
                        selector_id_for_group = int(selector_id_for_group)
                except Exception:
                    selector_id_for_group = None
                for var_id in candidates:
                    stream.seek(start_cursor)
                    context.values = copy.deepcopy(base_context.values)
                    context.bit_starts = copy.deepcopy(base_context.bit_starts)
                    context.sizes = copy.deepcopy(base_context.sizes)
                    context.actual_sizes = copy.deepcopy(base_context.actual_sizes)
                    context.wire_sizes = copy.deepcopy(base_context.wire_sizes)
                    context.length_gaps = list(base_context.length_gaps)
                    context.parsing_path = list(base_context.parsing_path)
                    context.visited_nodes = set(base_context.visited_nodes)
                    context.parent_on_path = dict(base_context.parent_on_path)
                    context.visit_log = list(base_context.visit_log)
                    context.active_variants = copy.deepcopy(base_context.active_variants)
                    context.field_spans = list(getattr(base_context, 'field_spans', []))
                    context.variant_trial_errors = copy.deepcopy(getattr(base_context, 'variant_trial_errors', []))
                    try:
                        self._parse_node(var_id, stream, context, evaluator, parent_id=node_id)
                        content_bits = context.actual_sizes.get(var_id)
                        if content_bits is None:
                            content_bits = context.actual_sizes.get(str(var_id), 0)
                        try:
                            content_bits_int = int(content_bits) if content_bits is not None else 0
                        except Exception:
                            content_bits_int = 0
                        wire_bits_int = stream.cursor - start_cursor
                        score = (content_bits_int, wire_bits_int)
                        if score > best_score:
                            best_candidate = var_id
                            best_score = score
                    except (ConstraintViolationError, IncompleteStreamError, ValueError, RoutingError) as e:
                        last_error = e
                        variant_errors.append((var_id, e))
                        continue
                    except NodeParseError as e:
                        last_error = e
                        variant_errors.append((var_id, e))
                        continue
                stream.seek(start_cursor)
                context.values = copy.deepcopy(base_context.values)
                context.bit_starts = copy.deepcopy(base_context.bit_starts)
                context.sizes = copy.deepcopy(base_context.sizes)
                context.actual_sizes = copy.deepcopy(base_context.actual_sizes)
                context.wire_sizes = copy.deepcopy(base_context.wire_sizes)
                context.length_gaps = list(base_context.length_gaps)
                context.parsing_path = list(base_context.parsing_path)
                context.visited_nodes = set(base_context.visited_nodes)
                context.parent_on_path = dict(base_context.parent_on_path)
                context.visit_log = list(base_context.visit_log)
                context.active_variants = copy.deepcopy(base_context.active_variants)
                context.field_spans = list(getattr(base_context, 'field_spans', []))
                context.variant_trial_errors = copy.deepcopy(getattr(base_context, 'variant_trial_errors', []))
                if best_candidate is None:
                    raise RoutingError(node_id, f'Routing failed at node {node_id}: None of the {len(candidates)} variants could be parsed. This indicates a selector/branching logic error rather than a leaf constraint failure.', variant_errors=variant_errors, selector_id=selector_id_for_group, candidate_variants=[_coerce_node_id(cid) for cid in candidates])
                if variant_errors:
                    max_records = max(1, int(os.getenv('STEP2_TRAFFIC_MAX_VARIANT_TRIAL_ERRORS', '8')))

                    def _safe_int(value: Any) -> Optional[int]:
                        try:
                            return int(value)
                        except Exception:
                            return None

                    def _eval_int_expr(expr: Any, current_id: int) -> Optional[int]:
                        if expr is None:
                            return None
                        try:
                            return int(evaluator.evaluate(expr, current_id))
                        except Exception:
                            return None
                    for var_id, exc in variant_errors[:max_records]:
                        var_node = self.nodes.get(_coerce_node_id(var_id)) or {}
                        bit_start_eval = _eval_int_expr(var_node.get('bit_start'), int(var_id))
                        if bit_start_eval is None:
                            bit_start_eval = _safe_int(start_cursor)
                        size_bits_eval = self._eval_size_expr(var_node.get('size_bits'), evaluator, int(var_id))
                        declared_end = int(bit_start_eval) + int(size_bits_eval) if bit_start_eval is not None and size_bits_eval is not None else None
                        record: Dict[str, Any] = {'group_parent_id': int(node_id), 'selector_id': int(selector_id_for_group) if selector_id_for_group is not None else None, 'candidate_variants': [int(_coerce_node_id(cid)) for cid in candidates], 'variant_id': int(_coerce_node_id(var_id)), 'variant_name': str(var_node.get('name') or ''), 'error_type': type(exc).__name__, 'message': str(exc), 'bit_start_eval': bit_start_eval, 'size_bits_eval': size_bits_eval, 'declared_end_bit': declared_end, 'packet_total_bits': int(getattr(stream, 'total_bits', 0) or 0)}
                        if isinstance(exc, NodeParseError):
                            record['node_id'] = int(getattr(exc, 'node_id', -1))
                            record['node_error_kind'] = str(getattr(exc, 'kind', '') or '')
                            cause = getattr(exc, 'cause', None)
                            if cause is not None:
                                record['cause_type'] = type(cause).__name__
                                record['cause_message'] = str(cause)
                                if isinstance(cause, IncompleteStreamError):
                                    record['cause_bit_pos'] = getattr(cause, 'bit_pos', None)
                                    record['cause_total_bits'] = getattr(cause, 'total_bits', None)
                                    record['cause_bits_needed'] = getattr(cause, 'bits_needed', None)
                                    record['cause_bits_remaining'] = getattr(cause, 'bits_remaining', None)
                        if isinstance(exc, IncompleteStreamError):
                            record['error_bit_pos'] = getattr(exc, 'bit_pos', None)
                            record['error_total_bits'] = getattr(exc, 'total_bits', None)
                            record['error_bits_needed'] = getattr(exc, 'bits_needed', None)
                            record['error_bits_remaining'] = getattr(exc, 'bits_remaining', None)
                        if isinstance(exc, ConstraintViolationError):
                            record['constraint_node_id'] = int(getattr(exc, 'node_id', -1))
                            record['constraint_text'] = str(getattr(exc, 'constraint_text', '') or '')
                            record['constraint_value'] = getattr(exc, 'value', None)
                            record['constraint_kind'] = str(getattr(exc, 'kind', '') or '')
                        try:
                            context.variant_trial_errors.append(record)
                        except Exception:
                            pass
                selector_id = self._find_selector_for_variant(best_candidate)
                if selector_id is not None:
                    variants_list = context.active_variants.setdefault(selector_id, [])
                    if best_candidate not in variants_list:
                        variants_list.append(best_candidate)
                logger.debug('Speculative Parsing: Winner is %s (content_bits=%s, wire_bits=%s)', best_candidate, best_score[0], best_score[1])
                self._parse_node(best_candidate, stream, context, evaluator, parent_id=node_id)
        final_size_bits = size_bits
        actual_consumed_bits = stream.cursor - node_start_cursor
        consumed_before_padding = actual_consumed_bits
        node_type_lower = str(node_type).lower() if node_type is not None else ''
        if node_type_lower in ['protocol', 'header', 'payload', 'variant', 'container']:
            if not (size_info.has_declared_size and size_info.declared_size_bits is not None):
                reevaluated: Optional[int] = self._eval_size_expr(size_expr, evaluator, node_id)
                if reevaluated is None:
                    for edge in self.edges:
                        if edge.get('rel') != 'length_of':
                            continue
                        dst = _coerce_node_id(edge.get('dst'))
                        if dst != node_id:
                            continue
                        formula = edge.get('formula')
                        if not formula:
                            continue
                        val = self._eval_size_expr(formula, evaluator, edge.get('src'))
                        if val is None:
                            continue
                        reevaluated = val
                        break
                if reevaluated is not None and int(reevaluated) >= 0:
                    try:
                        declared = int(reevaluated)
                    except Exception:
                        declared = -1
                    if declared >= 0:
                        size_info = NodeSizeInfo(True, declared)
                        context.sizes[node_id] = declared
                        final_size_bits = declared
            if size_info.has_declared_size and size_info.declared_size_bits is not None:
                declared_bits = size_info.declared_size_bits
                target_end = node_start_cursor + declared_bits
                if target_end < node_start_cursor:
                    logger.warning('Node %s declared_size_bits=%s is negative; ignoring declared size', node_id, declared_bits)
                else:
                    if target_end > stream.total_bits:
                        cause = IncompleteStreamError(f'Stream ended while seeking: invalid position {target_end}, total_bits={stream.total_bits}', bit_pos=target_end, total_bits=stream.total_bits)
                        raise NodeParseError(node_id, f'size_bits expression leads to read past end of packet (node={node_id}, declared_end={target_end}, total_bits={stream.total_bits})', kind='structure', cause=cause) from cause
                    if actual_consumed_bits > declared_bits:
                        if self._log_node_overflow:
                            try:
                                key = (int(node_id), int(target_end))
                            except Exception:
                                key = (str(node_id), int(target_end))
                            if key not in self._node_overflow_warned:
                                self._node_overflow_warned.add(key)
                                logger.warning('Node %s children consumed beyond declared size: consumed_bits=%s, declared_end_bit=%s', node_id, actual_consumed_bits, target_end)
                    else:
                        remaining_pad = declared_bits - actual_consumed_bits
                        if remaining_pad > 0:
                            logger.debug('Node %s padding/skip %s bits to align to declared size %s', node_id, remaining_pad, declared_bits)
                            stream.seek(target_end)
                            actual_consumed_bits = stream.cursor - node_start_cursor
        content_bits = consumed_before_padding if consumed_before_padding >= 0 else actual_consumed_bits
        if node_type_lower == 'payload' and (not (children_ids or [])) and (actual_consumed_bits > 0):
            content_bits = actual_consumed_bits
        context.actual_sizes[node_id] = content_bits
        context.wire_sizes[node_id] = actual_consumed_bits
        try:
            is_leaf_for_span = node_type_lower in LEAF_TYPES or not (children_ids or [])
            if is_leaf_for_span and actual_consumed_bits > 0:
                bit_start_val = context.bit_starts.get(node_id, node_start_cursor)
                context.field_spans.append({'node_id': node_id, 'bit_start': int(bit_start_val), 'wire_size_bits': int(actual_consumed_bits), 'content_size_bits': int(content_bits)})
        except Exception:
            pass
        try:
            if not (size_info.has_declared_size and size_info.declared_size_bits is not None):
                if node_type_lower in {'protocol', 'header', 'payload', 'variant', 'container'}:
                    raw_size_bits = node.get('size_bits')
                    is_explicitly_variable = raw_size_bits is None or (isinstance(raw_size_bits, str) and raw_size_bits.strip().lower() in {'variable', 'unknown', 'dynamic', ''})
                    if is_explicitly_variable:
                        context.sizes[node_id] = int(actual_consumed_bits)
        except Exception:
            pass

    def _is_node_active(self, node_id: int, context: RuntimeContext, evaluator: ExpressionEvaluator) -> bool:
        node_id = _coerce_node_id(node_id)
        conditions = [e for e in self.edges if _coerce_node_id(e.get('dst')) == node_id and e.get('rel') == 'condition_on']
        if not conditions:
            return True
        filtered = []
        for cond in conditions:
            edge_msg_type = str(cond.get('message_type') or 'bidirectional').lower()
            if self.target_message_type:
                if edge_msg_type not in {'bidirectional', self.target_message_type}:
                    continue
            filtered.append(cond)
        if self.target_message_type and (not filtered):
            return False
        from collections import defaultdict
        conditions_by_src = defaultdict(list)
        for cond in filtered:
            conditions_by_src[_coerce_node_id(cond.get('src'))].append(cond)
        for src_id, group in conditions_by_src.items():
            group_results = []
            for c in group:
                try:
                    formula = c.get('formula')
                    group_results.append(evaluator.evaluate(formula, node_id))
                except Exception as exc:
                    strict = os.getenv('STEP2_TRAFFIC_STRICT_CONDITION_EVAL', '1').strip().lower() not in {'0', 'false', 'no', 'off'}
                    if strict:
                        raise NodeParseError(int(node_id), f"condition_on formula failed to evaluate (edge {c.get('src')}->{c.get('dst')}, formula={c.get('formula')})", kind='semantics', cause=exc) from exc
                    group_results.append(False)
            if not any(group_results):
                return False
        return True

    def _compute_declared_size_bits(self, node_id: Union[str, int], parent_id: Optional[Union[str, int]], stream: BitStream, context: RuntimeContext, evaluator: ExpressionEvaluator) -> NodeSizeInfo:
        node_id = _coerce_node_id(node_id)
        parent_id = _coerce_node_id(parent_id) if parent_id is not None else None
        node = self.nodes.get(node_id)
        if node is None:
            raise ValueError(f'Node {node_id} not found while computing size_bits')
        size_expr = node.get('size_bits')
        if parent_id is None or node_id == _coerce_node_id(self.root_id):
            evaluated = self._eval_size_expr(size_expr, evaluator, node_id)
            if evaluated is not None and evaluated >= 0:
                return NodeSizeInfo(True, evaluated)
            if size_expr is None or (isinstance(size_expr, str) and size_expr.strip().lower() in {'variable', 'unknown', 'dynamic', ''}):
                return NodeSizeInfo(True, stream.total_bits)
        evaluated = self._eval_size_expr(size_expr, evaluator, node_id)
        if evaluated is not None and evaluated >= 0:
            return NodeSizeInfo(True, evaluated)
        for edge in self.edges:
            if edge.get('rel') != 'length_of':
                continue
            dst = _coerce_node_id(edge.get('dst'))
            if dst != node_id:
                continue
            formula = edge.get('formula')
            if not formula:
                continue
            val = self._eval_size_expr(formula, evaluator, edge.get('src'))
            if val is not None and val >= 0:
                return NodeSizeInfo(True, val)
        return NodeSizeInfo(False, None)

    def _eval_size_expr(self, expr: Any, evaluator: ExpressionEvaluator, current_node_id: Optional[Union[str, int]]=None) -> Optional[int]:
        if expr is None:
            return None
        if isinstance(expr, (int, float)) and (not isinstance(expr, bool)):
            try:
                return int(expr)
            except Exception:
                return None
        if isinstance(expr, str):
            normalized = expr.strip()
            if not normalized:
                return None
            if normalized.lower() in {'variable', 'unknown', 'dynamic'}:
                return None
            if normalized.isdigit() or (normalized.startswith('-') and normalized[1:].isdigit()):
                try:
                    return int(normalized)
                except Exception:
                    return None
            try:
                raw_val = evaluator.evaluate(normalized, current_node_id)
                if isinstance(raw_val, bool):
                    raw_val = int(raw_val)
                return int(raw_val)
            except UnresolvedReferenceError:
                return None
            except Exception:
                logger.debug("Failed to evaluate size expr '%s' for node %s", expr, current_node_id, exc_info=True)
                return None
        return None

    def _find_selector_for_variant(self, variant_id: Union[str, int]) -> Optional[Union[str, int]]:
        for e in self.edges:
            if e.get('rel') == 'condition_on' and _coerce_node_id(e.get('dst')) == _coerce_node_id(variant_id):
                return _coerce_node_id(e.get('src'))
        return None

    def _validate_length_edges(self, context: RuntimeContext, evaluator: ExpressionEvaluator) -> List[LengthMismatchDetail]:
        mismatches: List[LengthMismatchDetail] = []
        context.length_gaps = []

        def _lookup(map_obj: Dict[Any, Any], key: Any) -> Optional[Any]:
            if key in map_obj:
                return map_obj.get(key)
            skey = str(key)
            if skey in map_obj:
                return map_obj.get(skey)
            return None

        def _estimate_from_intervals(dst_id: Union[str, int]) -> Optional[int]:
            starts = getattr(context, 'bit_starts', {}) or {}
            declared_sizes = getattr(context, 'sizes', {}) or {}
            actual_sizes = getattr(context, 'actual_sizes', {}) or {}
            start_bit = _lookup(starts, dst_id)
            if start_bit is None:
                return None
            max_end = 0
            try:
                for nid, s in starts.items():
                    if s is None:
                        continue
                    size_val = _lookup(actual_sizes, nid)
                    if size_val is None:
                        size_val = _lookup(declared_sizes, nid)
                    if size_val is None:
                        continue
                    candidate = int(s) + int(size_val)
                    if candidate > max_end:
                        max_end = candidate
            except Exception:
                return None
            if max_end and max_end >= int(start_bit):
                return max_end - int(start_bit)
            return None
        for edge in self.edges:
            if edge.get('rel') != 'length_of':
                continue
            src = _coerce_node_id(edge.get('src'))
            dst = _coerce_node_id(edge.get('dst'))
            formula = edge.get('formula')
            if formula is None:
                continue
            content_bits = _lookup(getattr(context, 'actual_sizes', {}) or {}, dst)
            wire_bits = _lookup(getattr(context, 'wire_sizes', {}) or {}, dst)
            declared_bits = _lookup(getattr(context, 'sizes', {}) or {}, dst)
            try:
                expected = evaluator.evaluate(formula, current_node_id=src)
                if isinstance(expected, bool):
                    expected = int(expected)
                expected_bits = int(expected)
            except Exception:
                continue
            if expected_bits < 0:
                continue
            if wire_bits is None:
                wire_bits = declared_bits if declared_bits is not None else _estimate_from_intervals(dst)
            if content_bits is None:
                content_bits = wire_bits if wire_bits is not None else declared_bits
            if content_bits is not None and expected_bits is not None and (int(content_bits) > int(expected_bits)):
                mismatches.append(LengthMismatchDetail(src=src, dst=dst, expected_bits=expected_bits, actual_bits=int(content_bits), content_bits=int(content_bits), wire_bits=wire_bits if wire_bits is not None else int(content_bits), mismatch_kind='overflow', formula=formula, message_type=edge.get('message_type')))
                continue
            if wire_bits is not None and int(wire_bits) != int(expected_bits):
                mismatches.append(LengthMismatchDetail(src=src, dst=dst, expected_bits=expected_bits, actual_bits=int(wire_bits), content_bits=content_bits, wire_bits=wire_bits, mismatch_kind='wire_mismatch', formula=formula, message_type=edge.get('message_type')))
                continue
            if wire_bits is not None and int(wire_bits) == int(expected_bits) and (content_bits is not None) and (int(content_bits) < int(expected_bits)):
                context.length_gaps.append(LengthMismatchDetail(src=src, dst=dst, expected_bits=expected_bits, actual_bits=int(content_bits), content_bits=int(content_bits), wire_bits=wire_bits, mismatch_kind='coverage_gap', formula=formula, message_type=edge.get('message_type')))
        return mismatches
