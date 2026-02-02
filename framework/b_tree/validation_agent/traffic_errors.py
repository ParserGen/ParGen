from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

@dataclass
class TrafficParseFailure:
    packet_index: int
    node_id: int
    failure_kind: str
    bit_start: Optional[int]
    size_bits_eval: Optional[int]
    total_bits: int
    max_bit_reached: int
    path_node_ids: List[int]
    context_field_values: Dict[int, int]
    message: str = ''
    length_mismatch_src: Optional[int] = None
    length_mismatch_dst: Optional[int] = None
    length_expected_bits: Optional[int] = None
    length_actual_bits: Optional[int] = None
    length_formula: Optional[str] = None
    length_src_node_id: Optional[int] = None
    length_content_bits: Optional[int] = None
    length_wire_bits: Optional[int] = None
    length_gap_bits: Optional[int] = None
    length_overflow_bits: Optional[int] = None
    length_mismatch_kind: Optional[str] = None
    constraint_text: Optional[str] = None
    constraint_value: Optional[int] = None
    constraint_kind: Optional[str] = None
    routing_selector_id: Optional[int] = None
    routing_candidate_variant_ids: Optional[List[int]] = None
    routing_variant_errors: Optional[List[Dict[str, Any]]] = None
    coverage_tail_leftover_bits: Optional[int] = None
    coverage_internal_gap_bits: Optional[int] = None
    packet_hex: Optional[str] = None
    packet_len_bytes: Optional[int] = None
    group_signature: Optional[str] = None
