import logging
import json
import hashlib
import copy
import re
import os
from typing import Optional, List, Dict, Tuple, Set, Any
"""
ISSUE_SCENARIO_TEXTS = {'parent_overflow': 'Scenario: Parent container overflow / mis-sized header.\nValidator errors: "Layout: Container_A(ID:10) children may exceed parent size"\nPatch:\n{\n  "patch_metadata": { "description": "Repack header children and resize parent", "intent": "Fix overflow" },\n  "node_updates": [\n    { "node_id": 10, "property": "size_bits", "value": "48 + val(12)" },\n    { "node_id": 20, "property": "bit_start", "value": "10.bit_start + 16" },\n    { "node_id": 30, "property": "bit_start", "value": "10.bit_start + 16 + 20.size_bits" }\n  ]\n}', 'missing_length_binding': 'Scenario: Missing length_of binding for variable payload.\nValidator errors: "Semantics: Payload_B(ID:30) references val(12) but no length_of edge exists"\nPatch:\n{\n  "patch_metadata": { "description": "Bind Payload_B to Length_Field", "intent": "Restore dependency" },\n  "node_updates": [\n    { "node_id": 30, "property": "size_bits", "value": "val(12)" }\n  ],\n  "new_edges": [\n    { "src": 12, "dst": 30, "rel": "length_of", "formula": "val(12)", "message_type": "bidirectional" }\n  ]\n}', 'duplicate_root': 'Scenario: Duplicate header/root nodes and mis-parented children.\nValidator errors: "Structure: Multiple root nodes found" / "Child X has different parent"\nPatch:\n{\n  "patch_metadata": { "description": "Merge duplicate header into canonical root", "intent": "Single root" },\n  "node_updates": [\n    { "node_id": 16, "property": "parent_id", "value": 1 },\n    { "node_id": 1, "property": "children_ids", "value": [2,3,4,5,16] }\n  ],\n  "nodes_to_remove": [ { "node_id": 15 } ]\n}', 'condition_overlap': 'Scenario: Selector variants overlap / duplicate condition predicates.\nValidator errors: "Layout: Variant_Request invalid overlap with sibling" / "condition_on edges reuse identical predicates"\nPatch:\n{\n  "patch_metadata": { "description": "Re-scope selector branches", "intent": "Mutually exclusive variants" },\n  "node_updates": [\n    { "node_id": 40, "property": "bit_start", "value": "7.bit_start + 7.size_bits" },\n    { "node_id": 41, "property": "bit_start", "value": "7.bit_start + 7.size_bits + 40.size_bits" }\n  ],\n  "edge_updates": [\n    { "update_type": "modify", "edge_identifier": { "src": 7, "dst": 40, "rel": "condition_on" }, "new_properties": { "formula": "val(7) in {1,2}" } },\n    { "update_type": "modify", "edge_identifier": { "src": 7, "dst": 41, "rel": "condition_on" }, "new_properties": { "formula": "val(7) in {3,4}" } }\n  ]\n}', 'scalar_quantity_overlap': 'Scenario: A small scalar quantity-like field overlaps with a variable-length sibling payload field in the same container.\n\nValidator errors:\n- "Structure: ... Invalid overlap with sibling ..."\n- Both overlapping nodes share the same parent and message_type.\n- One node is a fixed-width scalar (size_bits is a small constant like 8/16/32) that is used only inside size_bits / constraint expressions.\n- The other node is variable-length and its size_bits formula references val(<SCALAR_NODE_ID>) (possibly multiplied by a constant factor).\n\nTypical interpretations:\n1. The scalar is a real on-wire header field which should appear before the payload.\n2. The scalar is purely semantic / derived and should not occupy any on-wire bits (semantic-only field).\n3. There are multiple quantity-like fields controlling the same payload length and one of them is redundant.\n\nYou must consider both possibilities (1) and (2) and choose a fix that:\n- eliminates the physical overlap,\n- keeps a single consistent length source for the payload,\n- and passes both static and traffic validators.\n\nTypical fixes:\n\nA. Re-layout header vs payload (scalar is on-wire):\n- Ensure the scalar quantity field starts where the parent's header ends.\n- Ensure the payload field starts immediately after the scalar:\n  * payload.bit_start = scalar.bit_start + scalar.size_bits\n- Ensure the parent container's size_bits equals the sum of its children's size_bits, instead of leaving gaps or overlaps.\n\nB. Convert the scalar into a semantic-only quantity (no on-wire bits):\n- Set the scalar's size_bits to 0:\n  * { "node_id": "<SCALAR_NODE_ID>", "property": "size_bits", "value": "0" }\n- Remove the scalar from the parent's layout / size_bits formula:\n  * Do not add scalar.size_bits when computing the parent size.\n- Keep uses of val(<SCALAR_NODE_ID>) in size_bits or constraint formulas if they still make semantic sense.\n\nC. Prefer intra-branch scalar length sources over cross-branch ones:\n- If a variable-length payload currently uses a quantity field from a different branch or message direction, consider:\n  * switching to a scalar sibling in the same branch; or\n  * converting the cross-branch quantity field into a semantic-only field (size_bits = 0) so it does not interfere with layout.\n\nPatch skeleton examples:\n\n1) Semantic-only quantity:\n{\n  "patch_metadata": {\n    "description": "Treat scalar quantity as semantic-only to resolve overlap with payload",\n    "intent": "Remove physical overlap while keeping a single length source"\n  },\n  "new_nodes": [],\n  "node_updates": [\n    { "node_id": "<SCALAR_NODE_ID>", "property": "size_bits", "value": "0" },\n    { "node_id": "<PARENT_ID>", "property": "size_bits", "value": "<EXPRESSION_SUM_OF_CHILDREN>" }\n  ],\n  "new_edges": [],\n  "edge_updates": [],\n  "edge_removes": []\n}\n\n2) Re-layout header + payload:\n{\n  "patch_metadata": {\n    "description": "Re-layout scalar quantity and payload to remove overlap",\n    "intent": "Header-then-payload, contiguous"\n  },\n  "new_nodes": [],\n  "node_updates": [\n    { "node_id": "<SCALAR_NODE_ID>", "property": "bit_start", "value": "<PARENT_ID>.bit_start + <HEADER_PREFIX_BITS>" },\n    { "node_id": "<PAYLOAD_NODE_ID>", "property": "bit_start", "value": "<SCALAR_NODE_ID>.bit_start + <SCALAR_NODE_ID>.size_bits" },\n    { "node_id": "<PARENT_ID>", "property": "size_bits", "value": "<SUM_OF_CHILD_SIZE_BITS>" }\n  ],\n  "new_edges": [],\n  "edge_updates": [],\n  "edge_removes": []\n}\n', 'length_of_src_mismatch': 'Scenario: length_of edge references wrong source node.\nValidator errors: "Graph: Payload(ID:30): length_of formula references [14] but src is 20"\nPatch:\n{\n  "patch_metadata": { "description": "Correct length_of source", "intent": "Align edge src with formula" },\n  "edge_removes": [\n    { "src": 20, "dst": 30, "rel": "length_of" }\n  ],\n  "new_edges": [\n    { "src": 14, "dst": 30, "rel": "length_of", "formula": "val(14)", "message_type": "bidirectional" }\n  ]\n}', 'length_of_duplicates': 'Scenario: Multiple length_of edges targeting same node.\nValidator errors: "Graph: Payload(ID:30): Multiple length_of bindings to node 30"\nPatch:\n{\n  "patch_metadata": { "description": "Consolidate length_of bindings", "intent": "Single sizing source" },\n  "edge_removes": [\n    { "src": 11, "dst": 30, "rel": "length_of" }\n  ],\n  "edge_updates": [\n    { "update_type": "modify", "edge_identifier": { "src": 12, "dst": 30, "rel": "length_of" }, "new_properties": { "formula": "val(12) * 8" } }\n  ]\n}', 'function_code_misparent': 'Scenario: Selector/Function field incorrectly kept under transport header, causing overflow.\nValidator errors: "Layout: <Header> children may exceed parent size" while a selector/Function entry is listed among offending children.\nPatch:\n{\n  "patch_metadata": { "description": "Move selector/Function field under PDU container", "intent": "Restore hierarchy" },\n  "node_updates": [\n    { "node_id": "<Function_Field_ID>", "property": "parent_id", "value": "<PDU_Selector_ID>" },\n    { "node_id": "<Header_ID>", "property": "children_ids", "value": [<header-only children> ] },\n    { "node_id": "<PDU_Selector_ID>", "property": "children_ids", "value": [<Function_Field_ID>, <request_variant>, <response_variant>] }\n  ],\n  "edge_updates": [],\n  "edge_removes": []\n}', 'traffic_parsing_blocked': 'Scenario: Dynamic parsing blocked because a field size or type is incorrect.\nValidator errors: "Semantics: Parsing blocked at Node X: Stream ended unexpectedly"\nPatch:\n{\n  "patch_metadata": { "description": "Fix size of Node X or previous field", "intent": "Fix parsing block" },\n  "node_updates": [\n    { "node_id": "<Node_X_ID>", "property": "size_bits", "value": "val(<Length_Field_ID>) * 8" }\n  ]\n}', 'traffic_constraint_failed': 'Scenario: Dynamic value violates constraint (likely endianness or strict range).\nValidator errors: "Semantics: Constraint failed for Node Y: value 256 violated value < 255"\nPatch:\n{\n  "patch_metadata": { "description": "Correct endianness for Node Y", "intent": "Fix constraint violation" },\n  "node_updates": [\n    { "node_id": "<Node_Y_ID>", "property": "byte_order", "value": "little" }\n  ]\n}', 'traffic_coverage_gap': 'Scenario: Bytes remain unparsed at the end of the packet.\nValidator errors: "Coverage: Parsing finished but 4 bytes remain unparsed"\nPatch:\n{\n  "patch_metadata": { "description": "Add missing Checksum/Footer field", "intent": "Complete coverage" },\n  "new_nodes": [\n    { "node_id": 900, "name": "Checksum", "node_type": "field", "data_type": "uint32", "bit_start": "...", "size_bits": 32, "parent_id": "..." }\n  ]\n}', 'traffic_length_mismatch': 'Scenario: Traffic parsing shows a node\'s size_bits expression reads past the end of the packet (not enough bits remain).\n\nValidator errors typically look like:\n- "[TRAFFIC][STRUCTURE][ERROR] node=<ID> size_bits expression leads to read past end of packet in sample #<N> ..."\n- Messages containing "read past end of packet", "not enough bits", or "size_bits expression leads to out-of-bounds".\n\nWhat this usually means:\n- The node is variable-length and its size_bits formula does not match real packets, or\n- The scalar quantity field that drives the length is mis-modeled (bit_start/size_bits wrong), or\n- The parent container size leaves gaps or double-counts bytes.\n\nWhen you see this, do NOT just loosen constraints or inflate packet length. Instead:\n\n1) Inspect the failing node\'s size_bits expression:\n- Does it reference a scalar sibling like val(<QUANTITY_NODE_ID>)?\n- Does bits_needed exceed the remaining bits between cursor and packet end?\n\n2) Inspect scalar quantity-like fields used in that expression:\n- Are they small fixed-width scalars (8/16/32 bits) placed before the payload?\n- Do their traffic values match the payload length?\n- If they are purely semantic, consider making them semantic-only (size_bits=0).\n\n3) Candidate fixes:\n\nA. Fix the size_bits formula:\n- Use the correct quantity/byte-count field in the same branch.\n- Adjust multipliers to match traffic (e.g., *8 vs *16).\n- Ensure size_bits never exceeds remaining bits.\n\nB. Fix or convert the quantity field:\n- If on-wire: correct its size_bits/bit_start so it precedes the payload.\n- If semantic-only: set size_bits=0 so it doesn\'t consume bits.\n\nC. Adjust the parent container layout:\n- Make children contiguous: payload.bit_start = previous_sibling.bit_start + previous_sibling.size_bits.\n- Set parent.size_bits to the sum of its children when they are present.\n\nPatch skeleton example:\n{\n  "patch_metadata": {\n    "description": "Align size_bits and quantity field with traffic to avoid out-of-bounds read",\n    "intent": "Match node length to actual packets"\n  },\n  "new_nodes": [],\n  "node_updates": [\n    { "node_id": "<PAYLOAD_NODE_ID>", "property": "size_bits", "value": "<CORRECT_EXPRESSION>" },\n    { "node_id": "<QUANTITY_NODE_ID>", "property": "size_bits", "value": "0" },  # optional semantic-only\n    { "node_id": "<PARENT_ID>", "property": "size_bits", "value": "<SUM_OF_CHILDREN_SIZE_BITS>" }\n  ],\n  "new_edges": [],\n  "edge_updates": [],\n  "edge_removes": []\n}\n', 'explicit_dependency_missing': 'Scenario: Formula references a node value (val(X)) but the corresponding graph edge is missing.\nValidator errors: "Semantics: Node_Y(ID:<Y>): Size expression references val(<X>) but no length_of edge exists"\nPatch:\n{\n  "patch_metadata": { "description": "Add missing length_of edge to support size formula", "intent": "Fix dependency" },\n  "new_edges": [\n    { "src": "<X>", "dst": "<Y>", "rel": "length_of", "formula": "val(<X>)", "message_type": "bidirectional" }\n  ]\n}', 'header_overflow_reparent': 'Scenario: Fixed-size Header contains a variable or extra child that causes overflow.\nValidator errors: "Layout: Header(ID:<H>): Children may exceed parent size... Offending children: Field_C(ID:<C>...)"\nPatch:\n{\n  "patch_metadata": { "description": "Move Field_C out of fixed Header into PDU Payload", "intent": "Fix container overflow" },\n  "node_updates": [\n    { "node_id": "<C>", "property": "parent_id", "value": "<PDU_ID>" },\n    { "node_id": "<H>", "property": "children_ids", "value": ["...remove <C>..."] },\n    { "node_id": "<PDU_ID>", "property": "children_ids", "value": ["...add <C>..."] }\n  ]\n}', 'sync_size_with_edge': 'Scenario: Field has \'variable\' size but a valid length_of edge exists.\nValidator errors: "Semantics: Field_A(ID:<A>) has size_bits="variable" but also a length_of edge... Please move the length formula"\nPatch:\n{\n  "patch_metadata": { "description": "Replace \'variable\' in size_bits with the explicit formula from the length_of edge", "intent": "Sync size definition" },\n  "node_updates": [\n    { "node_id": "<A>", "property": "size_bits", "value": "val(<Len_ID>) * 8" }\n  ]\n}', 'relax_selector_constraint': 'Scenario: Variant condition conflicts with parent selector\'s strict constraints.\nValidator errors: "Semantics: Variant_B(ID:<B>): Variant condition ... cannot be satisfied within selector constraints"\nPatch:\n{\n  "patch_metadata": { "description": "Relax selector constraints to include the new variant value", "intent": "Fix unsatisfiable condition" },\n  "node_updates": [\n    { "node_id": "<Selector_ID>", "property": "constraints", "value": ["enum: <existing_values>|<new_needed_value>"] }\n  ]\n}', 'self_reference_error': 'Scenario: Agent incorrectly linked a node to itself.\nValidator errors: "Edge 11->11 (length_of) is self-referential"\nPatch:\n{\n  "patch_metadata": { "description": "Remove invalid self-referential edge", "intent": "Fix graph cycle" },\n  "edge_removes": [\n    { "src": 11, "dst": 11, "rel": "length_of" }\n  ],\n  "node_updates": [\n    { "node_id": 11, "property": "size_bits", "value": "val(<ACTUAL_LENGTH_SOURCE_ID>) * 8" }\n  ]\n}', 'multiple_length_bindings': 'Scenario: Multiple edges define size for the same node.\nValidator errors: "Graph: Payload(ID:30): Multiple length_of bindings to node 30"\nPatch:\n{\n  "patch_metadata": { "description": "Remove stale length binding, keep only the correct one", "intent": "Resolve conflict" },\n  "edge_removes": [\n    { "src": <WRONG_SRC_ID>, "dst": 30, "rel": "length_of" }\n  ]\n}', 'propagate_parent_length': 'Scenario: Child has size but Parent container size is unknown.\nValidator errors: "Layout: Child(ID:20) may extend beyond parent Container(ID:10) (parent length unknown)"\nPatch:\n{\n  "patch_metadata": { "description": "Propagate length formula from PDU to specific Variant container", "intent": "Define parent size" },\n  "node_updates": [\n    { "node_id": 10, "property": "size_bits", "value": "val(<LENGTH_FIELD_ID>) * 8 - <HEADER_SIZE>" }\n  ],\n  "new_edges": [\n    { "src": <LENGTH_FIELD_ID>, "dst": 10, "rel": "length_of", "formula": "val(<src>) * 8 - <HEADER_SIZE>", "message_type": "bidirectional" }\n  ]\n}', 'simplify_pdu_size': 'Scenario: PDU/Container size formula is overly complex (using max/sum of many children) causing missing dependency errors.\nValidator errors: "Semantics: PDU(ID:<ID>): Size expression references val(...) but no length_of edge exists"\nPatch:\n{\n  "patch_metadata": { "description": "Simplify PDU size to rely on Header Length field instead of summing children", "intent": "Simplify structure" },\n  "node_updates": [\n    { "node_id": "<ID>", "property": "size_bits", "value": "(val(<LENGTH_FIELD_ID>) - <OFFSET>) * 8" }\n  ],\n  "edge_removes": [\n    { "src": "<OLD_SRC_ID>", "dst": "<ID>", "rel": "length_of" }\n  ],\n  "new_edges": [\n    { "src": "<LENGTH_FIELD_ID>", "dst": "<ID>", "rel": "length_of", "formula": "(val(<src>) - <OFFSET>) * 8", "message_type": "bidirectional" }\n  ]\n}'}
ISSUE_SCENARIO_RULES = [{'scenario': 'parent_overflow', 'pattern': 'children may exceed parent size'}, {'scenario': 'missing_length_binding', 'pattern': 'no length_of edge exists'}, {'scenario': 'duplicate_root', 'pattern': 'multiple root nodes found'}, {'scenario': 'duplicate_root', 'pattern': 'child \\d+ has different parent'}, {'scenario': 'condition_overlap', 'pattern': 'condition_on'}, {'scenario': 'scalar_quantity_overlap', 'pattern': 'invalid overlap with sibling'}, {'scenario': 'length_of_src_mismatch', 'pattern': 'length_of formula references'}, {'scenario': 'length_of_duplicates', 'pattern': 'multiple length_of bindings'}, {'scenario': 'function_code_misparent', 'pattern': 'function_code'}, {'scenario': 'traffic_parsing_blocked', 'pattern': 'parsing blocked'}, {'scenario': 'traffic_parsing_blocked', 'pattern': 'stream ended unexpectedly'}, {'scenario': 'traffic_constraint_failed', 'pattern': 'constraint failed'}, {'scenario': 'traffic_coverage_gap', 'pattern': 'remain[s]? unparsed'}, {'scenario': 'explicit_dependency_missing', 'pattern': 'references val\\(.*\\) but no length_of edge exists'}, {'scenario': 'explicit_dependency_missing', 'pattern': 'preserve the length_of relation'}, {'scenario': 'header_overflow_reparent', 'pattern': 'children may exceed parent size'}, {'scenario': 'header_overflow_reparent', 'pattern': 'offending children'}, {'scenario': 'sync_size_with_edge', 'pattern': 'move the length formula into size_bits'}, {'scenario': 'relax_selector_constraint', 'pattern': 'cannot be satisfied within selector constraints'}, {'scenario': 'self_reference_error', 'pattern': 'is self-referential'}, {'scenario': 'multiple_length_bindings', 'pattern': 'Multiple length_of bindings'}, {'scenario': 'propagate_parent_length', 'pattern': 'parent length unknown'}, {'scenario': 'simplify_pdu_size', 'pattern': 'Size expression .* references val.* but no length_of edge exists'}, {'scenario': 'traffic_length_mismatch', 'pattern': 'read past end of packet'}, {'scenario': 'traffic_length_mismatch', 'pattern': 'size_bits expression leads to out-of-bounds'}, {'scenario': 'traffic_length_mismatch', 'pattern': 'not enough bits'}]

"""

ISSUE_SCENARIO_TEXTS: Dict[str, str] = {
    'parent_overflow': """Scenario: Parent container overflow / mis-sized header.
Validator errors: "Layout: Container_A(ID:10) children may exceed parent size"
Patch:
{
  "patch_metadata": { "description": "Repack header children and resize parent", "intent": "overflow_fix" },
  "node_updates": [
    { "node_id": 10, "property": "size_bits", "value": "48 + val(12)" },
    { "node_id": 20, "property": "bit_start", "value": "10.bit_start + 16" },
    { "node_id": 30, "property": "bit_start", "value": "10.bit_start + 16 + 20.size_bits" }
  ]
}""",
    'missing_length_binding': """Scenario: Missing length_of binding for variable payload.
Validator errors: "Semantics: Payload_B(ID:30) references val(12) but no length_of edge exists"
Patch:
{
  "patch_metadata": { "description": "Bind Payload_B to Length_Field", "intent": "dependency_fix" },
  "node_updates": [
    { "node_id": 30, "property": "size_bits", "value": "val(12)" }
  ],
  "new_edges": [
    { "src": 12, "dst": 30, "rel": "length_of", "formula": "val(12)", "message_type": "bidirectional" }
  ]
}""",
    'duplicate_root': """Scenario: Duplicate header/root nodes and mis-parented children.
Validator errors: "Structure: Multiple root nodes found" / "Child X has different parent"
Patch:
{
  "patch_metadata": { "description": "Merge duplicate header into canonical root", "intent": "single_root" },
  "node_updates": [
    { "node_id": 16, "property": "parent_id", "value": 1 },
    { "node_id": 1, "property": "children_ids", "value": [2,3,4,5,16] }
  ],
  "nodes_to_remove": [ { "node_id": 15 } ]
}""",
    'condition_overlap': """Scenario: Selector variants overlap / duplicate condition predicates.
Validator errors: "invalid overlap with sibling" / "condition_on edges reuse identical predicates"
Patch:
{
  "patch_metadata": { "description": "Re-scope selector branches", "intent": "mutual_exclusion" },
  "edge_updates": [
    { "update_type": "modify", "edge_identifier": { "src": 7, "dst": 40, "rel": "condition_on" }, "new_properties": { "formula": "val(7) in {1,2}" } },
    { "update_type": "modify", "edge_identifier": { "src": 7, "dst": 41, "rel": "condition_on" }, "new_properties": { "formula": "val(7) in {3,4}" } }
  ]
}""",
    'scalar_quantity_overlap': """Scenario: A small scalar quantity-like field overlaps with a variable-length sibling payload field.

Interpretations:
1) Scalar is on-wire header -> payload starts after scalar.
2) Scalar is semantic-only -> set size_bits=0 so it consumes no wire bits.

Patch skeleton (option 1):
{
  "patch_metadata": {"description": "Resolve scalar/payload overlap", "intent": "layout_fix"},
  "node_updates": [
    {"node_id": "<PAYLOAD_NODE_ID>", "property": "bit_start", "value": "<SCALAR_NODE_ID>.bit_start + <SCALAR_NODE_ID>.size_bits"}
  ]
}

Patch skeleton (option 2):
{
  "patch_metadata": {"description": "Make scalar semantic-only", "intent": "semantic_only"},
  "node_updates": [
    {"node_id": "<SCALAR_NODE_ID>", "property": "size_bits", "value": "0"}
  ]
}""",
    'length_of_src_mismatch': """Scenario: length_of edge uses the wrong source field or formula.
Patch:
{
  "patch_metadata": {"description": "Fix length_of source/formula", "intent": "dependency_fix"},
  "edge_updates": [
    {"update_type": "modify", "edge_identifier": {"src": "<OLD_SRC_ID>", "dst": "<DST_ID>", "rel": "length_of"}, "new_properties": {"src": "<NEW_SRC_ID>", "formula": "val(<NEW_SRC_ID>)*8"}}
  ]
}""",
    'length_of_duplicates': """Scenario: Duplicate length_of edges for the same destination.
Patch:
{
  "patch_metadata": {"description": "Remove duplicate length_of", "intent": "dedup"},
  "edge_removes": [{"src": "<REDUNDANT_SRC_ID>", "dst": "<DST_ID>", "rel": "length_of"}]
}""",
    'function_code_misparent': """Scenario: A selector-like field (Function Code / Opcode) is mis-parented or duplicated inside variants.
Patch:
{
  "patch_metadata": {"description": "Hoist selector to shared header and re-layout variants", "intent": "selector_fix"},
  "node_updates": [
    {"node_id": "<SELECTOR_ID>", "property": "parent_id", "value": "<HEADER_ID>"},
    {"node_id": "<VARIANT_ID>", "property": "bit_start", "value": "<SELECTOR_ID>.bit_start + <SELECTOR_ID>.size_bits"}
  ]
}""",
    'traffic_parsing_blocked': """Scenario: Traffic parsing blocked (stream ended unexpectedly / oob_seek/oob_read).
Likely cause: size_bits too large or missing length_of binding.
Patch:
{
  "patch_metadata": {"description": "Fix size to prevent out-of-bounds", "intent": "traffic_oob_fix"},
  "node_updates": [{"node_id": "<NODE_ID>", "property": "size_bits", "value": "val(<LENGTH_ID>)*8"}],
  "new_edges": [{"src": "<LENGTH_ID>", "dst": "<NODE_ID>", "rel": "length_of", "formula": "val(<LENGTH_ID>)*8", "message_type": "bidirectional"}]
}""",
    'traffic_constraint_failed': """Scenario: Traffic constraint failed (value violates constraint).
Likely cause: constraint too strict or wrong size/endianness.
Patch:
{
  "patch_metadata": {"description": "Relax or correct constraint", "intent": "constraint_fix"},
  "node_updates": [{"node_id": "<NODE_ID>", "property": "constraints", "value": ["<REVISED_CONSTRAINT>"]}]
}""",
    'traffic_coverage_gap': """Scenario: Traffic has unconsumed trailer / coverage gaps.
Likely cause: missing leaf fields. Add an opaque bytes field as last resort.
Patch:
{
  "patch_metadata": {"description": "Add opaque payload to cover gap", "intent": "traffic_payload_fill"},
  "new_nodes": [{"node_id": "<NEW_ID>", "name": "opaque_payload", "node_type": "field", "data_type": "bytes", "bit_start": "<ANCHOR>.bit_start + <ANCHOR>.size_bits", "size_bits": "<GAP_SIZE_BITS>", "parent_id": "<PARENT_ID>"}]
}""",
    'explicit_dependency_missing': """Scenario: Expression references val(<ID>) but there is no length_of edge for that dependency.
Patch:
{
  "patch_metadata": {"description": "Add missing length_of dependency", "intent": "dependency_fix"},
  "new_edges": [{"src": "<SRC_ID>", "dst": "<DST_ID>", "rel": "length_of", "formula": "val(<SRC_ID>)*8", "message_type": "bidirectional"}]
}""",
    'header_overflow_reparent': """Scenario: Parent container overflows due to mis-parented fields.
Patch:
{
  "patch_metadata": {"description": "Reparent overflowing children", "intent": "overflow_fix"},
  "node_updates": [{"node_id": "<CHILD_ID>", "property": "parent_id", "value": "<NEW_PARENT_ID>"}]
}""",
    'sync_size_with_edge': """Scenario: size_bits and length_of disagree (formula only on the edge or only in size_bits).
Patch:
{
  "patch_metadata": {"description": "Synchronize size_bits with length_of", "intent": "consistency_fix"},
  "node_updates": [{"node_id": "<DST_ID>", "property": "size_bits", "value": "val(<SRC_ID>)*8"}],
  "edge_updates": [{"update_type": "modify", "edge_identifier": {"src": "<SRC_ID>", "dst": "<DST_ID>", "rel": "length_of"}, "new_properties": {"formula": "val(<SRC_ID>)*8"}}]
}""",
    'relax_selector_constraint': """Scenario: Variant activation constraint cannot be satisfied within selector constraints.
Patch:
{
  "patch_metadata": {"description": "Relax selector constraint", "intent": "constraint_fix"},
  "node_updates": [{"node_id": "<SELECTOR_ID>", "property": "constraints", "value": ["<RELAXED_RANGE>"]}]
}""",
    'self_reference_error': """Scenario: Self-referential edge detected (src == dst).
Patch:
{
  "patch_metadata": {"description": "Remove self-loop edge", "intent": "graph_fix"},
  "edge_removes": [{"src": "<ID>", "dst": "<ID>", "rel": "<REL>"}]
}""",
    'multiple_length_bindings': """Scenario: Multiple length_of edges define size for the same node.
Keep only the most plausible binding; remove others.
Patch:
{
  "patch_metadata": {"description": "Resolve multiple length_of bindings", "intent": "dedup"},
  "edge_removes": [{"src": "<WRONG_SRC_ID>", "dst": "<DST_ID>", "rel": "length_of"}]
}""",
    'propagate_parent_length': """Scenario: Parent container size is unknown; children may extend beyond parent.
Patch:
{
  "patch_metadata": {"description": "Propagate length to parent container", "intent": "define_parent_size"},
  "node_updates": [{"node_id": "<PARENT_ID>", "property": "size_bits", "value": "val(<LENGTH_ID>)*8"}],
  "new_edges": [{"src": "<LENGTH_ID>", "dst": "<PARENT_ID>", "rel": "length_of", "formula": "val(<LENGTH_ID>)*8", "message_type": "bidirectional"}]
}""",
    'simplify_pdu_size': """Scenario: Container/PDU size_bits is overly complex and introduces missing dependencies.
Patch:
{
  "patch_metadata": {"description": "Simplify PDU size_bits", "intent": "simplify"},
  "node_updates": [{"node_id": "<PDU_ID>", "property": "size_bits", "value": "(val(<LENGTH_ID>)-<OFFSET>)*8"}]
}""",
    'traffic_length_mismatch': """Scenario: Traffic shows length mismatch (read past end / not enough bits).
Patch:
{
  "patch_metadata": {"description": "Fix traffic length mismatch", "intent": "traffic_length_fix"},
  "node_updates": [{"node_id": "<NODE_ID>", "property": "size_bits", "value": "val(<LEN_ID>)*8"}]
}""",
}

ISSUE_SCENARIO_RULES = [
    {'scenario': 'parent_overflow', 'pattern': 'children may exceed parent size'},
    {'scenario': 'missing_length_binding', 'pattern': 'no length_of edge exists'},
    {'scenario': 'duplicate_root', 'pattern': 'multiple root nodes found'},
    {'scenario': 'duplicate_root', 'pattern': 'child \\\\d+ has different parent'},
    {'scenario': 'condition_overlap', 'pattern': 'condition_on'},
    {'scenario': 'scalar_quantity_overlap', 'pattern': 'invalid overlap with sibling'},
    {'scenario': 'length_of_src_mismatch', 'pattern': 'length_of formula references'},
    {'scenario': 'length_of_duplicates', 'pattern': 'multiple length_of bindings'},
    {'scenario': 'function_code_misparent', 'pattern': 'function_code'},
    {'scenario': 'traffic_parsing_blocked', 'pattern': 'parsing blocked'},
    {'scenario': 'traffic_parsing_blocked', 'pattern': 'stream ended unexpectedly'},
    {'scenario': 'traffic_constraint_failed', 'pattern': 'constraint failed'},
    {'scenario': 'traffic_coverage_gap', 'pattern': 'remain[s]? unparsed'},
    {'scenario': 'explicit_dependency_missing', 'pattern': 'references val\\\\(.*\\\\) but no length_of edge exists'},
    {'scenario': 'explicit_dependency_missing', 'pattern': 'preserve the length_of relation'},
    {'scenario': 'header_overflow_reparent', 'pattern': 'children may exceed parent size'},
    {'scenario': 'header_overflow_reparent', 'pattern': 'offending children'},
    {'scenario': 'sync_size_with_edge', 'pattern': 'move the length formula into size_bits'},
    {'scenario': 'relax_selector_constraint', 'pattern': 'cannot be satisfied within selector constraints'},
    {'scenario': 'self_reference_error', 'pattern': 'is self-referential'},
    {'scenario': 'multiple_length_bindings', 'pattern': 'Multiple length_of bindings'},
    {'scenario': 'propagate_parent_length', 'pattern': 'parent length unknown'},
    {'scenario': 'simplify_pdu_size', 'pattern': 'Size expression .* references val.* but no length_of edge exists'},
    {'scenario': 'traffic_length_mismatch', 'pattern': 'read past end of packet'},
    {'scenario': 'traffic_length_mismatch', 'pattern': 'size_bits expression leads to out-of-bounds'},
    {'scenario': 'traffic_length_mismatch', 'pattern': 'not enough bits'},
]

def _build_node_maps(tree: dict) -> Tuple[Dict[str, dict], Dict[str, int]]:
    nodes = tree.get('nodes', []) if isinstance(tree, dict) else []
    node_map: Dict[str, dict] = {}
    parent_map: Dict[str, Optional[str]] = {}
    for n in nodes:
        nid = n.get('node_id')
        if nid is None:
            continue
        nid_str = str(nid)
        node_map[nid_str] = n
        parent_map[nid_str] = str(n.get('parent_id')) if n.get('parent_id') is not None else None
    depth_cache: Dict[str, int] = {}

    def _depth(nid: str, visited: Optional[Set[str]]=None) -> int:
        if nid in depth_cache:
            return depth_cache[nid]
        if visited is None:
            visited = set()
        if nid in visited:
            return 0
        visited.add(nid)
        parent = parent_map.get(nid)
        if parent is None or parent not in parent_map:
            depth_cache[nid] = 0
        else:
            depth_cache[nid] = _depth(parent, visited) + 1
        return depth_cache[nid]
    for nid in parent_map:
        _depth(nid)
    return (node_map, depth_cache)

def _issue_priority(issue: dict, node_map: Dict[str, dict], depth_map: Dict[str, int]) -> Tuple[int, int, int, int]:
    severity_order = {'ERROR': 0, 'WARN': 1, 'HINT': 2}
    issue_type_order = {'STRUCTURE': 0, 'SEMANTICS': 1, 'COVERAGE': 2, 'WARNING': 3}
    target = issue.get('target')
    if not isinstance(target, dict):
        target = {}
    node_id = target.get('identifier')
    node_id_str = str(node_id) if node_id is not None else None
    depth = depth_map.get(node_id_str, 10 ** 6) if node_id_str else 10 ** 6
    bit_start_val = 10 ** 6
    if node_id_str and node_id_str in node_map:
        bs = node_map[node_id_str].get('bit_start')
        try:
            bit_start_val = int(bs)
        except Exception:
            bit_start_val = 10 ** 6
    import re as _re
    hits = 0
    desc = issue.get('description')
    if isinstance(desc, str):
        m = _re.search('total_hits=(\\d+)', desc)
        if m:
            try:
                hits = int(m.group(1))
            except Exception:
                hits = 0
    severity = severity_order.get(str(issue.get('severity') or '').upper(), 3)
    itype = issue_type_order.get(str(issue.get('type') or '').upper(), 4)
    return (depth, bit_start_val, -hits, severity, itype)

def build_issue_example_block(issues_payload, validator_errors, validator_extras):
    texts: List[str] = []
    for issue in issues_payload or []:
        if isinstance(issue, dict):
            description = issue.get('description')
            if isinstance(description, str):
                texts.append(description.lower())
    for err in validator_errors or []:
        if isinstance(err, str):
            texts.append(err.lower())
    for extra in validator_extras or []:
        if isinstance(extra, str):
            texts.append(extra.lower())
    matched: List[str] = []
    seen = set()
    for text in texts:
        for rule in ISSUE_SCENARIO_RULES:
            scenario = rule['scenario']
            if scenario in seen:
                continue
            if re.search(rule['pattern'], text, re.IGNORECASE):
                snippet = ISSUE_SCENARIO_TEXTS.get(scenario)
                if snippet:
                    matched.append(snippet)
                    seen.add(scenario)
    if not matched:
        return ''
    return '### ISSUE-SPECIFIC FEWSHOT EXAMPLES\n' + '\n\n'.join(matched) + '\n'

def summarize_sections_for_patch(sections, batch_start: int, batch_size: int, focus_only: bool=False):
    end = batch_start + batch_size
    subset = []
    for index, section in enumerate(sections):
        if not isinstance(section, dict):
            section = {'content': str(section)}
        elif 'content' not in section and 'summary' in section:
            section = {**section, 'content': section.get('summary', '')}
        if batch_start <= index < end:
            content = section.get('content', '')
            marked = copy.deepcopy(section)
            marked['content'] = f'<attention priority="high">\n{content}\n</attention>'
            marked['is_focused'] = True
            subset.append(marked)
    return subset

def build_initial_tree_message(sections, validation_feedback: Optional[str]=None):
    enhanced_sections = []
    summary_lines = []
    for section in sections:
        if not isinstance(section, dict):
            section = {'content': str(section)}
        elif 'content' not in section and 'summary' in section:
            section = {**section, 'content': section.get('summary', '')}
        summary = section.get('summary') or section.get('content', '')
        if isinstance(summary, str):
            summary_text = summary.strip()
        else:
            summary_text = ''
        enhanced_section = {'number': section.get('number', ''), 'title': section.get('title', ''), 'source_file': section.get('source_file', 'unknown'), 'summary': summary_text, 'content': section.get('content', '')[:], 'packet_formats': section.get('packet_formats', [])[:]}
        enhanced_sections.append(enhanced_section)
        section_label = section.get('number') or section.get('title') or 'Section'
        if summary_text:
            summary_lines.append(f'- {section_label}: {summary_text}')
        else:
            content_preview = section.get('content', '')
            if content_preview:
                summary_lines.append(f'- {section_label}: {content_preview[:200]}')
    overall_summary = '\n'.join(summary_lines) if summary_lines else '(No section summaries available.)'
    prompt = '\n\n## CRITICAL NON-NEGOTIABLE GUIDELINES\n\n- **Selector coverage must be exhaustive**: enumerate every documented value or range for each control field before creating variants. Keep selector constraints (enum/range) identical to the union of your `condition_on` predicates so no value is left without a variant.\n- **condition_on formulas must be valid booleans**: NEVER concatenate clauses (e.g., `A (B)` or `A B`). If you need multiple cases, use explicit `or`/`and` with parentheses.\n- **Represent exception patterns explicitly**: when the specification describes bit-derived or offset-based exceptions (e.g., high bit indicates error, value + constant), create separate variants with matching predicates.\n- **Length bindings must respect the spec**: if a length field includes shared headers or auxiliary bytes, subtract them before binding to downstream payloads. Use `length_of` edges instead of embedding arithmetic in `size_bits`.\n- **When mirroring a `length_of` formula into `size_bits`, copy the exact expression (including any offsets) and keep the `length_of` edge.** Never simplify `val(x) - 1` to `val(x)` or drop the edge; both must remain consistent with the protocol math.\n- **Variants contain only selector-specific bodies**: do not copy shared headers/selectors into variants; start variant `bit_start` immediately after the shared fields to avoid overlap.\n- **SMT-safe expressions are mandatory**: follow the numeric-expression and constraint rules below so every formula is Z3 compatible.\n- **If the current tree already matches the specification** and no meaningful structural change remains, return an empty patch (`{}`) instead of inventing arbitrary updates.\n\n## UNIVERSAL NODE TYPES (Protocol-Agnostic)\n\n```yaml\nprotocol:     # Root container for entire protocol message\nheader:       # Fixed-structure container with sub-fields  \nfield:        # Concrete data field (leaf node)\nselector:     # Control field that determines message variants\nvariant:      # Alternative message structure based on selector\npayload:      # Variable-content data section\ncontainer:    # Generic grouping of related fields\n```\n\n## POSITIONING STRATEGY (Universal)\n\nCRITICAL: Always Use Numeric Node IDs in Expressions\n\n### PROHIBITED Positioning Patterns:\n**Self-references**: `node.bit_start + node.size_bits` (e.g., "22.bit_start + 22.size_bits")\n**Parent container references**: Child referencing its direct parent container (e.g., Node 41 with parent_id=40 using "40.bit_start + 0")\n**Forward references**: Referencing nodes that don\'t exist or come later in sequence\n**Cross-container references** without proper hierarchy\n**Circular dependencies** between nodes\n\n**Key Principle**: bit_start = parent.bit_start + offset_within_parent\n\n## SMT-COMPATIBLE EXPRESSION RULES (STRICT)\n\n- `bit_start` / `size_bits` expressions must remain numeric. Use only literals, additions, or `val(NODE_ID) * constant` forms.\n- NEVER embed boolean expressions inside arithmetic (no `(val(X) == 2)` inside `size_bits`).\n- Conditions must remain boolean expressions (comparisons + `And`/`Or`/`Not`).\n- Reference other nodes via `val(NODE_ID)` or `NODE_ID.bit_start/size_bits`; do not introduce field names.\n- For length prefixes, express the relationship via `length_of` edges rather than inline conditional arithmetic.\n\n## MESSAGE TYPE CLASSIFICATION (Mandatory)\n\nEvery node MUST have exactly one message_type:\n\n- **"bidirectional"**: Used in both directions (headers, control fields)\n- **"request"**: Client-to-server/caller-to-callee structures  \n- **"response"**: Server-to-client/callee-to-caller structures\n\n## CONTROL FIELD DETECTION & VARIANT CREATION\nWhen you find a field that determines message structure:\n\n1. **Identify the selector field** (command, type, opcode, operation, etc.).\n2. **Enumerate every documented value or range** and determine which directions (request/response/exception) exist for each.\n3. **Do not duplicate selector fields** inside variants-variants only contain the selector-specific payload.\n4. **Add condition_on edges** that mirror the selector constraints exactly, including any bitwise predicates required for exceptions.\n5. **Verify coverage**: the union of all condition predicates must equal the selector\'s declared domain.\n```\n\n### ANTI-PATTERN - Avoid This:\n```json\n{\n  "node_id": "variant1_id",\n  "name": "Command_A_Variant",\n  "bit_start": "same_as_selector",  // POSITION CONFLICT!\n  "children_ids": ["duplicate_selector", "field1", "field2"]\n},\n{\n  "node_id": "duplicate_selector", \n  "name": "Command_A_Control_Field",  // DUPLICATE SELECTOR!\n  "bit_start": "same_as_original_selector"\n}\n```\n\n**Universal Rules for Variant Creation:**\n- **One selector per protocol layer** - never duplicate control fields\n- **Variants contain only command-specific data** - no repeated headers/selectors\n- **Sequential positioning** - variants start after shared fields\n- **Conditional edges** - link selector values to appropriate data variants and cover the entire selector domain\n \n**Initial tree scope:** Build a stable universal skeleton-root node, shared header nodes, base message/data containers, and essential fields only. Leave protocol-specific command or exception branches for the refinement stage.\n\n## CONSTRAINT EXTRACTION (SMT-Compatible Only)\n\nExtract constraints as PURE mathematical expressions:\n- "must be 0" -> `"enum: 0"`\n- "values 1-255" -> `"range: 1 <= value <= 255"`\n- "one of A, B, C" -> `"enum: A|B|C"`\n- "length field maximum 64 (bytes)" -> `"range: 0 <= value <= 64"`\n- "payload maximum 64 bytes" -> `"range: 0 <= size_bits <= 512"`  *(or omit and rely on `length_of`)*\n- "aligned to 2 bytes" -> `"formula: value % 2 == 0"`\n- "multiple of 8" -> `"formula: value % 8 == 0"`\n- "depends on field X" -> `"formula: value = val(X_NODE_ID)"`\n- **Formula assignment**: Every `formula:` constraint must be written as `formula: value = <expression>`, for example `formula: value = min(val(37), 252 * 8)`.\n\n**CRITICAL: SMT Solver Compatibility**\nAll constraints will be processed by an SMT solver for traffic generation.\nFORBIDDEN constraint formats (natural language):\n- "encoding: hexadecimal"\n- "alignment: 2-byte boundary"\n- "padding: zero bits"\n- "endianness: big"\n\nREQUIRED constraint formats (pure math only):\n- Use "range: min <= value <= max" for ranges\n- Use "enum: val1|val2|val3" for specific values\n- Use "formula: mathematical_expression" for complex conditions\n- Always use val(NODE_ID) to reference other nodes, NEVER field names\n\nCRITICAL: NO natural language in constraints - only mathematical expressions!\n\n## EDGE MESSAGE TYPE RULES\n\nEvery edge MUST have a message_type attribute:\n- **"bidirectional"**: Edge applies to both request and response messages\n- **"request"**: Edge only applies in request messages\n- **"response"**: Edge only applies in response messages\n\nFor condition_on edges:\n- If the condition determines a request variant -> message_type = "request"\n- If the condition determines a response variant -> message_type = "response"\n- If the condition applies to both -> message_type = "bidirectional"\n\nFor length_of, offset_of, crc_of edges:\n- Usually message_type = "bidirectional" unless specific to one direction\n- `src` / `dst` MUST be existing numeric node IDs (write them as numbers, not quoted strings).\n\n## OUTPUT SCHEMA (Strict JSON)\n\n## TLV-SEQUENCE MODELLING (protocol-agnostic)\n\nWhen the tree contains a repeated TLV list (Code/Tag + optional Length + Value repeated until end-of-list),\nprefer modelling it as a sequence instead of many overlapping siblings:\n- Create a node with `node_type: "tlv_seq"` for the repeated list.\n- The `tlv_seq` node\'s children define the item template and will be parsed repeatedly.\n- Use `stop_condition` on the tlv_seq node (e.g., `val(CODE_ID) == END_CODE`) and/or a bounded `size_bits`\n  on the tlv_seq to stop at the enclosing container boundary.\n- Inside each item, use `selector` + `variant` with `condition_on` edges to model PAD/END/normal items.\n  IMPORTANT: `parent_id`/`children_ids` represent physical containment. Variants MUST NOT be children of the selector\n  node unless they are sub-bitfields within the selector byte. Prefer an item container under `tlv_seq` and attach the\n  tag selector + all variants as siblings under that item container.\n\n\n{\n  "protocol_tree": {\n    "root_node_id": 0,\n    "nodes": [\n      {\n        "node_id": 0,\n        "name": "Protocol_Root",\n        "node_type": "protocol|header|field|selector|variant|payload|container|tlv_seq",\n        "message_type": "bidirectional|request|response",\n        "bit_start": "positioning_expression", (parent_node_id.bit_start + offset [It can be expressed using the size of a close previous brother or accurate absolute value]) **IMPORTANT, the first item must rely on parent node bit_start**\n        "size_bits": "size_expression_or_integer",\n        "data_type": "binary|uint8|uint16|uint32|uint64|string|bytes",\n        "byte_order": "big|little",\n        "parent_id": "parent_node_id_or_null",\n        "children_ids": ["array_of_child_node_ids"],\n        "constraints": ["constraint_strings"],\n        "source": "documentation_reference",\n        "dependencies": []\n      }\n    ],\n    "edges": [\n      {\n        "src": source_node_id,\n        "dst": destination_node_id,\n        "rel": "length_of|condition_on|offset_of|repeat_count|crc_of",\n        "formula": "relationship_expression",\n        "message_type": "bidirectional|request|response"\n      }\n    ]\n  }\n}\n\n\n## EXAMPLE OUTPUT (Generic Protocol)\n\n\n{\n  "protocol_tree": {\n    "root_node_id": "root",\n    "nodes": [\n      {\n        "node_id": "root",\n        "name": "Generic PDU",\n        "node_type": "protocol",\n        "message_type": "bidirectional",\n        "bit_start": 0,\n        "size_bits": "variable",\n        "data_type": "binary",\n        "byte_order": "big",\n        "parent_id": null,\n        "children_ids": ["10","20","30"],\n        "constraints": [],\n        "source": "Section 1.1.1",\n        "dependencies": []\n      },\n\n      /* - Header - */\n      {\n        "node_id": "10",\n        "name": "Header",\n        "node_type": "header",\n        "message_type": "bidirectional",\n        "bit_start": root.bit_start + 0,\n        "size_bits": "8 + 12.size_bits",\n        "data_type": "binary",\n        "byte_order": "big",\n        "parent_id": "root",\n        "children_ids": ["11","12"],\n        "constraints": [],\n        "source": "Section 2.5.8",\n        "dependencies": []\n      },\n      {\n        "node_id": "11",\n        "name": "Control_Byte",\n        "node_type": "field",\n        "message_type": "bidirectional",\n        "bit_start": "10.bit_start",\n        "size_bits": 8,\n        "data_type": "uint8",\n        "byte_order": "big",\n        "parent_id": "10",\n        "children_ids": [],\n        "constraints": ["enum: val1|val2|val3"],\n        "source": "Section 1.1.2",\n        "dependencies": []\n      },\n      {\n        "node_id": "12",\n        "name": "Length_Field",\n        "node_type": "field",\n        "message_type": "bidirectional",\n        "bit_start": "10.bit_start + 11.size_bits",\n        "size_bits": "varint",\n        "data_type": "uint",\n        "byte_order": "big",\n        "parent_id": "10",\n        "children_ids": [],\n        "constraints": [],\n        "source": "Section 2.1.3",\n        "dependencies": []\n      },\n\n      /* - Body Section A - */\n      {\n        "node_id": "20",\n        "name": "Body_SectionA",\n        "node_type": "header",\n        "message_type": "bidirectional",\n        "bit_start": "root.bit_start + 10.size_bits",\n        "size_bits": "val(12)",\n        "data_type": "binary",\n        "byte_order": "big",\n        "parent_id": "root",\n        "children_ids": [],\n        "constraints": [],\n        "source": "Section 3.1.6",\n        "dependencies": []\n      },\n\n      /* - Body Section B - */\n      {\n        "node_id": "30",\n        "name": "Body_SectionB",\n        "node_type": "payload",\n        "message_type": "bidirectional",\n        "bit_start": "root.bit_start + 10.size_bits",\n        "size_bits": "val(12)",\n        "data_type": "binary",\n        "byte_order": "big",\n        "parent_id": "root",\n        "children_ids": [],\n        "constraints": [],\n        "source": "Section 1.1.5",\n        "dependencies": []\n      }\n    ],\n    "edges": [\n      {\n        "src": 12,\n        "dst": 20,\n        "rel": "length_of",\n        "formula": "val(12)",\n        "message_type": "bidirectional"\n      },\n      {\n        "src": 12,\n        "dst": 30,\n        "rel": "length_of",\n        "formula": "val(12)",\n        "message_type": "bidirectional"\n      },\n      {\n        "src": 11,\n        "dst": 20,\n        "rel": "condition_on",\n        "formula": "val(11) == value1",\n        "message_type": "request"\n      },\n      {\n        "src": 11,\n        "dst": 30,\n        "rel": "condition_on",\n        "formula": "val(11) == value2",\n        "message_type": "response"\n      }\n    ]\n  }\n}\n\n## CRITICAL SUCCESS FACTORS\n\n1. **Protocol Agnostic**: No hardcoded assumptions about specific protocols\n2. **Structure First**: Focus on binary layout over semantic meaning\n3. **Concrete Only**: Extract only fields with clear bit positions/sizes\n4. **Relationship Driven**: Use edges to express field interdependencies\n5. **Variant Aware**: Detect and model conditional message structures\n6. **Position Safe**: Avoid circular dependencies and cross-container references\n7. **Hierarchy Complete**: Whenever you add a node, append its ID to the parent `children_ids` so the tree stays connected.\n\n## QUALITY CHECKLIST\n\nBefore returning your result, verify:\n- [ ] Every node has unique numeric node_id\n- [ ] Every node has required message_type field\n- [ ] No self-referential positioning expressions\n- [ ] All selector fields have corresponding variant nodes\n- [ ] Container hierarchy makes logical sense\n- [ ] Size and position expressions are well-formed\n\nBuild a **minimal but correct** structure. Better to have a simple, accurate skeleton than a complex, incorrect tree.\n\n## DOCUMENT SUMMARY (GLOBAL CONTEXT):\n' + overall_summary + '\n\n## DOCUMENTATION TO ANALYZE:\n' + json.dumps(enhanced_sections, indent=2) + '\n\nPlease analyze the above documentation and extract a protocol tree structure following the guidelines above.\nOutput ONLY the JSON object, no other text.'
    if validation_feedback:
        prompt += '\n\n## VALIDATION FEEDBACK FROM PREVIOUS ATTEMPT\n' + validation_feedback.strip() + '\n\nPlease address the validation issues above when generating the protocol tree.'
    message = [{'role': 'system', 'content': 'You are building a protocol format tree. Be specific and comprehensive. CRITICAL: You must respond with valid JSON only. No markdown, no comments, no extra text.'}, {'role': 'user', 'content': prompt + '\n\nIMPORTANT: Respond with ONLY the JSON object, no markdown formatting, no comments.'}]
    return message

def build_patch_refinement_message(tree, marked_sections, batch_start, batch_size, feedback: str | None=None, previous_patch: str | None=None, previous_attempt: dict | None=None, *, mode: str='fix', avoid_summaries: List[str] | None=None, experience: Optional[List[Dict[str, Any]]]=None):
    import json

    def _strict_validator_loop_enabled() -> bool:
        raw = os.getenv('STEP2_STRICT_VALIDATOR_LOOP', '')
        return str(raw).strip().lower() in {'1', 'true', 'yes', 'y', 'on'}

    def _strip_hex_preview_from_issue_description(desc: str) -> str:
        if not desc:
            return desc
        desc = re.sub('\\s+hex=[0-9a-fA-F]+', '', desc)
        desc = re.sub('\\s{2,}', ' ', desc).strip()
        return desc
    tree_json = json.dumps(tree, indent=2)
    sections_json = json.dumps(marked_sections, indent=2)
    pending_lines: List[str] = []
    recent_lines: List[str] = []
    validator_lines: List[str] = []
    followup_lines: List[str] = []
    issues_payload = []
    records_payload = []
    validator_errors = []
    validator_extras = []
    avoid_block = ''
    if avoid_summaries:
        unique_avoids = list(dict.fromkeys(avoid_summaries))[-8:]
        lines = ['### STRATEGY CONSTRAINTS (AVOID REPETITION)', 'The following patch strategies have ALREADY been tried at this state (as siblings) and were rejected.', 'You MUST generate a DIFFERENT approach (e.g., if reparenting failed, try fixing formulas; if formulas failed, try restructuring).', 'DO NOT output the same patch intent again:']
        for s in unique_avoids:
            lines.append(f'- [AVOID] {s}')
        avoid_block = '\n'.join(lines) + '\n'
    if isinstance(previous_attempt, dict):
        issues_payload = previous_attempt.get('pending_issues') or []
        records_payload = previous_attempt.get('recent_records') or []
        validator_errors = previous_attempt.get('validator_errors') or []
        validator_extras = previous_attempt.get('validator_extras') or []
        variant_warnings = [str(w) for w in validator_extras if 'variant condition' in str(w).lower() and 'cannot be satisfied' in str(w).lower()]
        if variant_warnings:
            guidance_msg = "CRITICAL PRIORITY: The validator found unreachable variants (condition cannot be satisfied). You MUST fix the 'condition_on' edges or the selector's constraints so these variants are reachable. Do NOT attempt to fix missing children or length errors inside a variant until its condition is valid."
            followup_lines.append(f'- {guidance_msg}')
            for w in variant_warnings[:3]:
                followup_lines.append(f'  * Focus on fixing this warning: {w}')
            action_msg = "REQUIRED ACTION: Expand the parent selector's 'enum'/'range' constraints to include the value required by the variant, OR correct the 'condition_on' formula if it mismatches the selector."
            followup_lines.append(f'- {action_msg}')
        followup_tasks = previous_attempt.get('followup_tasks') or []
        for task in followup_tasks[:10]:
            followup_lines.append(f'- {task}')
    node_map, depth_map = _build_node_maps(tree)
    sorted_issues = sorted(issues_payload[:12], key=lambda x: _issue_priority(x, node_map, depth_map))
    for issue in sorted_issues:
        if not isinstance(issue, dict):
            continue
        identifier = issue.get('id')
        issue_type = issue.get('type')
        severity = issue.get('severity')
        description = issue.get('description') or 'Unspecified validator issue'
        if _strict_validator_loop_enabled() and (mode or '').strip().lower() == 'traffic_fix':
            description = _strip_hex_preview_from_issue_description(str(description))
        target = issue.get('target')
        detail = description
        if target:
            detail += f' (target: {target})'
        label = f'[{severity}] {issue_type}' if severity or issue_type else 'ISSUE'
        if identifier:
            pending_lines.append(f'- {identifier} {label}: {detail}')
        else:
            pending_lines.append(f'- {label}: {detail}')
    for record in records_payload[:5]:
        if not isinstance(record, dict):
            continue
        summary = record.get('summary') or '(no summary)'
        reward = record.get('reward')
        introduced = record.get('introduced') or []
        resolved = record.get('resolved') or []
        line = f"- {record.get('hash', '')[:8]} {summary}"
        if reward is not None:
            line += f' | reward={reward:.2f}'
        if introduced or resolved:
            line += f' | introduced={len(introduced)} resolved={len(resolved)}'
        recent_lines.append(line)
    for err in validator_errors[:5]:
        validator_lines.append(f'- ERROR: {err}')
    for extra in validator_extras[:5]:
        validator_lines.append(f'- NOTE: {extra}')
    experience_lines: List[str] = []
    if experience:
        for entry in experience:
            packet_idx = entry.get('packet_idx', '?')
            error = entry.get('error') or entry.get('issue') or 'unknown issue'
            action = entry.get('action') or entry.get('strategy') or entry.get('summary') or ''
            experience_lines.append(f'- Packet #{packet_idx}: {error} -> {action}'.strip())
    experience_block = '### EXPERIENCE FROM PREVIOUS PACKETS\n' + ('\n'.join(experience_lines) if experience_lines else 'None') + '\n'
    pending_block = '### PENDING ISSUES\n' + ('\n'.join(pending_lines) if pending_lines else 'None') + '\n'
    recent_block = '### RECENT PATCHES\n' + ('\n'.join(recent_lines) if recent_lines else 'None') + '\n'
    validator_block = '### VALIDATOR NOTES\n' + ('\n'.join(validator_lines) if validator_lines else 'None') + '\n'
    followup_block = '### TARGETED FIX GUIDANCE\n' + ('\n'.join(followup_lines) if followup_lines else 'None') + '\n'
    feedback_block = ''
    if feedback:
        feedback_block = '### FEEDBACK FROM PREVIOUS ITERATION\n' + feedback.strip() + '\n'
    normalized_mode = (mode or 'fix').strip().lower()
    import os as _os
    atomic_env = _os.getenv('STEP2_PATCH_ATOMIC_MODE')
    if atomic_env is None:
        atomic_mode = normalized_mode == 'traffic_fix'
    else:
        atomic_mode = atomic_env.lower() in {'1', 'true', 'yes', 'on'}
    if normalized_mode == 'expand':
        objective_lines = ['Validator issues are currently resolved.', 'Expand the protocol structure to cover documentation gaps, adding nodes or edges even if temporary warnings appear.', 'Prioritise structural completeness and coverage of documented flows before returning to issue cleanup.']
        instructions = ['Operate on the existing tree; do not regenerate it from scratch.', 'Focus on adding or restructuring nodes and edges to cover the documentation, even if this introduces minor validator warnings.', 'Document every structural change in patch_metadata.description so follow-up cleanup can reference it.', 'Avoid deleting existing coverage unless it contradicts the documentation.', 'When deleting edges, use either edge_removes entries (e.g., {"src": "<SRC_NODE_ID>", "dst": "<DST_NODE_ID>", "rel": "length_of"}) or edge_updates entries with update_type="remove" plus edge_identifier; JSON Patch style {"op", "path"} entries are rejected.', 'If the tree already captures the documentation and no structural expansion remains, respond with {}.', 'Return ONLY a JSON object that matches the schema below -- no commentary.']
    else:
        objective_lines = ['Resolve the outstanding validator issues and follow-up tasks for this batch.']
        """
        instructions = ['### CRITICAL: THE HIERARCHY OF TRUTH', '1. **Supreme Authority (Ground Truth)**: The **Documentation** text and the **Traffic Hex Samples** (in issue descriptions) are the absolute truth. Never contradict them.', '2. **The Validator is a tool, not a god**: The validator reports inconsistent states (Symptoms). Its suggestions (e.g., "add edge") are heuristics and can be WRONG if they contradict the Ground Truth.', '3. **Conflict Resolution**: ', '   - **IF** Validator says "Add length_of edge" **BUT** Documentation says "Fixed 2-byte field",', '   - **THEN** the Validator is confused because you defined `size_bits="variable"`.', '   - **ACTION**: Do NOT add the edge. Instead, **FIX the attribute** (set `size_bits=16`). This aligns with Ground Truth AND silences the Validator.', '4. **Evidence-Based Reasoning**: Before every fix, look at the `hex=...` sample. Count the bytes. If the tree structure does not match the bytes, the tree is wrong, regardless of what the validator says.', '### CRITICAL: NO FORWARD REFERENCES', '1. **Time Flow**: A node can ONLY reference nodes that appear **before** it in the stream.', "2. **Prohibited**: Do NOT define a field's size based on a node that comes AFTER it (e.g., do not size a Length field based on the Payload).", '3. **Fix**: If you need to relate Length and Payload, the dependency MUST go from Predecessor (Length) -> Successor (Payload).', 'Formula syntax (validator/interpreter/Z3 share the SAME rules):', '  - Allowed identifiers: val(<ID>), <ID>.size_bits, <ID>.bit_start. Do NOT invent new symbols (e.g., size_bits_1).', '  - Operators: + - * / ( ) and/or/not with == != >= > <= <. NO &&, ||, &, |.', '  - No chained comparisons: write `val(x) >= 1 and val(x) <= 4` (NOT `1 <= val(x) <= 4`).', '  - OR must be fully expanded: GOOD `val(7)==1 or val(7)==2 or val(7)==4 or val(7)==15`; BAD `val(7)==1 || 2 || 4 || 15` (forbidden).', '  - size_bits must be pure arithmetic (no booleans); condition_on must be pure selector predicates (no message_type checks or other fields).', '  - condition_on scope rule: for an edge src->dst with rel="condition_on", the formula may reference ONLY val(src) (plus constants/boolean ops). Referencing val(other_id) is INVALID; if multiple control fields are involved, introduce nested selector/variant routing instead of mixing them in one condition.', '  - Avoid shadow selectors: do NOT create per-variant selector copies like Type_MD5/Type_SHA1 and then gate variants on those. Create ONE shared selector field (Type/AuthType/Opcode) at the correct wire offset, and route mutually-exclusive variants from it.', '  - Length/size_bits/length_of use bits as the unit: if a count field is in bytes, convert with val(<field>)*8; if it is already a bit count, use val(<field>) directly. Do not use reverse-engineering or rounding formulas.', '  - For nodes with `data_type="bytes"` or `node_type="payload"`, do NOT use `range: ... <= value <= ...` to express length (bytes will be treated as a big integer). Constrain length via `size_bits` (e.g., `range: 8 <= size_bits <= 128`, in bits) or rely only on length_of/size_bits expressions.', '  - length_of edges go from the length/count field to the payload; src/dst message_type must match. Put validation/range checks on the length field constraints, not inside length_of.', '  - For length_of/constraints, do NOT use division/rounding or reverse formulas like (val(x)+7)/8. Use forward numeric formulas; if needed, add simple range/enum constraints to the count field.', '  - A parent container's size_bits should equal the sum of its children or be driven by a length_of binding. Do not hide variable children with max(variant.size_bits) or fixed constants; every variable child must have a length_of binding.', '  - Avoid keeping two equivalent payload representations at the same level (e.g., *_Bytes alongside *_Response). Keep a single set of nodes with a clear length chain.', '  - Reserved/Padding/Spare/Unused rows are on-wire placeholders (from tables or line-format descriptions). Do not omit them just because they look semantically empty; missing them shifts all following fields (gap_bits / incomplete parse / read past end). Prefer adding the placeholder fields rather than shifting later fields to 'make it align'.', '  - `reserved_values` describe reserved/unassigned values; they are not a hard constraint that the value must fall in that range. Do not translate them into a `range:` constraint, and do not combine them with `enum:` into mutually-exclusive constraints (e.g., enum=0..8 + range=9..31). Only add hard constraints when the spec explicitly says MUST/SHALL (e.g., MUST be zero): then use `==0` / `range 0..0`.', '  - Forward/self references are prohibited; only reference already-parsed predecessors.', '  - Edges must not be self-referential (src != dst), especially for length_of/condition_on.', '  - Selector routing must target variants (not fields): if a node is node_type="selector", its outgoing condition_on edges MUST point to node_type="variant" containers (never directly to leaf field nodes). Group all fields that share the same selector predicate under ONE variant container and attach a single condition_on edge to that variant.', '  - Each variant must have exactly ONE condition_on from a single selector; do not attach multiple selectors or duplicate formulas to the same variant. Formulas across variants must be mutually exclusive. If you cannot express a clean single condition, return {} instead of emitting multiple edges.', 'If you violate these syntax rules, your patch is invalid-rewrite the formulas into the allowed form.', '### FIX PRIORITY', 'When applying patches, always follow this priority order:', '1. MUST NOT introduce any new issues with severity ERROR.', '2. MUST prioritize fixing existing issues with severity ERROR, especially STRUCTURE and SEMANTICS issues.', '3. Only attempt to fix WARN / HINT issues if this does not introduce any new ERROR and the change is local/simple.', '4. If you cannot fix all issues in one patch, prefer fixing some ERRORs and leave WARNs unresolved rather than risking new ERRORs.', 'Treat the current tree as a draft that may contain structural mistakes. Documentation and validator feedback are the source of truth.', 'It is acceptable to move, merge, or delete nodes when the documentation/validator indicates duplicate headers, mis-parented children, or missing containers.', 'Maintain a single logical root (typically node 0). If validator reports "Multiple root nodes", FIRST reattach the stray node by setting its parent_id and updating the correct parent.children_ids; only delete a root candidate if the documentation clearly says it should not exist.', 'For selector/variant conflicts (Invalid overlap / Non-exclusive conditions):', '  - Preferred: delete generic catch-all variants that lack conditions (e.g., Request_Payload/Response_Payload) and remove all references (parent.children_ids, edges).', '  - If keeping them: add exactly one condition_on per variant with a mutually exclusive formula covering only uncovered cases; do NOT leave unconditional branches alongside conditioned variants.', '  - When feedback mentions Non-exclusive conditions with <SpecificVariant>, prefer cleaning up or adding conditions to the generic variants involved (e.g., Request/Response_Payload) rather than deleting only one or two condition_on edges.', 'When adding/removing condition_on edges, always include src/dst/rel + formula + message_type to ensure precise matching; avoid fuzzy deletes that skip the intended edge.', 'Any time you delete or move a node, synchronize both sides: update parent.children_ids, clear child.parent_id if detached, and remove edges pointing to removed nodes.', 'For selector nodes, add an explicit enum/domain constraint when the documentation provides a bounded set of values. Ensure the enum is consistent with all outgoing condition_on edges (do not exclude values referenced by any branch).', 'Keep the patch focused on resolving the listed pending issues and follow-up tasks; structural repairs (e.g., re-homing Function_Code, deduplicating fields, restoring missing length bindings) are encouraged whenever they directly address the validator feedback.', 'Apply complete updates directly (no subaction splitting).', 'When deleting edges, use either edge_removes entries (e.g., {"src": 18, "dst": 23, "rel": "length_of"}) or edge_updates entries with update_type="remove" plus edge_identifier; JSON Patch style {"op", "path"} entries are rejected.', 'Example edge identifiers shown below are placeholders. Always confirm the correct source/destination IDs from the current tree and validator feedback before deleting a binding, especially for Byte Count -> payload edges.', 'Preserve numeric expressions and message typing rules when updating nodes or edges.', 'If the tree already reflects the documentation and no further fixes are needed, respond with {}.', 'Return ONLY a JSON object that matches the schema below -- no commentary.', '=== PATCH CONSTRAINTS === prefer SMALL, LOCAL changes; modify as few nodes as possible; avoid deleting subtrees or rewriting the root structure.', 'Allowed: update existing node attributes (bit_start, size_bits, message_type), add/update length bindings (length_of/depends_on), and minimal reparenting only to fix INVALID_PARENT issues.', 'Discouraged: deleting many nodes, creating many new nodes at once, or changing selector/root topology. If uncertain, leave unrelated parts untouched.', 'When size_bits is "variable" but a length field exists, keep size_bits as "variable" and add the length binding instead of guessing a fixed size.', 'Do NOT introduce new node_type values outside the allowed set.']
        """
        instructions_text = """### CRITICAL: THE HIERARCHY OF TRUTH
1. Documentation text and traffic hex samples are the ground truth.
2. Validator errors are symptoms; fix the tree to match ground truth.
3. If docs say a field is fixed-size, set size_bits to the constant (do not add length_of).

### CRITICAL: NO FORWARD REFERENCES
- A node can only reference nodes that appear before it on-wire.
- Do not size a Length field based on a Payload that comes later.

### FORMULA SYNTAX (validator/interpreter/Z3)
- Allowed identifiers: val(<ID>), <ID>.size_bits, <ID>.bit_start
- Allowed ops: + - * / ( ) and/or/not with == != >= > <= <
- Forbidden: && || &, |, chained comparisons, message_type checks inside formulas
- OR must repeat full comparisons (e.g., val(7)==1 or val(7)==2)

### PATCH RULES (STRICT)
- Return ONLY a JSON patch object (not a full tree).
- Prefer edge_removes / edge_updates; do NOT use JSON Patch op/path.
- Never create self-loop edges (src == dst).
- Keep patches atomic (one main fix per response).
"""
        instructions = [line.strip() for line in instructions_text.splitlines() if line.strip()]
    if normalized_mode == 'traffic_fix':
        instructions += ['### TRAFFIC ANALYSIS GUIDANCE (CRITICAL):', '- Follow the issue priority provided (higher severity + higher sample hits + earlier nodes first).', "- If you see 'Parsing blocked' or coverage gaps: address sizing/position issues before tweaking enums/ranges.", '- If a leaf field has size_bits="variable" (or missing) AND there is no length_of binding to it, it will consume 0 bytes and create coverage gaps. Use DOCUMENTATION CONTEXT to identify the length/count dependency, then add a length_of edge from the controlling field to that leaf (convert units to bits: bytes*8, words/registers*16, etc).', '=== TRAFFIC ERROR CONTEXT ===', "You will receive structured traffic failures with packet_index, node_id, failure_kind, bit_start, size_bits_eval, total_bits, max_bit_reached, path_node_ids, and context_field_values (values of preceding integer-like fields). Length mismatches also include src/dst/expected/actual bits plus the length_of formula. Some nodes may also include size_bits candidates derived from traffic such as 'val(F) * 8' or '(val(F) - k) * 8'.", '=== PATCH CONSTRAINTS (TRAFFIC) ===', '1) Prefer SMALL, LOCAL changes; focus on nodes mentioned in traffic failures.', '2) Allowed: adjust size_bits or bit_start with simple formulas, tweak constraints (enum/range/expressions), update message_type/data_type when needed, and add/update length_of/condition_on/depends_on edges that control length or presence.', '3) Disallowed: large restructures, deleting subtrees, complex arithmetic (no max/min/conditionals), or new selector topologies unless failures + docs clearly require it.', '4) When candidates are provided for a node, prefer them or a very small variation.', '- If you see candidate-variant failures (oob_seek/oob_read during speculative parsing): FIX those variant size_bits/bit_start issues first. Payload-fill can hide coverage gaps but will not repair broken variants.', '- Use traffic_payload_fill only as a LAST RESORT when the remaining bytes are genuinely undocumented/opaque and no length/count binding can be inferred without introducing routing/structure failures.', "- traffic_payload_fill MUST be a single new bytes-like field (node_type=field, data_type contains 'bytes' or 'byte').", '- traffic_payload_fill MUST be additive-only: use new_nodes only and leave node_updates/new_edges/edge_updates/edge_removes/nodes_to_remove empty (parent linking is automatic via parent_id).', '- For traffic_payload_fill formulas: NEVER reference the *parent* node\'s size_bits (e.g., "<parent_id>.size_bits"); this triggers a circular dependency and will be rejected.', '- For traffic_payload_fill formulas: do NOT use max()/min(). Keep expressions linear and monotonic.', '- Preferred payload fill pattern (use the length_of formula from failures):', '    bit_start = "<last_consumed_leaf>.bit_start + <last_consumed_leaf>.size_bits"', '    size_bits = "(<dst>.bit_start + (<length_of_formula_bits>)) - (<bit_start>)"']
    if atomic_mode:
        instructions = ['Atomic mode: perform exactly one focused change (single node update, single new edge, or single removal).', 'Do not bundle multiple unrelated edits. If multiple fixes are required, return only the first step.'] + instructions
    objective_block = '### CURRENT OBJECTIVE\n' + '\n'.join((f'- {line}' for line in objective_lines)) + '\n'
    instructions_block = '### INSTRUCTIONS\n' + '\n'.join((f'- {text}' for text in instructions)) + '\n'
    format_warning_block = ''
    if isinstance(previous_attempt, dict):
        raw_patch = previous_attempt.get('raw_patch')
        if isinstance(raw_patch, dict):
            edge_updates = raw_patch.get('edge_updates') or []
            if any((isinstance(entry, dict) and ('op' in entry or 'path' in entry) for entry in edge_updates)):
                format_warning_block = '### PATCH FORMAT WARNINGS\n- Previous patch attempted to remove edges using JSON Patch (fields `op`/`path`). This format is unsupported, so no edges were deleted. Use `edge_removes` or `edge_updates` with `edge_identifier` instead.\n'
    issue_examples_block = build_issue_example_block(issues_payload, validator_errors, validator_extras)
    validator_rules = '### VALIDATOR LAWS (NON-NEGOTIABLE)\n1.  **The Containment Law**: A parent node\'s `size_bits` MUST be greater than or equal to the sum of its fixed-size children.\n    * Violation: "Children may exceed parent size".\n    * Fix: Increase parent size or remove/reparent children.\n\n2.  **The Exclusivity Law**: Two variants cannot overlap in physical space (same `bit_start`) UNLESS they have mutually exclusive `condition_on` formulas.\n    * Violation: "Invalid overlap with sibling".\n    * Fix: Add `condition_on` edges to BOTH variants (e.g., `val(x)==1` vs `val(x)==2`).\n\n3.  **The Causality Law (No Future References)**: A node\'s formula can ONLY reference nodes that appear **before** it in the parsing order.\n    * Violation: "Reference to unparsed node".\n    * Fix: Remove forward references.\n\n4.  **The Connectivity Law**: If a formula references `val(X)`, there MUST be a corresponding graph edge from node X to the current node.\n    * Violation: "References val(X) but no ... edge exists".\n    * Fix: Add the missing `length_of` or `condition_on` edge.\n\n5.  **The Type Law**:\n    * `length_of` edges determine **size**.\n    * `condition_on` edges determine **existence/variant selection**.\n    * Do not mix them.\n\n6.  **The "Unknown" Law**: If a container\'s size depends on variable-sized children (payloads), its size is `variable`. Do NOT force a static formula unless documentation/traffic proves it.\n'
    validator_rules_block = validator_rules + '\n'
    patch_format = '\n{\n  "patch_metadata": {\n    "description": "...",\n    "intent": "..."\n  },\n  "new_nodes": [],\n  "nodes_to_remove": [],\n  "node_updates": [\n    { "node_id": 17, "property": "size_bits", "value": "(val(5)-2)*8", "reason": "..." },\n    { "node_id": 9, "updates": { "constraints": ["enum: 1|2|3"] }, "reason": "..." }\n  ],\n  "new_edges": [\n    { "src": 5, "dst": 17, "rel": "length_of", "formula": "val(5)*8" },\n    { "src": 4, "dst": 23, "rel": "condition_on", "formula": "val(4)==3", "message_type": "request" }\n  ],\n  "edge_updates": [\n    {\n      "update_type": "modify|remove",\n      "edge_identifier": { "src": "<SRC_NODE_ID>", "dst": "<DST_NODE_ID>", "rel": "length_of" },\n      "new_properties": {\n        "formula": "<UPDATED_FORMULA>"\n      }\n    }\n  ],\n  "edge_removes": [\n    { "src": "<SRC_NODE_ID>", "dst": "<DST_NODE_ID>", "rel": "length_of" }\n  ],\n  "validation_notes": []\n}\n'
    prompt_template = '## PATCH REFINEMENT OBJECTIVE\n\n    ### CURRENT TREE\n    {tree_json}\n\n    {validator_rules_block}\n\n    {experience_block}\n\n    {objective_block}{pending_block}\n    {recent_block}\n    {validator_block}\n    {followup_block}{feedback_block}\n    {avoid_block}\n    ### DOCUMENTATION CONTEXT (FOCUS {batch_start}-{batch_end})\n    {sections_json}\n\n    {instructions_block}{issue_examples_block}\n    ### PATCH SCHEMA (RETURN JSON ONLY)\n    {patch_format}\n    '
    prompt = prompt_template.format(tree_json=tree_json, validator_rules_block=validator_rules_block, experience_block=experience_block, objective_block=objective_block, pending_block=pending_block, recent_block=recent_block, validator_block=validator_block, followup_block=followup_block, feedback_block=feedback_block + format_warning_block, avoid_block=avoid_block, batch_start=batch_start, batch_end=batch_start + batch_size - 1, sections_json=sections_json, instructions_block=instructions_block, issue_examples_block='\n' + issue_examples_block if issue_examples_block else '', patch_format=patch_format)
    message = [{'role': 'system', 'content': 'You are a protocol tree patch generator. Generate incremental JSON patches only. If no patch is needed, return {}.'}, {'role': 'user', 'content': prompt}]
    return message
