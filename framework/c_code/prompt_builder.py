from __future__ import annotations
import json
import textwrap
from typing import Dict, List, Optional
from .constraint_contract import build_contract, format_contract_for_prompt
from .host_ir_schema import ArtifactSpec, HostIR, ParseAPIOperation, SymbolSpec
from .parse_ir import Edge, ParseIR

def _format_nodes(parse_ir: ParseIR) -> str:
    lines: List[str] = []
    for node_id in sorted(parse_ir.nodes.keys()):
        node = parse_ir.nodes[node_id]
        children = ','.join((str(cid) for cid in node.children_ids)) if node.children_ids else '-'
        constraints = '; '.join(node.constraints) if node.constraints else '-'
        desc = node.description or '-'
        if len(desc) > 80:
            desc = desc[:77] + '...'
        bo = node.byte_order or '-'
        stop = getattr(node, 'stop_condition', None) or '-'
        max_items = getattr(node, 'max_items', None)
        max_items_str = str(max_items) if max_items is not None else '-'
        lines.append(f'{node.id}\t{name_clean(node.name)}\t{node.kind}\t{node.data_type}\tstart={node.bit_start}\tsize_bits={node.size_bits}\tparent={node.parent_id}\tchildren=[{children}]\tconstraints=[{constraints}]\tmessage_type={node.message_type}\tstop_condition={stop}\tmax_items={max_items_str}\tdesc={desc}\tbyte_order={bo}')
    return '\n'.join(lines) if lines else '(no nodes)'

def _format_edges(edges: List[Edge]) -> str:
    lines: List[str] = []
    for edge in sorted(edges, key=lambda e: (e.src, e.dst, e.rel)):
        lines.append(f'{edge.src} -> {edge.dst}\trel={edge.rel}\tformula={edge.formula}\tmessage_type={edge.message_type}')
    return '\n'.join(lines) if lines else '(no edges)'

def _format_artifacts(artifacts: List[ArtifactSpec]) -> str:
    lines: List[str] = []
    for art in artifacts:
        lines.append(f'- id={art.id}, filename_template={art.filename_template}, language={art.language}, role={art.role}, kind={art.kind}, build_src={art.build_src}')
    return '\n'.join(lines) if lines else '(no artifacts specified)'

def _format_symbols(symbols: List[SymbolSpec]) -> str:
    lines: List[str] = []
    for sym in symbols:
        used = ','.join(sym.used_in) if sym.used_in else '-'
        lines.append(f'- {sym.name} (visibility={sym.visibility}, defined_in={sym.defined_in}, used_in=[{used}])')
    return '\n'.join(lines) if lines else '(no symbols specified)'

def _format_parse_api(ops: List[ParseAPIOperation]) -> str:
    lines: List[str] = []
    for op in ops:
        desc = op.description.replace('\n', ' ') if op.description else ''
        lines.append(f'- {op.name} ({op.kind}): {op.signature} :: {desc}')
    return '\n'.join(lines) if lines else '(no parse_api ops specified)'

def _parse_ir_json(parse_ir: ParseIR) -> str:
    nodes_data: List[Dict[str, object]] = []
    for node in parse_ir.nodes.values():
        payload: Dict[str, object] = {'id': node.id, 'name': name_clean(node.name), 'kind': node.kind, 'data_type': node.data_type, 'bit_start': node.bit_start, 'size_bits': node.size_bits, 'message_type': node.message_type, 'parent_id': node.parent_id, 'children_ids': node.children_ids, 'constraints': node.constraints, 'description': node.description, 'byte_order': node.byte_order}
        if getattr(node, 'stop_condition', None):
            payload['stop_condition'] = getattr(node, 'stop_condition')
        if getattr(node, 'max_items', None) is not None:
            payload['max_items'] = getattr(node, 'max_items')
        nodes_data.append(payload)
    edges_data: List[Dict[str, object]] = []
    for edge in parse_ir.edges:
        edges_data.append({'src': edge.src, 'dst': edge.dst, 'rel': edge.rel, 'formula': edge.formula, 'message_type': edge.message_type})
    payload = {'protocol_name': parse_ir.protocol_name, 'root_id': parse_ir.root_id, 'nodes': nodes_data, 'edges': edges_data}
    return json.dumps(payload, ensure_ascii=False, indent=2)

def name_clean(name: str) -> str:
    return name.replace('\t', ' ').strip()

def build_codegen_prompt(parse_ir: ParseIR, host_ir: HostIR, target_protocol_name: Optional[str]=None, api_doc_text: Optional[str]=None, codegen_profile: Optional[Dict[str, object]]=None) -> str:
    nodes_table = _format_nodes(parse_ir)
    edges_table = _format_edges(parse_ir.edges)
    artifacts_text = _format_artifacts(host_ir.artifacts)
    symbols_text = _format_symbols(host_ir.symbols)
    parse_api_text = _format_parse_api(host_ir.parse_api)
    extras_json = json.dumps(host_ir.extras or {}, ensure_ascii=False, indent=2)
    parse_ir_json = _parse_ir_json(parse_ir)
    target_proto = target_protocol_name or parse_ir.protocol_name or 'unknown_protocol'
    api_doc_snippet = (api_doc_text or '(no api_doc found)').strip()
    if len(api_doc_snippet) > 6000:
        api_doc_snippet = api_doc_snippet[:6000] + '\n... (truncated)'
    profile_json = '(none)'
    if isinstance(codegen_profile, dict) and codegen_profile:
        profile_json = json.dumps(codegen_profile, ensure_ascii=False, indent=2)
    output_schema = textwrap.dedent('\nFirst output a summary block using EXACTLY this fence and schema:\n```summary\n{\n  "artifacts_used": ["artifact_id", ...],\n  "public_symbols": ["symbol_name", ...],\n  "field_to_code_mapping": [\n    { "format_path": "path.from.root", "artifact": "artifact_id", "operation": "container_op|field_op|selector_op|helper" },\n    { "format_path": "RootLayer.Header.LeafField", "artifact": "dissector_source", "operation": "field_op" },\n    { "format_path": "RootLayer.Header", "artifact": "dissector_source", "operation": "container_op" }\n  ]\n}\n```\nThen output EACH artifact\'s content in its own fence:\n```file:rendered_filename\n<complete file content>\n```\nNo prose, no extra text.\n        ').strip()
    constraints = textwrap.dedent('\nHard constraints (host-agnostic):\n- Artifacts: you may ONLY emit artifacts declared in host_ir.artifacts; do not invent or drop artifacts. Use artifact ids in summary; render filenames using the provided filename_template.\n- Build role: kind=="source" && build_src==true files must be included in build scripts; kind=="header" must NOT be compiled directly.\n- Symbols: visibility=="public" must be declared in interface artifacts (headers/modules) and defined in their designated source artifact; visibility=="internal" must stay private.\n- Format tree fidelity: every Parse-IR leaf field must be parsed at its specified span; keep parent/child hierarchy intact; do not reuse the same field handle for multiple regions; do not wrap a field node as a container. For kind=="tlv_seq" nodes, parse the template leaf fields once per item occurrence (repeated parsing).\n- Operation mapping: for Parse-IR nodes with kind=="field", you MUST ONLY use operations of kind "field_op" in field_to_code_mapping; never use "container_op" or "selector_op" for these leaf fields. Container-like nodes (kind in ["protocol","header","payload","container","variant","selector","tlv_seq"]) may use "container_op" or "selector_op" as appropriate, but MUST NOT be mapped as "field_op" directly.\n- Selector/length edges: respect rel=condition_on and rel=length_of exactly as given in Parse-IR; do not reorder fields or ignore offsets/lengths.\n- TLV-seq semantics: when kind=="tlv_seq", treat its children as the TLV item template and parse it repeatedly from the current cursor, stopping when the node description/constraints indicate an end-of-list condition (e.g., stop_condition) or when the enclosing buffer ends.\n- API docs: honor constraints/field meanings described in api_doc when mapping to format_tree nodes; do not ignore documented on-wire fields unless clearly out-of-band.\n- Constraints & validation: Parse-IR node.constraints and normative API-doc rules (MUST/SHALL) are NOT optional. Implement them as runtime validation checks. If a check fails, emit a host-idiomatic diagnostic signal (e.g., Wireshark Expert Info / Wireshark Lua expert info / Zeek+Spicy parse failure) and stop parsing the packet ONLY when continuing would be unsafe.\n- Bytes/payload semantics: if a node represents raw bytes (kind=="payload" or data_type indicates bytes/blob), NEVER implement length bounds as numeric "value" range constraints on the bytes themselves. Use size_bits bounds, length fields, and rel=length_of sizing formulas instead.\n- Codegen profile: if <codegen_profile> is provided, treat it as authoritative additional constraints (e.g., direction rules and generic parsing heuristics like count-prefixed payload handling). Do NOT ignore it.\n- Implicit fields: you MAY introduce extra on-wire fields ONLY when required by <codegen_profile> (e.g., splitting a count/length byte from a count-prefixed blob/array). Do NOT remove or skip any Parse-IR leaf fields; keep offsets/lengths consistent.\n        ').strip()
    if host_ir.host_name.lower() in {'wireshark_c', 'wireshark', 'wireshark-c'}:
        constraints += '\n\n' + textwrap.dedent('\nWireshark-C specific constraints:\n- Request/Response direction MUST follow Parse-IR message_type (request/response/bidirectional).\n  If you register the dissector on a known TCP/UDP port, classify direction via transport:\n    * request: pinfo->destport == <registered_port>\n    * response: pinfo->srcport == <registered_port>\n  Do NOT use ad-hoc heuristics such as pinfo->match_uint comparisons.\n  BAD (forbidden):\n    bool is_request = (pinfo->srcport == pinfo->match_uint);\n  GOOD:\n    const guint16 registered_port = <registered_port>;\n    bool is_request = (pinfo->destport == registered_port);\n    bool is_response = (pinfo->srcport == registered_port);\n- Always bounds-check before reading: use tvb_reported_length_remaining()/tvb_captured_length_remaining()\n  and guard against truncated frames.\n- Constraint feedback signals: do NOT silently return on constraint violations that can be reported safely.\n  Prefer adding Expert Info on the relevant proto_item / subtree:\n    - include <epan/expert.h>, define/register expert fields, then call expert_add_info_format(...)\n  Only abort parsing early for unsafe truncation/bounds conditions.\n- When Parse-IR provides bit_start/size_bits, ensure the dissection offsets match those byte positions\n  (bit_start/8). Do not assume all fields are strictly sequential if bit_start jumps.\n            ').strip()
    if host_ir.host_name.lower() in {'wireshark_lua', 'wireshark-lua'}:
        constraints += '\n\n' + textwrap.dedent('\nWireshark-Lua specific constraints:\n- Request/Response direction MUST follow Parse-IR message_type (request/response/bidirectional).\n  If you register the dissector on a known TCP/UDP port, classify direction via transport:\n    * request: pkt.dst_port == <registered_port>\n    * response: pkt.src_port == <registered_port>\n  Do NOT use ad-hoc heuristics.\n- Always bounds-check before reading slices: guard buf:len() and use early returns ONLY for unsafe truncation.\n- Constraint feedback signals: on constraint violations (invalid enum/range/length), report via Expert Info:\n    subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "...")\n  Do NOT silently return for semantic violations when you can keep parsing/mark malformed safely.\n            ').strip()
    if host_ir.host_name.lower() in {'zeek_spicy', 'zeek-spicy'}:
        constraints += '\n\n' + textwrap.dedent('\nZeek+Spicy specific constraints:\n- Implement Parse-IR constraints as Spicy-level checks:\n  - hard invariants MUST use `&requires` so invalid packets fail parsing (clear signal for evaluation/export).\n  - length bindings MUST use `&size=...` / length_of equivalents; do NOT read past declared bounds.\n- Prefer failing a single packet cleanly (constraint violation) over producing silently wrong fields.\n- Bit-level fields MUST respect Parse-IR `bit_start`/`size_bits` exactly:\n  - If `size_bits` is not a multiple of 8, you MUST parse the field via `bitfield(N) { ... }` and select the correct bit range(s).\n  - Do NOT approximate sub-byte fields by reading whole bytes (e.g., do NOT parse a 4-bit field as `uint8` and then validate its range).\n  - Do NOT use guessed syntax like `uint8 &bit-order=... { ... }` or `uint8(4)`; use `bitfield(N)` plus `&bit-order=spicy::BitOrder::{MSB0,LSB0}`.\n  - Pack contiguous sub-byte fields that share the same underlying byte(s) into a single `bitfield(8)` (or `bitfield(16)`) and map ranges to match the intended semantics.\n    Example (TCP-style nibble field at MSB side):\n      first_byte: bitfield(8) {\n          data_offset: 0..3;   # MSB nibble (with &bit-order=MSB0)\n          reserved: 4..7;\n      } &bit-order=spicy::BitOrder::MSB0;\n    Then validate `self.first_byte.data_offset` (not the whole byte).\n            ').strip()
    if host_ir.host_name.lower() in {'scapy'}:
        constraints += '\n\n' + textwrap.dedent('\nScapy specific constraints:\n- Implement the protocol as one or more Scapy Packet layers (class <Name>(Packet)).\n- Use `fields_desc = [...]` with Scapy Field objects; do NOT parse by manual slicing without\n  representing the on-wire leaf fields as Scapy Fields.\n- Length fields must be dissected as standalone leaf fields (e.g., FieldLenField/ShortField/etc.)\n  and then used to bound subsequent variable-length fields using StrLenField/PacketLenField/\n  PacketListField (avoid "eating" the length inside a blob parser).\n- Selector/condition fields must be dissected as standalone leaf fields, and optional/variant\n  parsing must be expressed via ConditionalField and/or separate Packet variants.\n- If <codegen_profile> provides registration ports for scapy, you MUST register using bind_layers\n  on BOTH directions:\n    bind_layers(TCP, Proto, dport=PORT); bind_layers(TCP, Proto, sport=PORT)\n    bind_layers(UDP, Proto, dport=PORT); bind_layers(UDP, Proto, sport=PORT)\n- Keep module import side effects minimal: class definitions + bind_layers only; no file IO.\n            ').strip()
    contract_items = build_contract(parse_ir)
    constraints += '\n\n' + textwrap.dedent(f'\n<tool_constraint_contract>\n{format_contract_for_prompt(host_name=host_ir.host_name, items=contract_items)}\n</tool_constraint_contract>\n        ').strip()
    return textwrap.dedent(f'\nYou are a code generation agent. Produce complete plugin source files for host "{host_ir.host_name}".\n- Plugin kind: {host_ir.plugin_kind}\n- Target protocol name for this run: {target_proto}\n- Parse-IR protocol name: {parse_ir.protocol_name}\n- Inputs are authoritative specs: format_tree (Parse-IR), host_ir, api_doc.\n\n<format_tree as table>\n{nodes_table}\n\n<format_tree edges>\n{edges_table}\n\n<format_tree JSON>\n{parse_ir_json}\n\n<host_ir.artifacts>\n{artifacts_text}\n\n<host_ir.symbols>\n{symbols_text}\n\n<host_ir.parse_api>\n{parse_api_text}\n\n<host_ir.summary>\n{host_ir.summary}\n\n<host_ir.rules>\n{host_ir.rules}\n\n<host_ir.templates>\n{host_ir.templates}\n\n<host_ir.extras>\n{extras_json}\n\n<codegen_profile>\n{profile_json}\n\n<api_doc>\n{api_doc_snippet}\n\n{constraints}\n\nOutput format (strict):\n{output_schema}\n').strip()

def build_doc_summary_codegen_prompt(*, protocol_name: str, document_summary: str, host_ir: HostIR, target_protocol_name: Optional[str]=None, api_doc_text: Optional[str]=None, codegen_profile: Optional[Dict[str, object]]=None, constraints_contract: Optional[str]=None) -> str:
    artifacts_text = _format_artifacts(host_ir.artifacts)
    symbols_text = _format_symbols(host_ir.symbols)
    parse_api_text = _format_parse_api(host_ir.parse_api)
    extras_json = json.dumps(host_ir.extras or {}, ensure_ascii=False, indent=2)
    target_proto = target_protocol_name or protocol_name or 'unknown_protocol'
    doc_snippet = (document_summary or '(no document summary found)').strip()
    if len(doc_snippet) > 12000:
        doc_snippet = doc_snippet[:12000] + '\n... (truncated)'
    api_doc_snippet = (api_doc_text or '').strip()
    if not api_doc_snippet:
        api_doc_snippet = '(no api_doc provided)'
    if len(api_doc_snippet) > 6000:
        api_doc_snippet = api_doc_snippet[:6000] + '\n... (truncated)'
    profile_json = '(none)'
    if isinstance(codegen_profile, dict) and codegen_profile:
        profile_json = json.dumps(codegen_profile, ensure_ascii=False, indent=2)
    output_schema = textwrap.dedent('\nFirst output a summary block using EXACTLY this fence and schema:\n```summary\n{\n  "artifacts_used": ["artifact_id", ...],\n  "public_symbols": ["symbol_name", ...],\n  "field_to_code_mapping": [\n    { "format_path": "Your.Logical.Path", "artifact": "artifact_id", "operation": "container_op|field_op|selector_op|helper" }\n  ]\n}\n```\nThen output EACH artifact\'s content in its own fence:\n```file:rendered_filename\n<complete file content>\n```\nNo prose, no extra text.\n        ').strip()
    constraints = textwrap.dedent('\nHard constraints (host-agnostic):\n- Artifacts: you may ONLY emit artifacts declared in host_ir.artifacts; do not invent or drop artifacts. Use artifact ids in summary; render filenames using the provided filename_template.\n- Build role: kind=="source" && build_src==true files must be included in build scripts; kind=="header" must NOT be compiled directly.\n- Symbols: visibility=="public" must be declared in interface artifacts (headers/modules) and defined in their designated source artifact; visibility=="internal" must stay private.\n- Protocol fidelity: treat <document_summary> as the ONLY authoritative protocol-format spec (no format_tree will be provided). Infer field structure, offsets, lengths, and variants conservatively.\n- Robustness: always bounds-check before reading; handle truncated frames safely (mark malformed or stop parsing when unsafe).\n- Registration: register a dissector for the Target protocol name so that `tshark -Y <filter_name>` works (filter_name == target protocol).\n- Codegen profile: if <codegen_profile> is provided, treat it as authoritative extra constraints (ports/direction rules/payload handling). Do NOT ignore it.\n        ').strip()
    if host_ir.host_name.lower() in {'wireshark_c', 'wireshark', 'wireshark-c'}:
        constraints += '\n\n' + textwrap.dedent('\nWireshark-C specific constraints:\n- Always bounds-check before reading: use tvb_reported_length_remaining()/tvb_captured_length_remaining()\n  and guard against truncated frames.\n- Constraint feedback signals: do NOT silently return on semantic violations that can be reported safely.\n  Prefer adding Expert Info on the relevant proto_item / subtree; only abort early for unsafe truncation.\n- Constraint alert tags: when you detect a semantic violation (invalid enum/range/length mismatch/truncation),\n  include the substring `BS_CONSTRAINT` in the Expert Info message (optionally add a short id, e.g. `BS_CONSTRAINT <field>_<rule>`).\n            ').strip()
    if host_ir.host_name.lower() in {'wireshark_lua', 'wireshark-lua'}:
        constraints += '\n\n' + textwrap.dedent('\nWireshark-Lua specific constraints:\n- Always bounds-check before reading slices: guard buf:len() and use early returns ONLY for unsafe truncation.\n- Constraint feedback signals: on semantic violations, report via Expert Info:\n    subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "...")\n  Do NOT silently return for semantic violations when you can keep parsing/mark malformed safely.\n- Constraint alert tags: when you detect a semantic violation (invalid enum/range/length mismatch/truncation),\n  include the substring `BS_CONSTRAINT` in the Expert Info message (optionally add a short id, e.g. `BS_CONSTRAINT <field>_<rule>`).\n            ').strip()
    if host_ir.host_name.lower() in {'zeek_spicy', 'zeek-spicy'}:
        constraints += '\n\n' + textwrap.dedent('\nZeek+Spicy specific constraints:\n- Prefer failing a single packet cleanly (constraint violation) over producing silently wrong fields.\n- Use `&requires` / `&size` and explicit parsing structure; do not read past bounds.\n            ').strip()
    if host_ir.host_name.lower() in {'scapy'}:
        constraints += '\n\n' + textwrap.dedent('\nScapy specific constraints:\n- Implement the protocol as one or more Scapy Packet layers (class <Name>(Packet)).\n- Use `fields_desc = [...]` with Scapy Field objects; do NOT parse by manual slicing without\n  representing on-wire fields as Scapy Fields.\n            ').strip()
    contract_text = (constraints_contract or '').strip()
    if contract_text:
        constraints += '\n\n' + textwrap.dedent(f'\nConstraint alerting contract (exp_constraint):\n- If the contract below is provided, implement the runtime validation checks it describes.\n- When a listed constraint is VIOLATED, emit the tag EXACTLY as a substring: `BS_CONSTRAINT <id>`.\n- Do NOT emit tags on success.\n\n<constraints_contract>\n{contract_text}\n            ').strip()
    return textwrap.dedent(f'\nYou are a code generation agent. Produce complete plugin source files for host "{host_ir.host_name}".\n- Plugin kind: {host_ir.plugin_kind}\n- Target protocol name for this run: {target_proto}\n- Input spec: document_summary only (no Parse-IR)\n\n<document_summary>\n{doc_snippet}\n\n<host_ir.artifacts>\n{artifacts_text}\n\n<host_ir.symbols>\n{symbols_text}\n\n<host_ir.parse_api>\n{parse_api_text}\n\n<host_ir.summary>\n{host_ir.summary}\n\n<host_ir.rules>\n{host_ir.rules}\n\n<host_ir.templates>\n{host_ir.templates}\n\n<host_ir.extras>\n{extras_json}\n\n<codegen_profile>\n{profile_json}\n\n<api_doc>\n{api_doc_snippet}\n\n{constraints}\n\nOutput format (strict):\n{output_schema}\n').strip()
