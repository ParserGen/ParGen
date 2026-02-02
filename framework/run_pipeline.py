from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Sequence

logger = logging.getLogger(__name__)

PACKAGE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from framework.a_doc.pipeline import DocumentPipeline, DocumentPipelineConfig
from framework.b_tree.fix_agent.step2_fix import run_step2_fix
from framework.b_tree.pipeline import FormatTreeConfig, FormatTreePipeline
from framework.b_tree.run_traffic_fix import run_traffic_fix
from framework.c_code.llm_client import LLMConfig as StageCLLMConfig
from framework.c_code.stage_c_pipeline import StageCConfig, run_stage_c
from framework.config_manager import load_api_keys
from framework.logging_utils import setup_logging
from framework.paths import DATA_DIR, DEFAULT_API_CONFIG


@dataclass
class ProtocolPaths:
    root: Path

    def __post_init__(self) -> None:
        self.inputs_dir = self.root / "inputs"
        self.outputs_dir = self.root / "outputs"
        self.logs_dir = self.root / "logs"
        self.cache_dir = self.root / "cache"

        self.stage_a_dir = self.outputs_dir / "stage_a"
        self.stage_b_dir = self.outputs_dir / "stage_b"
        self.stage_c_dir = self.outputs_dir / "stage_c"
        self.step2_results_dir = self.stage_b_dir / "step2_results"

        self.pdfs_dir = self.inputs_dir / "pdfs"
        self.traffic_dir = self.inputs_dir / "traffic"
        self.host_docs_root = self.inputs_dir / "host_docs"

        for path in (
            self.inputs_dir,
            self.outputs_dir,
            self.logs_dir,
            self.cache_dir,
            self.stage_a_dir,
            self.stage_b_dir,
            self.stage_c_dir,
            self.step2_results_dir,
            self.pdfs_dir,
            self.traffic_dir,
            self.host_docs_root,
        ):
            path.mkdir(parents=True, exist_ok=True)

    @property
    def sections_file(self) -> Path:
        return self.stage_a_dir / "document_sections.json"

    @property
    def raw_sections_file(self) -> Path:
        return self.stage_a_dir / "document_sections_raw.json"

    @property
    def format_tree_file(self) -> Path:
        return self.stage_b_dir / "format_tree.json"

    @property
    def traffic_fixed_tree_file(self) -> Path:
        return self.step2_results_dir / "traffic_fixed_tree.json"

    @property
    def traffic_file(self) -> Path:
        candidates = [
            self.traffic_dir / f"traffic_{self.root.name}.txt",
            self.traffic_dir / "traffic.txt",
            self.root / "traffic.txt",
            self.root / f"traffic_{self.root.name}.txt",
        ]
        for cand in candidates:
            if cand.exists():
                return cand
        return candidates[0]

    def host_docs_dir_for(self, host_name: str) -> Path:
        return self.host_docs_root / host_name


def _load_sections_file(path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and isinstance(payload.get("sections"), list):
        payload = payload["sections"]
    if not isinstance(payload, list):
        raise ValueError(f"Sections JSON must be a list or contain 'sections': {path}")
    out: list[dict] = []
    for item in payload:
        if isinstance(item, dict):
            out.append(item)
        else:
            out.append({"content": str(item)})
    return out


def _write_sections(path: Path, sections: Sequence[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"sections": list(sections), "generated_at": int(time.time())}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _find_pdfs(paths: ProtocolPaths, explicit: Optional[Sequence[Path]]) -> list[Path]:
    if explicit:
        return [Path(p) for p in explicit]
    if paths.pdfs_dir.exists():
        pdfs = sorted(paths.pdfs_dir.glob("*.pdf"))
        if pdfs:
            return pdfs
    legacy = paths.root / "pdfs"
    if legacy.exists():
        pdfs = sorted(legacy.glob("*.pdf"))
        if pdfs:
            return pdfs
    return []


def run_stage_a(*, paths: ProtocolPaths, pdfs: Sequence[Path], llm_api_key: str) -> None:
    logger.info("[Stage A] Document extraction")
    pipeline = DocumentPipeline(DocumentPipelineConfig(llm_api_key=llm_api_key))
    merged_sections: list[dict] = []
    merged_raw: list[dict] = []
    for pdf in pdfs:
        result = pipeline.process_pdf(Path(pdf))
        if not isinstance(result, dict) or not bool(result.get("success")):
            msg = None
            if isinstance(result, dict):
                msg = result.get("error") or result.get("message")
            raise RuntimeError(f"Stage A failed for {pdf}: {msg or result}")
        outputs = result.get("output_files") or {}
        llm_results = outputs.get("llm_results")
        raw_data = outputs.get("raw_data")
        if not llm_results or not raw_data:
            raise RuntimeError(f"Stage A did not return expected output_files for {pdf} (keys={list(outputs.keys())})")
        merged_sections.extend(_load_sections_file(Path(str(llm_results))))
        merged_raw.extend(_load_sections_file(Path(str(raw_data))))
    _write_sections(paths.sections_file, merged_sections)
    _write_sections(paths.raw_sections_file, merged_raw)
    logger.info("  sections: %s", paths.sections_file)
    logger.info("  raw: %s", paths.raw_sections_file)


def run_stage_b(*, paths: ProtocolPaths, sections_file: Path, raw_sections_file: Path, args: argparse.Namespace) -> Path:
    logger.info("[Stage B] Format tree construction")
    cfg = FormatTreeConfig(
        sections_file=sections_file,
        raw_file=raw_sections_file,
        initial_llm_model=getattr(args, "stage_b_initial_model", None),
        initial_llm_temperature=getattr(args, "stage_b_initial_temperature", None),
        initial_llm_max_tokens=getattr(args, "stage_b_initial_max_tokens", None),
        refine_llm_model=getattr(args, "stage_b_model", None),
        refine_llm_temperature=getattr(args, "stage_b_temperature", None),
        refine_llm_max_tokens=getattr(args, "stage_b_max_tokens", None),
    )
    tree = FormatTreePipeline(cfg).build()
    if tree is None:
        raise RuntimeError("Stage B returned no tree")
    payload: Any = tree
    if hasattr(tree, "to_dict"):
        payload = tree.to_dict()
    paths.format_tree_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    logger.info("  tree: %s", paths.format_tree_file)
    return paths.format_tree_file


def run_stage_c(*, tree_path: Path, paths: ProtocolPaths, args: argparse.Namespace) -> None:
    logger.info("[Stage C] Host-IR driven code generation")
    output_dir = Path(args.stage_c_output_dir) if args.stage_c_output_dir else paths.stage_c_dir
    host_docs_dir = Path(args.stage_c_host_docs) if args.stage_c_host_docs else paths.host_docs_dir_for(args.stage_c_host)
    llm_cfg = StageCLLMConfig(provider="anthropic", model=args.stage_c_model, temperature=args.stage_c_temperature, max_tokens=args.stage_c_max_tokens)
    cfg = StageCConfig(
        format_tree_path=tree_path,
        host_name=args.stage_c_host,
        protocol_family=args.stage_c_protocol_family or args.protocol,
        host_docs_dir=host_docs_dir,
        output_dir=output_dir,
        host_ir_cache_path=Path(args.stage_c_host_ir_cache) if args.stage_c_host_ir_cache else None,
        codegen_profile_path=Path(args.stage_c_codegen_profile) if args.stage_c_codegen_profile else None,
        llm_config=llm_cfg,
        contract_repair_max_rounds=int(args.stage_c_contract_repair_max_rounds or 2),
    )
    summary = run_stage_c(cfg)
    for key, val in summary.items():
        logger.info("  - %s: %s", key, val)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ParGen core pipeline (Stage A -> B -> optional fix -> optional traffic fix -> C)")
    parser.add_argument("--protocol", default="modbus", help="Protocol name (used under framework/data when --root is unset)")
    parser.add_argument("--root", type=Path, default=None, help="Protocol root directory (overrides framework/data/<protocol>)")
    parser.add_argument("--pdf", dest="pdfs", action="append", type=Path, help="PDF path (repeatable). Defaults to inputs/pdfs/*.pdf under the protocol root")
    parser.add_argument("--api-key", default=None, help="LLM API key for Stage A (overrides config/env)")
    parser.add_argument("--config", type=Path, default=DEFAULT_API_CONFIG, help="API config JSON (for env key injection)")
    parser.add_argument("--sections-file", type=Path, default=None, help="Pre-extracted sections JSON (skips Stage A)")
    parser.add_argument("--raw-sections-file", type=Path, default=None, help="Pre-extracted raw sections JSON (skips Stage A)")
    parser.add_argument("--force-stage-a", action="store_true", help="Run Stage A even if sections files exist")
    parser.add_argument("--force-stage-b", action="store_true", help="Rebuild Stage B even if format_tree.json exists")
    parser.add_argument("--no-step2-fix", dest="enable_step2_fix", action="store_false", default=True, help="Disable syntax-only Step2 fix")
    parser.add_argument("--no-traffic-fix", dest="enable_traffic_fix", action="store_false", default=True, help="Disable traffic-aware fix loop")
    parser.add_argument("--traffic", type=Path, default=None, help="Traffic hex dump path (defaults to inputs/traffic/traffic*.txt)")
    parser.add_argument("--traffic-max-packets", type=int, default=0, help="Max packets for traffic fix (0 = no limit)")
    parser.add_argument("--traffic-max-llm-calls", type=int, default=20, help="Max LLM calls for traffic fix")
    parser.add_argument("--stage-b-initial-model", type=str, default=None, help="LLM model for Stage B initial tree")
    parser.add_argument("--stage-b-initial-temperature", type=float, default=None, help="LLM temperature for Stage B initial tree")
    parser.add_argument("--stage-b-initial-max-tokens", type=int, default=None, help="LLM max tokens for Stage B initial tree")
    parser.add_argument("--stage-b-model", type=str, default=None, help="LLM model for Stage B refinement")
    parser.add_argument("--stage-b-temperature", type=float, default=None, help="LLM temperature for Stage B refinement")
    parser.add_argument("--stage-b-max-tokens", type=int, default=None, help="LLM max tokens for Stage B refinement")
    parser.add_argument("--skip-stage-c", action="store_true", help="Skip Stage C code generation")
    parser.add_argument("--stage-c-host", default="wireshark_c", help="Stage C host backend name (e.g., wireshark_c)")
    parser.add_argument("--stage-c-host-docs", type=Path, default=None, help="Host docs directory (defaults to inputs/host_docs/<host>)")
    parser.add_argument("--stage-c-output-dir", type=Path, default=None, help="Stage C output directory (defaults to outputs/stage_c)")
    parser.add_argument("--stage-c-host-ir-cache", type=Path, default=None, help="Optional Host-IR cache file")
    parser.add_argument("--stage-c-codegen-profile", type=Path, default=None, help="Optional codegen profile JSON")
    parser.add_argument("--stage-c-protocol-family", type=str, default=None, help="Protocol family label for Stage C")
    parser.add_argument("--stage-c-model", type=str, default=None, help="LLM model for Stage C")
    parser.add_argument("--stage-c-temperature", type=float, default=0.2, help="LLM temperature for Stage C")
    parser.add_argument("--stage-c-max-tokens", type=int, default=64000, help="LLM max tokens for Stage C")
    parser.add_argument("--stage-c-contract-repair-max-rounds", type=int, default=2, help="Max contract repair rounds for Stage C")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    setup_logging(console_level=logging.INFO)
    load_api_keys(args.config, set_env=True)

    protocol_root = Path(args.root).resolve() if args.root else (DATA_DIR / str(args.protocol)).resolve()
    paths = ProtocolPaths(protocol_root)

    sections_file = Path(args.sections_file) if args.sections_file else paths.sections_file
    raw_sections_file = Path(args.raw_sections_file) if args.raw_sections_file else paths.raw_sections_file

    stage_a_needed = args.force_stage_a or (not sections_file.exists()) or (not raw_sections_file.exists())
    if stage_a_needed:
        pdfs = _find_pdfs(paths, args.pdfs)
        if not pdfs:
            raise SystemExit(f"No PDFs found under {paths.pdfs_dir} (and none provided via --pdf).")
        api_key = args.api_key or os.environ.get("LLM_API_KEY") or os.environ.get("CLAUDE_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise SystemExit("Stage A requires an API key (provide --api-key or configure api_config.json).")
        run_stage_a(paths=paths, pdfs=pdfs, llm_api_key=str(api_key))
        sections_file = paths.sections_file
        raw_sections_file = paths.raw_sections_file

    stage_b_needed = args.force_stage_b or (not paths.format_tree_file.exists())
    if stage_b_needed:
        tree_path = run_stage_b(paths=paths, sections_file=sections_file, raw_sections_file=raw_sections_file, args=args)
    else:
        tree_path = paths.format_tree_file
        logger.info("[Stage B] Reusing existing tree: %s", tree_path)

    if args.enable_step2_fix:
        logger.info("[Stage B2] Syntax-only fixing (Step2 fix)")
        fixed_path = run_step2_fix(cache_path=tree_path, sections_path=sections_file, output_dir=paths.step2_results_dir, log_dir=paths.logs_dir / "stage_b")
        tree_path = fixed_path
        logger.info("  fixed: %s", tree_path)
    else:
        logger.info("[Stage B2] Skipped (--no-step2-fix)")

    if args.enable_traffic_fix:
        traffic_path = Path(args.traffic) if args.traffic else paths.traffic_file
        if traffic_path.exists():
            logger.info("[Stage B3] Traffic-aware fixing")
            out_path = paths.traffic_fixed_tree_file
            out_path.parent.mkdir(parents=True, exist_ok=True)
            tree_path = run_traffic_fix(
                tree_path=Path(tree_path),
                traffic_path=traffic_path,
                sections_path=sections_file if sections_file.exists() else None,
                output_path=out_path,
                max_llm_calls=int(args.traffic_max_llm_calls),
                max_packets=int(args.traffic_max_packets),
                per_issue_mcts=True,
                batch_size=1,
            )
            logger.info("  traffic_fixed: %s", tree_path)
        else:
            logger.info("[Stage B3] Skipped (traffic file not found: %s)", traffic_path)
    else:
        logger.info("[Stage B3] Skipped (--no-traffic-fix)")

    if args.skip_stage_c:
        logger.info("[Stage C] Skipped (--skip-stage-c)")
        return

    run_stage_c(tree_path=Path(tree_path), paths=paths, args=args)


if __name__ == "__main__":
    main()
