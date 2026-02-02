from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
from ..config_manager import load_api_keys
from ..paths import DEFAULT_API_CONFIG
from .pipeline import DocumentPipeline, DocumentPipelineConfig

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run the document processing pipeline')
    parser.add_argument('pdf', type=Path, help='Path to the source specification PDF')
    parser.add_argument('--output', type=Path, default=Path('doc_results.json'), help='Where to store processed results JSON')
    parser.add_argument('--api-key', default=None, help='API key (overrides config/env)')
    parser.add_argument('--config', type=Path, default=DEFAULT_API_CONFIG, help='Path to API config JSON')
    parser.add_argument('--section-strategy', choices=['leaf_only', 'fine_grained'], default='leaf_only', help='Section selection strategy')
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    load_api_keys(args.config, set_env=True)
    api_key = args.api_key or os.environ.get('LLM_API_KEY') or os.environ.get('CLAUDE_API_KEY') or os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        raise SystemExit('API key is required (provide --api-key or configure api_config.json)')
    config = DocumentPipelineConfig(llm_api_key=api_key, section_strategy=args.section_strategy)
    pipeline = DocumentPipeline(config)
    result = pipeline.process_pdf(args.pdf)
    args.output.write_text(json.dumps(result, ensure_ascii=True, indent=2), encoding='utf-8')
    summary = pipeline.summarize(result)
if __name__ == '__main__':
    main()
