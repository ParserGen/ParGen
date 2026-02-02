from __future__ import annotations
import argparse
import json
from pathlib import Path
from .pipeline import FormatTreeConfig, FormatTreePipeline

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Build a protocol format tree')
    parser.add_argument('sections', type=Path, help='LLM-processed sections JSON')
    parser.add_argument('raw', type=Path, help='Raw extracted sections JSON')
    parser.add_argument('--output', type=Path, default=Path('format_tree.json'), help='Path to save the resulting tree')
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    config = FormatTreeConfig(sections_file=args.sections, raw_file=args.raw)
    pipeline = FormatTreePipeline(config)
    tree = pipeline.build()
    if tree is None:
        raise SystemExit('Failed to build format tree')
    if hasattr(tree, 'to_dict'):
        payload = tree.to_dict()
    elif hasattr(tree, '__dict__'):
        payload = json.loads(json.dumps(tree, default=lambda o: getattr(o, '__dict__', str(o))))
    else:
        payload = tree
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
if __name__ == '__main__':
    main()
