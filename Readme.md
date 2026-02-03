# ParGen-Release

ParGen aims to automatically derive executable protocol parsers from natural-language specification documents. By consolidating fragmented specification statements into a unified protocol representation (e.g., message layout, field semantics, and cross-field validity rules) and iteratively validating the generated parsers on real traffic traces, ParGen helps produce parsers that are both accurate and consistent across heterogeneous parsing platforms.

This repository includes the core implementation to support reproduction of the key components and results described in our paper.

## Repository layout

```
.
├── Readme.md
├── datasets/
│   ├── specs/              # protocol specification documents
│   └── gt/                 # ground-truth / annotations
└── framework/
    ├── run_pipeline.py     # core end-to-end pipeline entry
    ├── paths.py            # artifacts/cache path definitions
    ├── logging_utils.py
    ├── config_manager.py
    ├── a_doc/              # Stage A: document ingestion & extraction
    ├── b_tree/             # Stage B: protocol-tree generation/validation/repair
    └── c_code/             # Stage C: code generation & repair (C)
```
