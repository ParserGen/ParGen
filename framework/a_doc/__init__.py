from __future__ import annotations
if __package__ and __package__.startswith('framework.'):
    from .pipeline import DocumentPipeline, DocumentPipelineConfig
    __all__ = ['DocumentPipeline', 'DocumentPipelineConfig']
else:
    __all__: list[str] = []
