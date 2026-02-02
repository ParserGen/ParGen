__all__ = ['DocumentPipeline', 'DocumentPipelineConfig', 'FormatTreePipeline', 'FormatTreeConfig', 'StageCConfig', 'run_stage_c']

def __getattr__(name):
    if name in {'DocumentPipeline', 'DocumentPipelineConfig'}:
        from .a_doc.pipeline import DocumentPipeline, DocumentPipelineConfig
        return {'DocumentPipeline': DocumentPipeline, 'DocumentPipelineConfig': DocumentPipelineConfig}[name]
    if name in {'FormatTreePipeline', 'FormatTreeConfig'}:
        from .b_tree.pipeline import FormatTreePipeline, FormatTreeConfig
        return {'FormatTreePipeline': FormatTreePipeline, 'FormatTreeConfig': FormatTreeConfig}[name]
    if name in {'StageCConfig', 'run_stage_c'}:
        from .c_code.stage_c_pipeline import StageCConfig, run_stage_c
        return {'StageCConfig': StageCConfig, 'run_stage_c': run_stage_c}[name]
    raise AttributeError(f"module 'framework' has no attribute '{name}'")
