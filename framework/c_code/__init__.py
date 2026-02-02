from __future__ import annotations
from typing import TYPE_CHECKING, Any
if __package__ and __package__.startswith('framework.'):
    __all__ = ['ArtifactSpec', 'Edge', 'HostIR', 'LLMClient', 'LLMConfig', 'Node', 'ParseIR', 'StageCConfig', 'build_parse_ir', 'create_llm_client', 'run_stage_c']
    if TYPE_CHECKING:
        from .host_ir_schema import ArtifactSpec, HostIR
        from .llm_client import LLMClient, LLMConfig, create_llm_client
        from .parse_ir import Edge, Node, ParseIR, build_parse_ir
        from .stage_c_pipeline import StageCConfig, run_stage_c
    _EXPORTS: dict[str, tuple[str, str]] = {'ArtifactSpec': ('host_ir_schema', 'ArtifactSpec'), 'HostIR': ('host_ir_schema', 'HostIR'), 'LLMClient': ('llm_client', 'LLMClient'), 'LLMConfig': ('llm_client', 'LLMConfig'), 'create_llm_client': ('llm_client', 'create_llm_client'), 'Edge': ('parse_ir', 'Edge'), 'Node': ('parse_ir', 'Node'), 'ParseIR': ('parse_ir', 'ParseIR'), 'build_parse_ir': ('parse_ir', 'build_parse_ir'), 'StageCConfig': ('stage_c_pipeline', 'StageCConfig'), 'run_stage_c': ('stage_c_pipeline', 'run_stage_c')}

    def __getattr__(name: str) -> Any:
        spec = _EXPORTS.get(name)
        if spec is None:
            raise AttributeError(name)
        mod_name, attr = spec
        module = __import__(f'{__name__}.{mod_name}', fromlist=[attr])
        return getattr(module, attr)

    def __dir__() -> list[str]:
        return sorted(list(globals().keys()) + list(__all__))
else:
    __all__: list[str] = []
