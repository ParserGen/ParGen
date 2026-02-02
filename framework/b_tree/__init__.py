from __future__ import annotations
from typing import TYPE_CHECKING, Any
if __package__ and __package__.startswith('framework.'):
    __all__ = ['FormatTreePipeline', 'FormatTreeConfig']
    if TYPE_CHECKING:
        from .pipeline import FormatTreeConfig, FormatTreePipeline

    def __getattr__(name: str) -> Any:
        if name == 'FormatTreePipeline':
            from .pipeline import FormatTreePipeline
            return FormatTreePipeline
        if name == 'FormatTreeConfig':
            from .pipeline import FormatTreeConfig
            return FormatTreeConfig
        raise AttributeError(name)

    def __dir__() -> list[str]:
        return sorted(list(globals().keys()) + list(__all__))
else:
    __all__: list[str] = []
