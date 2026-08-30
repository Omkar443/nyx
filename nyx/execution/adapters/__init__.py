"""
NYX Tool Adapters Package
"""
from __future__ import annotations

import importlib
from typing import Type
from nyx.execution.adapters.base import ToolAdapter
from nyx.execution.adapters.subfinder import SubfinderAdapter
from nyx.execution.adapters.httpx import HttpxAdapter
from nyx.execution.adapters.katana import KatanaAdapter
from nyx.execution.adapters.nuclei import NucleiAdapter
from nyx.execution.adapters.nmap import NmapAdapter
from nyx.execution.adapters.ffuf import FfufAdapter
from nyx.execution.adapters.probe import ProbeAdapter
from nyx.execution.adapters.sqlmap import SqlmapAdapter

_ADAPTER_REGISTRY: dict[str, Type[ToolAdapter]] = {
    "subfinder": SubfinderAdapter,
    "httpx": HttpxAdapter,
    "katana": KatanaAdapter,
    "nuclei": NucleiAdapter,
    "sqlmap": SqlmapAdapter,
    "nmap": NmapAdapter,
    "ffuf": FfufAdapter,
    "probe": ProbeAdapter,
    "vuln_probe": ProbeAdapter,
}


def get_adapter(tool_name: str, adapter_path: str | None = None) -> ToolAdapter | None:
    """Retrieve or dynamically import a ToolAdapter instance for a tool."""
    name_clean = tool_name.lower().strip()

    if adapter_path:
        try:
            mod_name, cls_name = adapter_path.rsplit(".", 1)
            mod = importlib.import_module(mod_name)
            adapter_cls = getattr(mod, cls_name)
            if issubclass(adapter_cls, ToolAdapter):
                return adapter_cls()
        except Exception:
            pass

    if name_clean in _ADAPTER_REGISTRY:
        return _ADAPTER_REGISTRY[name_clean]()

    return None


__all__ = [
    "ToolAdapter",
    "SubfinderAdapter",
    "HttpxAdapter",
    "KatanaAdapter",
    "NucleiAdapter",
    "SqlmapAdapter",
    "NmapAdapter",
    "FfufAdapter",
    "ProbeAdapter",
    "get_adapter",
]
