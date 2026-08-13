# NYX Tool Adapter Architecture

## 1. Overview
The NYX Tool Adapter framework (`nyx/execution/adapters/`) decouples raw subprocess execution from tool-specific input validation, command building, and structured output parsing.

---

## 2. ToolAdapter Base Contract (`nyx/execution/adapters/base.py`)

Every tool adapter inherits from `ToolAdapter` and implements three core methods:

```python
class ToolAdapter(ABC):
    tool_name: str

    @abstractmethod
    def validate(self, target: str, arguments: list[str] | None = None) -> tuple[bool, str]:
        """Validate input target format and argument compatibility."""
        pass

    @abstractmethod
    def build_command(self, target: str, arguments: list[str] | None = None) -> list[str]:
        """Construct canonical execution command vector."""
        pass

    @abstractmethod
    def parse_result(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse raw process output into structured domain JSON metadata."""
        pass
```

---

## 3. Implemented Adapters

| Adapter Class | Module Path | Focus | Structured Output |
|---|---|---|---|
| `SubfinderAdapter` | `nyx.execution.adapters.subfinder` | Subdomain Discovery | `subdomains`, `assets_found`, `count` |
| `HttpxAdapter` | `nyx.execution.adapters.httpx` | HTTP Probing & Tech Detection | `live_hosts`, `technologies`, `assets_found` |
| `KatanaAdapter` | `nyx.execution.adapters.katana` | Web Crawling | `endpoints`, `assets_found`, `count` |
| `NucleiAdapter` | `nyx.execution.adapters.nuclei` | Vulnerability Scanning | `vulnerabilities`, `assets_found`, `count` |
| `NmapAdapter` | `nyx.execution.adapters.nmap` | Port & Service Scanning | `open_ports`, `assets_found`, `count` |

---

## 4. Adapter Dynamic Loading (`get_adapter`)
Tool adapters are bound to tool definitions in `.nyx/tools.yaml` via the `adapter` attribute and loaded dynamically at execution runtime:

```yaml
tools:
  subfinder:
    binary: "subfinder"
    execution_class: "PASSIVE"
    adapter: "nyx.execution.adapters.subfinder.SubfinderAdapter"
```
