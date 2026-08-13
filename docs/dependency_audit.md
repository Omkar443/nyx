# NYX Supply Chain & Dependency Audit

## 1. Executive Summary
Audit of Python runtime dependencies and Node.js frontend packages.

---

## 2. Python Dependencies
- **Core Requirements**: Python >= 3.9, FastAPI, Uvicorn, Playwright, PyYAML, Pydantic, HTTPX.
- **Optional Dependencies**: `requests` (http).
- **Vulnerability Check**: `0` critical vulnerabilities reported. Standard fallback to Python stdlib `urllib` when optional dependencies absent.

---

## 3. Frontend Packages (Node.js)
- **Framework**: React 18 + Vite 5 + TailwindCSS + Lucide React icons.
- **Build Output**: Clean compiled static assets in `frontend/dist/`.
