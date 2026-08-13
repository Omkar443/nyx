"""
NYX Execution Artifacts Storage Engine
Manages storage, retrieval, and indexing of tool execution stdout, stderr, and result JSON artifacts.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from nyx.infrastructure.filesystem import _get_eng_dir
from nyx.models.execution import ExecutionResult


def get_execution_artifact_dir(execution_id: str, create: bool = True) -> Path:
    d = _get_eng_dir(create=create)
    exec_dir = d / "executions" / execution_id
    if create:
        exec_dir.mkdir(parents=True, exist_ok=True)
    return exec_dir


def store_execution_artifacts(
    result: ExecutionResult,
    parsed_data: dict[str, Any] | None = None,
    extra_files: dict[str, str | bytes] | None = None,
) -> dict[str, str]:
    """Store stdout, stderr, result.json, and extra artifacts for an execution."""
    exec_dir = get_execution_artifact_dir(result.execution_id, create=True)

    stdout_path = exec_dir / "stdout.txt"
    stderr_path = exec_dir / "stderr.txt"
    result_path = exec_dir / "result.json"

    stdout_path.write_text(result.stdout or "", encoding="utf-8")
    stderr_path.write_text(result.stderr or "", encoding="utf-8")

    res_dict = result.to_dict()
    if parsed_data:
        res_dict["parsed_data"] = parsed_data

    result_path.write_text(json.dumps(res_dict, indent=2), encoding="utf-8")

    artifacts = {
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
        "result_json": str(result_path),
        "dir": str(exec_dir),
    }

    if parsed_data:
        parsed_path = exec_dir / "parsed.json"
        parsed_path.write_text(json.dumps(parsed_data, indent=2), encoding="utf-8")
        artifacts["parsed_json"] = str(parsed_path)

    if extra_files:
        for fname, content in extra_files.items():
            fpath = exec_dir / fname
            if isinstance(content, bytes):
                fpath.write_bytes(content)
            else:
                fpath.write_text(content, encoding="utf-8")
            artifacts[fname] = str(fpath)

    return artifacts


def get_execution_artifacts(execution_id: str) -> dict[str, Any]:
    """Retrieve artifact details and files for a stored execution ID."""
    d = _get_eng_dir(create=False)
    exec_dir = d / "executions" / execution_id
    if not exec_dir.exists():
        return {"status": "error", "message": f"Execution directory for '{execution_id}' not found."}

    artifacts = {"execution_id": execution_id, "dir": str(exec_dir), "files": {}}
    for fpath in exec_dir.iterdir():
        if fpath.is_file():
            artifacts["files"][fpath.name] = str(fpath)

    result_json = exec_dir / "result.json"
    if result_json.exists():
        try:
            artifacts["result"] = json.loads(result_json.read_text(encoding="utf-8"))
        except Exception:
            pass

    return {"status": "success", "artifacts": artifacts}
