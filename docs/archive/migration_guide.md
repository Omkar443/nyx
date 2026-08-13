# NYX Migration Guide

> [!NOTE]
> This document describes internal development history before NYX identity migration.
> It is archived and not part of the public architecture documentation.


> [!NOTE]
> **Historical Migration Reference**: This document describes historical architectural migrations and baseline decoupling iterations.


## Migration Overview
This guide covers upgrading from the legacy `nyx` CLI module to the decoupled `nyx` service architecture.

## Import Repointing Matrix

| Legacy Import Path | New Decoupled Import Path |
|---|---|
| `from nyx_cli.cli import color, say, section` | `from nyx.interface.output import color, say, section` |
| `from nyx_cli.cli import REPO_ROOT, _get_eng_dir, calculate_file_hash` | `from nyx.infrastructure.filesystem import REPO_ROOT, _get_eng_dir, calculate_file_hash` |
| `from nyx_cli.cli import get_cmd_path, has_cmd` | `from nyx.infrastructure.tools import get_cmd_path, has_cmd` |
| `from nyx_cli.cli import run_cmd` | `from nyx.infrastructure.process import run_cmd` |
| `from nyx_cli.cli import normalize_url` | `from nyx.infrastructure.urls import normalize_url` |
| `from nyx_cli.cli import check_authorization, get_engagement_scope` | `from nyx.security.authorization import check_authorization, get_engagement_scope` |
| `from nyx_cli.cli import sanitize_canonical_evidence` | `from nyx.security.authorization import sanitize_canonical_evidence` |

## Backward Compatibility
- The `nyx` binary is the primary entry point.
- The `nyx` command remains available as a full backward-compatibility alias pointing to `nyx`.
