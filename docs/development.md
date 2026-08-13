# NYX Security Engine Development Guide

## Project Architecture
NYX uses a 4-tier service architecture:
- `nyx.interface`: Output formatting & presentation
- `nyx.application`: Service facades and orchestration entrypoints
- `nyx.core` / `nyx.security` / `nyx.recon` / `nyx.validation`: Pure security logic and engines
- `nyx.infrastructure`: Process execution, tool discovery, filesystem, and URL helpers

## Running the Automated Test Suite
To run the full regression test suite across all 12 phase verification harnesses:

```powershell
python -c "
import subprocess, sys

test_scripts = [
    'scratch/stage3_tests.py',
    'scratch/phase41_tests.py',
    'scratch/phase42_tests.py',
    'scratch/phase43_tests.py',
    'scratch/phase50_tests.py',
    'scratch/phase51_tests.py',
    'scratch/phase60_tests.py',
    'scratch/phase70_tests.py',
    'scratch/phase80_tests.py',
    'scratch/phase90_tests.py',
    'scratch/phase100_tests.py',
    'scratch/phase110_tests.py'
]

for script in test_scripts:
    p = subprocess.run([sys.executable, script], capture_output=True, text=True)
    print(f'{script}: {\"PASS\" if p.returncode == 0 else \"FAIL\"}')
"
```

## Building the Package
Build wheel and sdist distributions using standard build tools:

```powershell
python -m build
```
