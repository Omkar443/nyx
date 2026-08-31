# Contributing to NYX Security Intelligence Engine

Thank you for your interest in contributing to NYX!

## Development & Contribution Guidelines

### 1. Development Setup
1. Fork and clone the repository:
   ```bash
   git clone https://github.com/Omkar443/nyx.git
   cd nyx
   ```
2. Run the onboarding wizard or install dependencies in editable mode:
   ```bash
   ./install.sh
   # or
   python3 -m pip install -e ".[all]"
   ```

### 2. Coding Standards & Architectural Invariants
- **PEP 8 Compliance**: Python code must conform to PEP 8 style standards.
- **Architectural Separation**: Maintain **zero imports** from `nyx_cli.cli` inside core engine packages (`nyx/*`). The CLI depends on core packages, never the reverse.
- **Safety First**: Never bypass scope enforcement gates, authorization checks, or fail-closed policy behaviors.
- **Evidence Integrity**: All tool execution adapters must capture raw output and support deterministic verification.

### 3. Running Automated Tests
Ensure all automated tests pass before submitting a pull request:
```bash
python3 -m pytest
```

### 4. Submitting a Pull Request
1. Create a descriptive feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Commit your changes with clear, semantic commit messages:
   ```bash
   git commit -m "feat(ai): add new provider integration"
   ```
3. Push to your branch and open a Pull Request against `main` detailing the changes made, tests executed, and behavioral impacts.

---

## Security Vulnerability Reporting
For reporting vulnerabilities in NYX itself or understanding the responsible disclosure policy, please see [SECURITY.md](SECURITY.md).
