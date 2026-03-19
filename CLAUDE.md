# Command Safety Analyzer

## Overview
This project is a command safety analysis system that uses OpenSandbox (Docker-based isolation) to perform deep behavioral analysis of shell commands. It classifies commands as safe or malicious.

## Architecture
- `checker.sh` — Main analysis engine. Contains an embedded Python script (~1500 lines) that performs 24-dimension behavioral analysis inside a sandbox.
- `triage.sh` — Standalone fast triage (pure bash, no dependencies). For API/CI integration.
- `run_all.sh` — Batch runner with Git auto-commit and accuracy reporting.
- `samples/white.jsonl` and `samples/black.jsonl` — Test samples (JSONL format).
- `test_patterns.sh` — Pattern validation test suite (116 tests).

## Key Design Decisions
- The embedded Python script in checker.sh runs inside a venv created at runtime
- triage.sh is intentionally zero-dependency (bash + grep only) for maximum portability
- Scoring uses a weighted system (0-100) with legitimate command downscoring
- MITRE ATT&CK mapping is maintained for all findings
- Attack chain correlation crosses dimension boundaries for multi-stage detection

## Running Tests
```bash
./test_patterns.sh           # Pattern validation (116 tests)
./test_patterns.sh --verbose # With details
```

## Common Tasks
```bash
# Single command analysis
COMMAND="some command" ./checker.sh

# Fast triage (no Docker)
COMMAND="some command" ./triage.sh

# Batch run all samples
./run_all.sh

# Run specific sample
./run_all.sh black:b01
```

## Environment Variables
- `COMMAND` — Command to analyze
- `SANDBOX_PORT` — Server port (default: 8080)
- `REGISTRY_MIRROR` — Docker registry mirror for China
- `FAST_TRIAGE=1` — Enable fast triage mode in checker.sh
