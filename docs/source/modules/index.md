# Module Documentation

```{toctree}
:maxdepth: 2
```

## Package Structure

The analyzer package contains all core functionality organized into logical modules:

```
analyzer/
├── __init__.py          # Package initialization
├── engine.py           # Main analysis orchestration
├── sandbox_ops.py      # Sandbox operations and management
├── diff_analysis.py    # Before/after difference analysis
├── scoring.py          # Risk scoring and verdict calculation
├── patterns.py         # Detection patterns and rules
├── report.py           # Report generation and formatting
└── exceptions.py       # Custom exception definitions
```

## Core Modules

### analyzer.engine

Main analysis workflow orchestration:

```python
"""Main analysis engine orchestrating the complete workflow."""

async def run_analysis(
    command: str,
    port: int = 8080,
    image: str = "opensandbox/code-interpreter:v1.0.2",
    report_dir: str = ".",
    config: ScoringConfig = None
) -> dict:
    """
    Execute complete behavioral analysis workflow.
    
    This function orchestrates the entire analysis process:
    1. Environment setup and validation
    2. Sandbox creation and baseline collection
    3. Command execution with real-time monitoring
    4. Post-execution state collection
    5. Multi-dimensional analysis
    6. Risk scoring and verdict generation
    7. Report generation
    
    Args:
        command: Command string to analyze
        port: OpenSandbox server port
        image: Docker image for sandbox environment
        report_dir: Directory for output reports
        config: Scoring configuration parameters
        
    Returns:
        Complete analysis results dictionary
        
    Raises:
        SandboxError: If sandbox operations fail
        AnalysisError: If analysis process encounters errors
    """
    pass
```

### analyzer.sandbox_ops

Sandbox management and operations:

```python
"""Sandbox operations for isolated command execution."""

async def create_sandbox(image: str, port: int) -> Sandbox:
    """
    Create and initialize a new sandbox container.
    
    Args:
        image: Docker image name
        port: Port for sandbox communication
        
    Returns:
        Initialized Sandbox object
    """
    pass

async def collect_all_snapshots(sandbox: Sandbox) -> dict:
    """
    Collect comprehensive system state snapshot.
    
    Captures:
    - File system state
    - Process information
    - Network connections
    - System configuration
    - User and permission data
    
    Args:
        sandbox: Active sandbox instance
        
    Returns:
        Dictionary containing all snapshot data
    """
    pass

async def run_cmd(sandbox: Sandbox, command: str, timeout: int = 30) -> tuple[str, str]:
    """
    Execute command in sandbox environment.
    
    Args:
        sandbox: Sandbox instance
        command: Command to execute
        timeout: Execution timeout in seconds
        
    Returns:
        Tuple of (stdout, stderr)
    """
    pass
```

### analyzer.diff_analysis

Core difference analysis engine:

```python
"""Before/after snapshot comparison and analysis."""

class DiffAnalyzer:
    """Analyzes differences between system snapshots."""
    
    def __init__(self, before: dict, after: dict):
        """
        Initialize with before and after snapshots.
        
        Args:
            before: Baseline system state
            after: Post-execution system state
        """
        self.before = before
        self.after = after
        self.evidence = {}
    
    def analyze_files(self) -> list[Change]:
        """
        Analyze file system changes.
        
        Detects:
        - New files
        - Deleted files
        - Modified files
        - Permission changes
        - Ownership changes
        
        Returns:
            List of file change objects
        """
        pass
    
    def analyze_processes(self) -> list[ProcessEvent]:
        """
        Analyze process-related changes.
        
        Returns:
            List of process events
        """
        pass
    
    def analyze_network(self) -> list[Connection]:
        """
        Analyze network behavior changes.
        
        Returns:
            List of network connections
        """
        pass
```

### analyzer.scoring

Risk scoring and verdict calculation:

```python
"""Risk scoring engine and configuration management."""

@dataclass
class Finding:
    """Represents a single security finding."""
    dimension: str
    severity: str  # CRITICAL, WARN, INFO
    description: str
    risk_score: int
    mitre_techniques: list[str]
    evidence: str = ""

class ScoringEngine:
    """Calculates risk scores and determines verdicts."""
    
    def __init__(self, config: ScoringConfig):
        self.config = config
        self.findings: list[Finding] = []
    
    def add_finding(self, finding: Finding):
        """Add a security finding to the analysis."""
        self.findings.append(finding)
    
    def total_score(self) -> int:
        """
        Calculate total risk score.
        
        Returns:
            Risk score from 0-100
        """
        pass
    
    def verdict(self) -> str:
        """
        Determine final verdict based on score.
        
        Returns:
            One of: LIKELY_SAFE, LOW_RISK, SUSPICIOUS, DANGEROUS
        """
        pass
    
    def confidence(self) -> str:
        """
        Calculate confidence level.
        
        Returns:
            One of: HIGH, MEDIUM, LOW
        """
        pass

@dataclass
class ScoringConfig:
    """Configuration for scoring parameters."""
    dangerous_threshold: int = 60
    suspicious_threshold: int = 25
    block_threshold: int = 50
    entropy_threshold: float = 6.5
    hidden_proc_tolerance: int = 10
    
    @classmethod
    def from_file(cls, filepath: str) -> 'ScoringConfig':
        """Load configuration from file."""
        pass
```

### analyzer.patterns

Detection patterns and rules:

```python
"""Security detection patterns and artifact analysis."""

# Behavioral artifact patterns
ARTIFACT_PATTERNS: list[tuple[str, str, str, int]] = [
    # Pattern format: (regex, description, mitre_id, score)
    (r"/dev/tcp/\S+/\d+", "reverse shell via /dev/tcp", "T1059.004", 40),
    (r"bash\s+-i\s+>&", "interactive bash reverse shell", "T1059.004", 45),
    (r"/etc/shadow", "shadow file reference", "T1048", 30),
    (r"authorized_keys", "SSH authorized_keys manipulation", "T1098", 30),
]

# Cron-specific patterns
CRON_ARTIFACT_PATTERNS: list[tuple[str, str, str, int]] = [
    (r"curl\s+.*\|\s*(ba)?sh", "cron: curl|bash payload", "T1053.003", 35),
    (r"/dev/tcp/", "cron: reverse shell", "T1059.004", 45),
]

# MITRE ATT&CK mappings
MITRE: dict[str, str] = {
    "T1059.004": "Unix Shell",
    "T1053.003": "Cron",
    "T1098": "Account Manipulation",
    "T1048": "Exfiltration Over Alternative Protocol",
}

def match_artifact_patterns(content: str) -> list[PatternMatch]:
    """
    Match content against artifact patterns.
    
    Args:
        content: Text content to analyze
        
    Returns:
        List of pattern matches found
    """
    pass
```

### analyzer.report

Report generation and formatting:

```python
"""Report generation in multiple formats."""

def generate_text_summary(report: dict) -> str:
    """
    Generate human-readable text summary.
    
    Args:
        report: Complete analysis report
        
    Returns:
        Formatted text summary
    """
    pass

def generate_sarif(report: dict) -> dict:
    """
    Convert report to SARIF v2.1.0 format.
    
    Args:
        report: Analysis report
        
    Returns:
        SARIF-compatible dictionary
    """
    pass

def save_reports(report: dict, report_dir: str) -> tuple[str, str, str]:
    """
    Save reports in multiple formats.
    
    Args:
        report: Analysis results
        report_dir: Output directory
        
    Returns:
        Tuple of (json_path, txt_path, sarif_path)
    """
    pass
```

## Utility Modules

### checker.py

Main entry point for command analysis:

```python
"""Main command line interface for analysis."""

def main():
    """
    Main entry point for command analysis.
    
    Environment variables:
        COMMAND: Command to analyze
        COMMAND_B64: Base64-encoded command (takes precedence)
        SANDBOX_PORT: Sandbox server port (default: 8080)
        SANDBOX_IMAGE: Docker image to use
        REPORT_DIR: Output directory for reports
    """
    pass

def _load_command() -> str:
    """
    Load command from environment variables.
    
    Handles both plain text and base64-encoded commands.
    
    Returns:
        Decoded command string
    """
    pass
```

### run_all.sh

Batch processing script:

```bash
#!/bin/bash
"""
Batch processing script for multiple samples.

Features:
- Parallel execution with configurable concurrency
- Automatic Git commit integration
- Retry mechanism for failed analyses
- Progress tracking and reporting
- Support for white/black sample categorization

Usage:
    ./run_all.sh [category] [--no-commit] [--retry N]

Arguments:
    category: white, black, all, or specific samples (e.g., white:w01,w02)
    --no-commit: Skip Git auto-commit
    --retry N: Number of retry attempts for failed analyses
"""
```

### triage.sh

Fast triage analysis:

```bash
#!/bin/bash
"""
Fast triage engine for preliminary command screening.

Features:
- Zero-dependency operation
- Millisecond response times
- Pattern-based detection
- Exit code based verdict system
- Human-readable and JSON output modes

Usage:
    COMMAND="cmd" ./triage.sh [--explain] [--json-input]

Exit codes:
    0: PASS (safe command)
    1: REVIEW (requires deeper analysis)
    2: BLOCK (high-confidence malicious)
"""
```

## Exception Hierarchy

```python
"""Custom exception classes for the analyzer."""

class AnalyzerError(Exception):
    """Base exception for analyzer errors."""
    pass

class SandboxError(AnalyzerError):
    """Errors related to sandbox operations."""
    pass

class AnalysisError(AnalyzerError):
    """Errors during analysis process."""
    pass

class ConfigurationError(AnalyzerError):
    """Configuration-related errors."""
    pass

class PatternError(AnalyzerError):
    """Pattern matching errors."""
    pass
```

## Type Definitions

```python
"""Common type definitions used throughout the package."""

from typing import TypedDict, Literal

class AnalysisResult(TypedDict):
    """Structure of analysis results."""
    version: str
    command: str
    verdict: Literal["LIKELY_SAFE", "LOW_RISK", "SUSPICIOUS", "DANGEROUS"]
    risk_score: int
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    findings: list[Finding]
    timeline: list[TimelineEvent]
    mitre_attack: dict[str, MITREInfo]
    dimensions: dict[str, object]

class Finding(TypedDict):
    """Structure of individual findings."""
    dimension: str
    severity: Literal["CRITICAL", "WARN", "INFO"]
    description: str
    risk_score: int
    mitre_attack: list[MITRETechnique]
    evidence: str

# Common string literals
Verdict = Literal["LIKELY_SAFE", "LOW_RISK", "SUSPICIOUS", "DANGEROUS"]
Confidence = Literal["HIGH", "MEDIUM", "LOW"]
Severity = Literal["CRITICAL", "WARN", "INFO"]
```

This modular structure enables flexible integration and extension while maintaining clear separation of concerns.