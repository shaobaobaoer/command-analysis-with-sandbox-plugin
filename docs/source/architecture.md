# Architecture Overview

## Core Design Philosophy

The Command Safety Analyzer is built on the principle of **pure behavioral analysis** through sandbox execution comparison. Unlike traditional static analysis tools, it makes all security decisions based solely on observing actual system changes during command execution.

### Key Principles

1. **Dynamic Only**: No static pattern matching of command strings
2. **Before/After Comparison**: All detections compare system state snapshots
3. **Isolated Execution**: Commands run in secure Docker sandboxes
4. **Multi-Dimensional**: 24 distinct analysis dimensions
5. **Attack-Oriented**: MITRE ATT&CK framework integration

## System Architecture

```mermaid
graph TD
    A[User Command] --> B[Triage Engine]
    B --> C{Risk Level}
    C -->|LOW| D[Allow]
    C -->|MEDIUM| E[Sandbox Analysis]
    C -->|HIGH| F[Block]
    E --> G[OpenSandbox Container]
    G --> H[24-Dimension Analysis]
    H --> I[Scoring Engine]
    I --> J[Final Verdict]
```

## Component Breakdown

### 1. Triage Engine (`triage.sh`)

**Purpose**: Rapid preliminary screening
**Performance**: &lt; 50ms response time
**Method**: Static pattern matching against known malicious signatures

```bash
# Flow:
# 1. Parse command string
# 2. Apply regex patterns
# 3. Calculate risk score
# 4. Return verdict (PASS/REVIEW/BLOCK)
```

### 2. Sandbox Analysis Engine (`checker.py`)

**Purpose**: Deep behavioral analysis
**Performance**: 15-30 seconds per command
**Method**: Execute in isolated environment and compare before/after states

#### Execution Flow

1. **Environment Setup**
   - Start OpenSandbox server
   - Create isolated container
   - Establish monitoring probes

2. **Baseline Collection**
   - File system snapshot
   - Process tree capture
   - Network state recording
   - System configuration backup

3. **Command Execution**
   - Run command in sandbox
   - Real-time monitoring via probes
   - Capture all system interactions

4. **Post-Analysis**
   - Collect final state snapshot
   - Compare with baseline
   - Apply detection algorithms
   - Generate risk assessment

### 3. Analysis Dimensions

The system analyzes 24 distinct security-relevant aspects:

#### File System Dimensions (1-5)
- **D1**: File creation/deletion/modification tracking
- **D2**: Real-time file event monitoring (inotify)
- **D3**: Sensitive file access patterns
- **D4**: Persistence mechanism detection
- **D5**: Shell environment modifications

#### Process & Execution Dimensions (6-10)
- **D6**: Network connection behavior
- **D7**: DNS configuration changes
- **D8**: Suspicious binary deployment
- **D9**: Resource consumption anomalies
- **D10**: Process tree analysis

#### Content Analysis Dimensions (11-15)
- **D11**: Kernel module changes
- **D12**: SUID/SGID file creation
- **D13**: Environment variable manipulation
- **D14**: Binary integrity verification
- **D15**: Symbolic link creation

#### Behavioral Dimensions (16-24)
- **D16**: File content scanning
- **D17**: Command output analysis
- **D18**: Entropy-based anomaly detection
- **D19**: Cron job modifications
- **D20**: Hidden process detection
- **D21**: Signal handler manipulation
- **D22**: Capability changes
- **D23**: Attack chain correlation
- **D24**: File permission changes

### 4. Scoring Engine

Converts behavioral observations into quantitative risk assessments:

```python
class ScoringEngine:
    def calculate_score(self, findings):
        # Weighted sum of all findings
        base_score = sum(finding.weight * finding.severity_factor 
                        for finding in findings)
        
        # Apply confidence modifiers
        if self.is_legitimate_pattern(command):
            base_score /= LEGITIMATE_DIVISOR
            
        # Attack chain bonuses
        if self.detect_attack_chain(findings):
            base_score *= ATTACK_CHAIN_MULTIPLIER
            
        return min(100, max(0, base_score))
```

### 5. Pattern Detection System

Uses regular expressions and behavioral heuristics:

```python
# Artifact pattern matching (content analysis)
ARTIFACT_PATTERNS = [
    # Reverse shell detection
    (r"/dev/tcp/\S+/\d+", "reverse shell via /dev/tcp", "T1059.004", 40),
    (r"bash\s+-i\s+>&", "interactive bash reverse shell", "T1059.004", 45),
    
    # Credential exfiltration
    (r"/etc/shadow", "shadow file reference", "T1048", 30),
    (r"base64.*\|\s*curl", "base64 exfil via curl", "T1048", 35),
    
    # Persistence mechanisms
    (r"authorized_keys", "SSH authorized_keys manipulation", "T1098", 30),
]
```

## Data Flow Architecture

### Input Processing

```mermaid
graph LR
    A[Raw Command] --> B[Base64 Encoding]
    B --> C[Environment Variables]
    C --> D[Sandbox Execution]
    D --> E[State Snapshots]
    E --> F[Dimension Analysis]
    F --> G[Risk Scoring]
    G --> H[Verdict Generation]
```

### Report Generation

Each analysis produces multiple report formats:

1. **JSON Report**: Complete structured data
2. **Text Summary**: Human-readable format
3. **SARIF Report**: CI/CD integration format

## Performance Architecture

### Concurrency Model

```python
async def run_batch_analysis(commands):
    # Concurrent execution with semaphore limiting
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    
    async def analyze_single(cmd):
        async with semaphore:
            return await run_analysis(cmd)
    
    # Gather all results concurrently
    results = await asyncio.gather(*[
        analyze_single(cmd) for cmd in commands
    ])
    return results
```

### Resource Isolation

- **Docker Containers**: Per-command isolation
- **Memory Limits**: Configurable per container
- **CPU Shares**: Fair resource distribution
- **Network Isolation**: Prevent lateral movement

## Security Model

### Threat Model

The analyzer assumes:
- Commands may be malicious
- Attackers may use evasion techniques
- Sandboxes can be escaped (defense in depth)
- Network traffic may be malicious

### Mitigation Strategies

1. **Layered Defense**
   - Fast triage for obvious threats
   - Deep analysis for complex attacks
   - Multiple detection dimensions

2. **Isolation Boundaries**
   - Docker container separation
   - Network namespace isolation
   - File system isolation

3. **Monitoring Coverage**
   - Real-time system call tracing
   - Network traffic inspection
   - File system change monitoring

## Scalability Considerations

### Horizontal Scaling

```bash
# Distribute load across multiple instances
export INSTANCE_ID=$(hostname)
./run_all.sh --instance $INSTANCE_ID --total-instances 4
```

### Vertical Scaling

- **Memory**: Increase RAM for more concurrent analyses
- **CPU**: Add cores for faster individual analysis
- **Storage**: SSD storage for faster I/O operations

### Load Balancing

```python
# Round-robin job distribution
def distribute_jobs(jobs, num_workers):
    return [jobs[i::num_workers] for i in range(num_workers)]
```

## Future Architecture Improvements

### Planned Enhancements

1. **Machine Learning Integration**
   - Anomaly detection models
   - Behavioral clustering
   - Adaptive threshold tuning

2. **Cloud-Native Deployment**
   - Kubernetes operator
   - Serverless analysis functions
   - Distributed storage backend

3. **Advanced Evasion Detection**
   - Timing-based analysis
   - Environmental awareness
   - Multi-stage attack correlation

This architecture provides a robust foundation for detecting sophisticated attacks while maintaining performance and scalability.