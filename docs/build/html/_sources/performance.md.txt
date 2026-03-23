# Performance Optimization Guide

## Current Performance Baseline

### Typical Performance Metrics

| Operation | Time | Resource Usage |
|-----------|------|----------------|
| Fast Triage | &lt; 50ms | &lt; 10MB RAM |
| Full Analysis | 15-30 seconds | ~200MB RAM |
| Batch Processing (4 concurrent) | Variable | ~800MB RAM peak |

### Bottleneck Analysis

The main performance bottlenecks are:

1. **Docker Container Startup**: ~3-5 seconds per analysis
2. **Snapshot Collection**: ~2-4 seconds for full system scan
3. **Pattern Matching**: ~1-2 seconds for content analysis
4. **Report Generation**: ~0.5 seconds for JSON/text/SARIF

## Optimization Strategies

### 1. Concurrency Optimization

#### Increase Parallel Processing

```bash
# Adjust concurrent job limit
export MAX_CONCURRENT_JOBS=8

# For memory-constrained systems
export MAX_CONCURRENT_JOBS=2
export DOCKER_MEMORY_LIMIT=256m
```

#### Worker Pool Management

```python
# Optimal worker configuration
WORKER_CONFIG = {
    'cpu_bound': multiprocessing.cpu_count() - 1,
    'io_bound': multiprocessing.cpu_count() * 2,
    'memory_limit_per_worker': '512m'
}
```

### 2. Docker Optimization

#### Image Pre-loading

```bash
# Pre-pull images to avoid delays
docker pull opensandbox/code-interpreter:v1.0.2
docker pull opensandbox/execd:v1.0.7

# Use local registry mirror
export REGISTRY_MIRROR=your-local-mirror.com/opensandbox
```

#### Container Resource Limits

```bash
# Optimize container resources
DOCKER_OPTS="--memory=512m --cpus=1.0 --oom-kill-disable"

# For high-throughput environments
DOCKER_OPTS="--memory=1g --cpus=2.0 --restart=no"
```

### 3. Caching Strategies

#### Snapshot Caching

```python
class SnapshotCache:
    def __init__(self):
        self.cache = {}
        self.max_size = 100  # Cache last 100 baselines
    
    async def get_cached_baseline(self, container_config):
        cache_key = hash_container_config(container_config)
        if cache_key in self.cache:
            return self.cache[cache_key]
        # Generate new baseline and cache it
        baseline = await self.generate_baseline(container_config)
        self.cache[cache_key] = baseline
        return baseline
```

#### Pattern Compilation Caching

```python
# Compile regex patterns once at startup
COMPILED_PATTERNS = {
    name: re.compile(pattern, re.IGNORECASE) 
    for name, pattern, _, _ in ARTIFACT_PATTERNS
}
```

### 4. Selective Analysis

#### Dimension Prioritization

```python
# Focus on high-value dimensions first
HIGH_PRIORITY_DIMENSIONS = [
    '网络行为',      # Network behavior
    '持久化机制',    # Persistence  
    '文件变更',      # File changes
    '用户权限',      # User/permissions
]

def selective_analysis(enabled_dimensions=None):
    if enabled_dimensions is None:
        enabled_dimensions = HIGH_PRIORITY_DIMENSIONS
    # Only run specified dimensions
    return run_analysis(dimensions=enabled_dimensions)
```

#### Early Termination

```python
class EarlyTerminationAnalyzer:
    def __init__(self, threshold=80):
        self.threshold = threshold
        
    async def analyze_with_early_exit(self, command):
        critical_findings = []
        
        # Run critical dimensions first
        for dimension in CRITICAL_DIMENSIONS:
            findings = await self.run_dimension(dimension, command)
            critical_findings.extend(findings)
            
            # Check if we can terminate early
            current_score = self.calculate_score(critical_findings)
            if current_score >= self.threshold:
                return self.final_verdict(current_score, critical_findings)
                
        # Continue with remaining dimensions
        return await self.complete_analysis(critical_findings)
```

## Advanced Optimization Techniques

### 1. Warm Start Optimization

```bash
# Keep sandbox containers warm
docker run -d --name sandbox-warm opensandbox/code-interpreter:v1.0.2 tail -f /dev/null

# Reuse warm containers for analysis
export WARM_CONTAINER=sandbox-warm
```

### 2. Streaming Analysis

```python
async def streaming_analysis(command):
    """Analyze command output as it's generated"""
    
    # Start command execution
    process = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    
    # Stream analysis
    async def analyze_stream(stream, stream_name):
        buffer = ""
        async for line in stream:
            buffer += line.decode()
            if len(buffer) > 1000:  # Process in chunks
                await analyze_buffer_chunk(buffer, stream_name)
                buffer = ""
    
    # Run concurrent stream analysis
    await asyncio.gather(
        analyze_stream(process.stdout, 'stdout'),
        analyze_stream(process.stderr, 'stderr')
    )
```

### 3. Incremental State Tracking

```python
class IncrementalStateTracker:
    def __init__(self):
        self.previous_state = None
        self.state_diff_cache = {}
    
    def get_incremental_changes(self, current_state):
        if self.previous_state is None:
            self.previous_state = current_state
            return current_state
            
        # Only analyze what changed
        changes = diff_states(self.previous_state, current_state)
        self.previous_state = current_state
        return changes
```

## Benchmarking Framework

### Performance Testing Script

```bash
#!/bin/bash
# benchmark_optimization.sh

echo "=== Performance Benchmark ==="

# Test different configurations
configs=(
    "MAX_CONCURRENT_JOBS=1"
    "MAX_CONCURRENT_JOBS=4" 
    "MAX_CONCURRENT_JOBS=8"
    "DOCKER_MEMORY_LIMIT=256m"
    "DOCKER_MEMORY_LIMIT=512m"
)

for config in "${configs[@]}"; do
    echo "Testing: $config"
    export $config
    time ./run_all.sh white:w01,w02,w03,w04 2>/dev/null
    echo "---"
done
```

### Detailed Profiling

```python
import cProfile
import pstats
from pstats import SortKey

def profile_analysis():
    profiler = cProfile.Profile()
    profiler.enable()
    
    # Run analysis
    asyncio.run(run_analysis("test command"))
    
    profiler.disable()
    
    # Print statistics
    stats = pstats.Stats(profiler)
    stats.sort_stats(SortKey.TIME)
    stats.print_stats(20)  # Top 20 functions
```

## Resource Monitoring

### Real-time Monitoring Script

```bash
#!/bin/bash
# monitor_resources.sh

while true; do
    echo "=== $(date) ==="
    echo "CPU Usage:"
    top -bn1 | head -20
    
    echo "Memory Usage:"
    free -h
    
    echo "Docker Stats:"
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"
    
    echo "Analysis Queue:"
    ps aux | grep checker.sh | wc -l
    
    sleep 10
done
```

### Container Resource Optimization

```yaml
# docker-compose.optimized.yml
version: '3.8'
services:
  analyzer:
    image: opensandbox/code-interpreter:v1.0.2
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '1.0'
        reservations:
          memory: 256M
          cpus: '0.5'
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=100m
```

## Scaling Strategies

### Horizontal Scaling

```python
# Load balancer for distributed analysis
class AnalysisLoadBalancer:
    def __init__(self, workers):
        self.workers = workers
        self.current_worker = 0
    
    def get_next_worker(self):
        worker = self.workers[self.current_worker]
        self.current_worker = (self.current_worker + 1) % len(self.workers)
        return worker
    
    async def distribute_analysis(self, commands):
        tasks = []
        for command in commands:
            worker = self.get_next_worker()
            task = worker.analyze(command)
            tasks.append(task)
        
        return await asyncio.gather(*tasks)
```

### Cloud-Native Scaling

```yaml
# Kubernetes deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: command-analyzer
spec:
  replicas: 4
  selector:
    matchLabels:
      app: command-analyzer
  template:
    metadata:
      labels:
        app: command-analyzer
    spec:
      containers:
      - name: analyzer
        image: command-analyzer:latest
        resources:
          requests:
            memory: "256Mi"
            cpu: "500m"
          limits:
            memory: "512Mi" 
            cpu: "1000m"
```

## Performance Targets

### Optimization Goals

| Metric | Current | Target | Improvement |
|--------|---------|---------|-------------|
| Single Analysis Time | 20s | 10s | 2x faster |
| Batch Throughput | 4 cmds/min | 12 cmds/min | 3x improvement |
| Memory Usage | 200MB/cmd | 100MB/cmd | 2x reduction |
| CPU Efficiency | 70% | 85% | 15% better |

### Monitoring Dashboard

Create a performance dashboard using tools like Grafana:

```json
{
  "dashboard": {
    "title": "Command Analyzer Performance",
    "panels": [
      {
        "title": "Analysis Throughput",
        "type": "graph",
        "targets": ["rate(analysis_completed[5m])"]
      },
      {
        "title": "Average Analysis Time", 
        "type": "stat",
        "targets": ["avg(analysis_duration_seconds)"]
      },
      {
        "title": "Resource Utilization",
        "type": "graph",
        "targets": ["container_memory_usage_bytes", "container_cpu_usage_seconds_total"]
      }
    ]
  }
}
```

## Best Practices Summary

1. **Start with profiling** to identify actual bottlenecks
2. **Optimize Docker startup** through pre-loading and caching
3. **Use appropriate concurrency** levels for your hardware
4. **Implement selective analysis** for time-sensitive applications
5. **Monitor resource usage** continuously in production
6. **Scale horizontally** rather than vertically when possible
7. **Cache aggressively** baseline snapshots and compiled patterns
8. **Consider streaming** for long-running analyses

The key is to measure first, then optimize based on actual performance data rather than assumptions.