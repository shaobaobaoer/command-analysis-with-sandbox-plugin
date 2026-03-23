# Integration Guide

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security-scan.yml
name: Command Security Scan

on:
  pull_request:
    branches: [ main, develop ]
  push:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.12'
    
    - name: Install dependencies
      run: |
        sudo apt update
        sudo apt install -y docker.io
        pip install -r requirements.txt
    
    - name: Pull sandbox images
      run: |
        docker pull opensandbox/code-interpreter:v1.0.2
        docker pull opensandbox/execd:v1.0.7
    
    - name: Run security analysis
      run: |
        # Analyze changed files
        git diff --name-only HEAD^ HEAD | while read file; do
          if [[ "$file" =~ \.(sh|bash|py)$ ]]; then
            echo "Analyzing $file"
            COMMAND="$(cat $file)" ./checker.sh
          fi
        done
    
    - name: Upload SARIF results
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: reports/
        category: command-security
```

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - security

security_scan:
  stage: security
  image: docker:20.10
  services:
    - docker:20.10-dind
  variables:
    DOCKER_DRIVER: overlay2
    DOCKER_TLS_CERTDIR: "/certs"
  
  before_script:
    - apk add --no-cache python3 py3-pip git
    - pip3 install -r requirements.txt
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
  
  script:
    - docker pull opensandbox/code-interpreter:v1.0.2
    - ./test_patterns.sh
    - ./run_all.sh --no-commit
    
  artifacts:
    reports:
      sarif: reports/*.sarif.json
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Analysis') {
            steps {
                sh '''
                    # Install dependencies
                    sudo apt update
                    sudo apt install -y docker.io python3-pip
                    pip3 install -r requirements.txt
                    
                    # Pull images
                    docker pull opensandbox/code-interpreter:v1.0.2
                    
                    # Run analysis
                    ./run_all.sh --no-commit
                    
                    # Check results
                    if [ $(grep -c "DANGEROUS\\|SUSPICIOUS" reports/summary.jsonl) -gt 0 ]; then
                        echo "Security violations found!"
                        exit 1
                    fi
                '''
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
        }
    }
}
```

## API Gateway Integration

### NGINX with Lua

```nginx
# nginx.conf
http {
    lua_package_path "/path/to/analyzer/?.lua;;";
    
    server {
        listen 8080;
        
        location /execute {
            access_by_lua_block {
                local analyzer = require "command_analyzer"
                local command = ngx.var.arg_cmd
                
                local result = analyzer.triage(command)
                
                if result.verdict == "BLOCK" then
                    ngx.status = 403
                    ngx.say("Command blocked: " .. result.reason)
                    ngx.exit(403)
                elseif result.verdict == "REVIEW" then
                    -- Forward to sandbox analysis
                    local full_result = analyzer.analyze(command)
                    if full_result.risk_score > 70 then
                        ngx.status = 403
                        ngx.say("High risk command blocked")
                        ngx.exit(403)
                    end
                end
            }
            
            proxy_pass http://backend;
        }
    }
}
```

### Express.js Middleware

```javascript
// securityMiddleware.js
const { spawn } = require('child_process');
const util = require('util');

class CommandAnalyzer {
    async triage(command) {
        return new Promise((resolve, reject) => {
            const child = spawn('./triage.sh', {
                env: { ...process.env, COMMAND: command }
            });
            
            let stdout = '';
            child.stdout.on('data', data => stdout += data);
            
            child.on('close', code => {
                resolve({
                    verdict: ['PASS', 'REVIEW', 'BLOCK'][code],
                    details: stdout.trim()
                });
            });
        });
    }
    
    async fullAnalysis(command) {
        // Similar implementation using checker.sh
    }
}

const analyzer = new CommandAnalyzer();

function securityMiddleware(req, res, next) {
    const command = req.body.command;
    
    analyzer.triage(command).then(result => {
        if (result.verdict === 'BLOCK') {
            return res.status(403).json({
                error: 'Command blocked',
                reason: result.details
            });
        }
        
        if (result.verdict === 'REVIEW') {
            // Perform full analysis for borderline cases
            return analyzer.fullAnalysis(command).then(fullResult => {
                if (fullResult.risk_score > 70) {
                    return res.status(403).json({
                        error: 'High risk command',
                        score: fullResult.risk_score
                    });
                }
                next();
            });
        }
        
        next();
    }).catch(next);
}

module.exports = securityMiddleware;
```

## SIEM Integration

### Splunk Integration

```python
# splunk_command_analyzer.py
import splunklib.client as client
import json
from analyzer.engine import run_analysis
import asyncio

class SplunkAnalyzer:
    def __init__(self, host, port, username, password):
        self.service = client.connect(
            host=host, port=port, username=username, password=password
        )
    
    async def analyze_suspicious_commands(self):
        # Search for suspicious shell commands
        search_query = 'search index=oslogs sourcetype="shell" command=* | stats count by command'
        
        jobs = self.service.jobs
        job = jobs.create(search_query)
        
        while not job.is_done():
            await asyncio.sleep(1)
        
        # Analyze each suspicious command
        results = job.results()
        for result in results:
            command = result['command']
            analysis = await run_analysis(command)
            
            # Send alerts for high-risk commands
            if analysis['risk_score'] > 60:
                self.send_alert(command, analysis)
    
    def send_alert(self, command, analysis):
        alert = {
            'event_type': 'suspicious_command',
            'command': command,
            'risk_score': analysis['risk_score'],
            'verdict': analysis['verdict'],
            'findings': analysis['findings']
        }
        
        # Send to Splunk HEC
        # Implementation details omitted
```

### ELK Stack Integration

```json
{
  "logstash": {
    "input": {
      "file": {
        "path": "/var/log/commands.log",
        "codec": "json"
      }
    },
    "filter": {
      "if": "[command] and [risk_score] > 50",
      "then": {
        "exec": {
          "command": "./checker.sh",
          "add_field": {
            "enriched_analysis": "%{message}"
          }
        }
      }
    },
    "output": {
      "elasticsearch": {
        "hosts": ["localhost:9200"],
        "index": "command-security-%{+YYYY.MM.dd}"
      }
    }
  }
}
```

## Cloud Platform Integration

### AWS Lambda

```python
# lambda_handler.py
import json
import boto3
from analyzer.engine import run_analysis
import asyncio

def lambda_handler(event, context):
    command = event.get('command')
    if not command:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing command'})
        }
    
    # Run analysis asynchronously
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(run_analysis(command))
    
    # Send to CloudWatch for monitoring
    cloudwatch = boto3.client('cloudwatch')
    cloudwatch.put_metric_data(
        Namespace='CommandSecurity',
        MetricData=[{
            'MetricName': 'RiskScore',
            'Value': result['risk_score'],
            'Unit': 'Count'
        }]
    )
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'verdict': result['verdict'],
            'score': result['risk_score'],
            'confidence': result['confidence']
        })
    }
```

### Google Cloud Functions

```python
# main.py
import functions_framework
from analyzer.engine import run_analysis
import asyncio

@functions_framework.http
def analyze_command(request):
    request_json = request.get_json(silent=True)
    command = request_json.get('command')
    
    if not command:
        return {'error': 'Missing command'}, 400
    
    # Run analysis
    result = asyncio.run(run_analysis(command))
    
    # Log to Cloud Logging
    import google.cloud.logging
    client = google.cloud.logging.Client()
    client.logger('command-security').log_struct({
        'command': command,
        'verdict': result['verdict'],
        'score': result['risk_score']
    })
    
    return {
        'verdict': result['verdict'],
        'score': result['risk_score'],
        'confidence': result['confidence']
    }
```

## Container Security Integration

### Kubernetes Admission Controller

```yaml
# admission-controller.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: command-security-admission
spec:
  replicas: 2
  selector:
    matchLabels:
      app: command-security
  template:
    metadata:
      labels:
        app: command-security
    spec:
      containers:
      - name: analyzer
        image: command-analyzer:latest
        ports:
        - containerPort: 8443
        volumeMounts:
        - name: tls-certs
          mountPath: /etc/certs
          readOnly: true
      volumes:
      - name: tls-certs
        secret:
          secretName: command-security-tls
```

```python
# admission_webhook.py
from flask import Flask, request, jsonify
import jsonpatch
from analyzer.engine import run_analysis
import asyncio

app = Flask(__name__)

@app.route('/mutate', methods=['POST'])
def mutate_pod():
    request_info = request.get_json()
    uid = request_info["request"]["uid"]
    
    # Extract commands from pod specification
    pod_spec = request_info["request"]["object"]["spec"]
    containers = pod_spec.get("containers", [])
    
    patches = []
    for i, container in enumerate(containers):
        command = container.get("command", [])
        if command:
            cmd_string = " ".join(command)
            result = asyncio.run(run_analysis(cmd_string))
            
            # Block high-risk commands
            if result["risk_score"] > 80:
                patches.append({
                    "op": "remove",
                    "path": f"/spec/containers/{i}/command"
                })
    
    return jsonify({
        "response": {
            "uid": uid,
            "allowed": len(patches) == 0,
            "patchType": "JSONPatch",
            "patch": jsonpatch.JsonPatch(patches).to_string()
        }
    })
```

## Monitoring and Alerting

### Prometheus Integration

```python
# prometheus_exporter.py
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import asyncio
from analyzer.engine import run_analysis

# Metrics
analysis_duration = Histogram('command_analysis_duration_seconds', 'Time spent analyzing commands')
analysis_count = Counter('command_analysis_total', 'Total number of analyses', ['verdict'])
risk_scores = Histogram('command_risk_scores', 'Distribution of risk scores', buckets=[0, 10, 25, 50, 75, 100])

class PrometheusAnalyzer:
    def __init__(self):
        start_http_server(8000)
    
    async def analyze_with_metrics(self, command):
        with analysis_duration.time():
            result = await run_analysis(command)
            analysis_count.labels(verdict=result['verdict']).inc()
            risk_scores.observe(result['risk_score'])
            return result

# Usage
analyzer = PrometheusAnalyzer()
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "Command Security Analytics",
    "panels": [
      {
        "title": "Analysis Throughput",
        "type": "graph",
        "targets": [
          "rate(command_analysis_total[5m])"
        ]
      },
      {
        "title": "Risk Score Distribution",
        "type": "heatmap",
        "targets": [
          "command_risk_scores_bucket"
        ]
      },
      {
        "title": "Verdict Distribution",
        "type": "piechart",
        "targets": [
          "sum by (verdict) (command_analysis_total)"
        ]
      },
      {
        "title": "Average Analysis Time",
        "type": "stat",
        "targets": [
          "avg(command_analysis_duration_seconds)"
        ]
      }
    ]
  }
}
```

## Performance Optimization for Integrations

### Connection Pooling

```python
# connection_pool.py
import asyncio
from asyncio import Semaphore
import aioredis

class AnalysisPool:
    def __init__(self, max_concurrent=10):
        self.semaphore = Semaphore(max_concurrent)
        self.redis = None
    
    async def initialize(self):
        self.redis = await aioredis.create_redis_pool('redis://localhost')
    
    async def analyze_command(self, command):
        async with self.semaphore:
            # Check cache first
            cache_key = f"analysis:{hash(command)}"
            cached = await self.redis.get(cache_key)
            if cached:
                return json.loads(cached)
            
            # Perform analysis
            result = await run_analysis(command)
            
            # Cache result
            await self.redis.setex(cache_key, 3600, json.dumps(result))
            return result
```

### Asynchronous Processing

```python
# async_processor.py
import asyncio
import aiofiles
from analyzer.engine import run_analysis

class AsyncCommandProcessor:
    def __init__(self, max_workers=4):
        self.semaphore = asyncio.Semaphore(max_workers)
    
    async def process_command_queue(self, input_file, output_file):
        async with aiofiles.open(input_file, 'r') as infile, \
                   aiofiles.open(output_file, 'w') as outfile:
            
            tasks = []
            async for line in infile:
                command = line.strip()
                task = self.process_single_command(command)
                tasks.append(task)
            
            # Process in batches
            for i in range(0, len(tasks), 10):
                batch = tasks[i:i+10]
                results = await asyncio.gather(*batch, return_exceptions=True)
                
                for result in results:
                    if not isinstance(result, Exception):
                        await outfile.write(json.dumps(result) + '\n')
    
    async def process_single_command(self, command):
        async with self.semaphore:
            return await run_analysis(command)
```

These integration patterns provide robust ways to incorporate command security analysis into various operational environments while maintaining performance and reliability.