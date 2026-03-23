# Installation Guide

## System Requirements

### Minimum Requirements
- **Operating System**: Linux (Ubuntu 20.04+, CentOS 8+, Debian 11+)
- **CPU**: 2 cores minimum, 4 cores recommended
- **RAM**: 4GB minimum, 8GB recommended
- **Disk Space**: 10GB free space
- **Docker**: Version 20.10+ (for sandbox isolation)

### Software Dependencies

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y docker.io python3 python3-pip git

# CentOS/RHEL
sudo yum install -y docker python3 python3-pip git
```

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/command-analysis-with-sandbox-plugin.git
cd command-analysis-with-sandbox-plugin
```

### 2. Install Python Dependencies

```bash
# Using system Python (recommended for production)
pip3 install -r requirements.txt

# Or create a virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure Docker

```bash
# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add current user to docker group (optional but recommended)
sudo usermod -aG docker $USER
# Logout and login again for group changes to take effect
```

### 4. Pull Required Docker Images

```bash
# Pull the main sandbox images
docker pull opensandbox/code-interpreter:v1.0.2
docker pull opensandbox/execd:v1.0.7
```

### 5. Test Installation

```bash
# Run basic tests
./test_patterns.sh

# Run a simple command analysis
COMMAND="echo hello" ./checker.sh
```

## Configuration

### Environment Variables

Create a `.env` file for persistent configuration:

```bash
# .env
SANDBOX_PORT=8080
REGISTRY_MIRROR=sandbox-registry.cn-zhangjiakou.cr.aliyuncs.com/opensandbox
REPORT_DIR=./reports
MAX_CONCURRENT_JOBS=4
```

### Scoring Configuration

Adjust detection thresholds in `scoring.conf`:

```ini
# Critical thresholds
BLOCK_THRESHOLD=50
DANGEROUS_THRESHOLD=60
SUSPICIOUS_THRESHOLD=25

# Behavior tolerances
HIDDEN_PROC_TOLERANCE=10
ENTROPY_THRESHOLD=6.5

# C2 detection
C2_PORTS=4444,5555,6666,7777,8888,9999,1234,31337
```

## Performance Tuning

### Memory Optimization

For memory-constrained environments:

```bash
# Limit Docker container memory
export DOCKER_MEMORY_LIMIT=512m

# Reduce concurrent jobs
export MAX_CONCURRENT_JOBS=2
```

### CPU Optimization

For CPU-constrained environments:

```bash
# Limit CPU shares
export DOCKER_CPU_SHARES=512

# Use fewer worker threads
export WORKER_THREADS=2
```

## Troubleshooting

### Common Issues

1. **Docker Permission Denied**
   ```bash
   # Solution: Add user to docker group
   sudo usermod -aG docker $USER
   ```

2. **Port Already in Use**
   ```bash
   # Solution: Change port
   export SANDBOX_PORT=8081
   ```

3. **Insufficient Memory**
   ```bash
   # Solution: Increase swap or reduce concurrent jobs
   export MAX_CONCURRENT_JOBS=1
   ```

4. **Image Pull Failures**
   ```bash
   # Solution: Use mirror or retry
   export REGISTRY_MIRROR=your-mirror-address
   ```

### Verification Commands

```bash
# Check Docker status
docker info

# Test Python environment
python3 -c "import asyncio; print('Asyncio OK')"

# Verify sandbox images
docker images | grep opensandbox
```

## Upgrade Process

To upgrade from a previous version:

```bash
# Backup current configuration
cp scoring.conf scoring.conf.backup

# Pull latest changes
git pull origin main

# Update dependencies
pip3 install -r requirements.txt --upgrade

# Restore configuration
cp scoring.conf.backup scoring.conf

# Run tests
./test_patterns.sh
```

## Next Steps

Once installed, proceed to the {doc}`quickstart` guide to begin analyzing commands.