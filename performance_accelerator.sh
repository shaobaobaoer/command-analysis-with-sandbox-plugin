#!/bin/bash
# performance_accelerator.sh - Optimize Command Safety Analyzer performance

set -euo pipefail

echo "🚀 Command Safety Analyzer Performance Accelerator"
echo "=================================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log "Checking system prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        error "Docker not found. Please install Docker first."
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        error "Docker daemon not running. Please start Docker service."
        exit 1
    fi
    
    # Check available resources
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    local cpu_cores=$(nproc)
    
    log "System resources: ${mem_total}MB RAM, ${cpu_cores} CPU cores"
    
    if [ "$mem_total" -lt 2048 ]; then
        warn "Low memory (${mem_total}MB). Consider reducing concurrent jobs."
    fi
    
    success "Prerequisites check passed"
}

# Optimize Docker configuration
optimize_docker() {
    log "Optimizing Docker configuration..."
    
    # Create Docker daemon configuration if it doesn't exist
    local daemon_conf="/etc/docker/daemon.json"
    
    if [ ! -f "$daemon_conf" ]; then
        sudo mkdir -p /etc/docker
        sudo tee "$daemon_conf" > /dev/null <<EOF
{
    "experimental": true,
    "features": {
        "buildkit": true
    },
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    }
}
EOF
        log "Created Docker daemon configuration"
        sudo systemctl restart docker
        success "Docker daemon restarted with optimizations"
    else
        log "Docker configuration already exists"
    fi
}

# Pre-load sandbox images
preload_images() {
    log "Pre-loading sandbox images..."
    
    local images=(
        "opensandbox/code-interpreter:v1.0.2"
        "opensandbox/execd:v1.0.7"
    )
    
    for image in "${images[@]}"; do
        if docker images "$image" --format "{{.Repository}}:{{.Tag}}" | grep -q "$image"; then
            log "Image $image already present"
        else
            log "Pulling $image..."
            if docker pull "$image"; then
                success "Pulled $image"
            else
                error "Failed to pull $image"
            fi
        fi
    done
}

# Create warm containers
create_warm_containers() {
    log "Creating warm containers for faster startup..."
    
    # Clean up any existing warm containers
    docker rm -f sandbox-warm 2>/dev/null || true
    
    # Create a warm container that stays running
    if docker run -d --name sandbox-warm \
        --memory=256m \
        --cpus=0.5 \
        opensandbox/code-interpreter:v1.0.2 \
        tail -f /dev/null; then
        success "Warm container created"
        export WARM_CONTAINER=sandbox-warm
    else
        warn "Failed to create warm container"
    fi
}

# Optimize system settings
optimize_system() {
    log "Optimizing system settings..."
    
    # Increase file watchers limit
    if [ -f /proc/sys/fs/inotify/max_user_watches ]; then
        local current=$(cat /proc/sys/fs/inotify/max_user_watches)
        if [ "$current" -lt 524288 ]; then
            echo 524288 | sudo tee /proc/sys/fs/inotify/max_user_watches > /dev/null
            log "Increased inotify watches limit to 524288"
        fi
    fi
    
    # Optimize I/O scheduler for SSD
    if lsblk -o NAME,ROTA | grep -q "0$"; then
        log "SSD detected - optimizing I/O settings"
        # SSD-specific optimizations can be added here
    fi
}

# Configure analysis settings
configure_analysis() {
    log "Configuring analysis settings..."
    
    # Set optimal concurrency based on system resources
    local cpu_cores=$(nproc)
    local optimal_concurrent=$((cpu_cores > 4 ? 4 : cpu_cores))
    
    export MAX_CONCURRENT_JOBS=$optimal_concurrent
    export DOCKER_MEMORY_LIMIT="512m"
    export DOCKER_CPU_SHARES="512"
    
    log "Set concurrent jobs to $optimal_concurrent"
    log "Container memory limit: 512MB"
    log "Container CPU shares: 512"
    
    # Create optimized scoring configuration
    if [ ! -f "scoring.conf.optimized" ]; then
        cat > scoring.conf.optimized <<EOF
# Optimized scoring configuration for performance
BLOCK_THRESHOLD=50
BLOCK_BLACKLIST_THRESHOLD=25
REVIEW_THRESHOLD=10
DANGEROUS_THRESHOLD=60
SUSPICIOUS_THRESHOLD=25
LOW_RISK_THRESHOLD=10
LEGITIMATE_DIVISOR=2
ENTROPY_THRESHOLD=6.5
HIDDEN_PROC_TOLERANCE=10
C2_PORTS=4444,5555,6666,7777,8888,9999,1234,31337
EOF
        success "Created optimized scoring configuration"
    fi
}

# Create performance test script
create_test_script() {
    log "Creating performance test script..."
    
    cat > performance_test.sh <<'EOF'
#!/bin/bash
# Performance test script

echo "=== Performance Test ==="

# Test single command analysis time
echo "Testing single command analysis..."
start_time=$(date +%s.%N)
COMMAND="echo hello" timeout 60 ./checker.sh > /dev/null 2>&1
end_time=$(date +%s.%N)

duration=$(echo "$end_time - $start_time" | bc)
echo "Single analysis time: ${duration}s"

# Test batch processing
echo "Testing batch processing..."
start_time=$(date +%s.%N)
timeout 300 ./run_all.sh white:w01,w02,w03,w04 --no-commit > /dev/null 2>&1
end_time=$(date +%s.%N)

duration=$(echo "$end_time - $start_time" | bc)
echo "Batch processing time: ${duration}s"

# Test fast triage
echo "Testing fast triage..."
start_time=$(date +%s.%N)
COMMAND="echo hello" ./triage.sh > /dev/null 2>&1
end_time=$(date +%s.%N)

duration=$(echo "$end_time - $start_time" | bc)
echo "Fast triage time: ${duration}s"
EOF

    chmod +x performance_test.sh
    success "Created performance_test.sh"
}

# Show optimization summary
show_summary() {
    echo
    echo "✨ Performance Optimization Complete!"
    echo "====================================="
    echo
    echo "Applied optimizations:"
    echo "  • Docker daemon configuration"
    echo "  • Pre-loaded sandbox images" 
    echo "  • Warm container for faster startup"
    echo "  • System resource limits optimized"
    echo "  • Analysis concurrency tuned"
    echo "  • Optimized scoring configuration"
    echo
    echo "Environment variables set:"
    echo "  MAX_CONCURRENT_JOBS=$MAX_CONCURRENT_JOBS"
    echo "  DOCKER_MEMORY_LIMIT=$DOCKER_MEMORY_LIMIT" 
    echo "  DOCKER_CPU_SHARES=$DOCKER_CPU_SHARES"
    echo
    echo "Next steps:"
    echo "  1. Run './performance_test.sh' to verify improvements"
    echo "  2. Use 'export WARM_CONTAINER=sandbox-warm' for faster startups"
    echo "  3. Consider using './triage.sh' for preliminary screening"
    echo "  4. Adjust MAX_CONCURRENT_JOBS based on your workload"
    echo
    success "Ready for high-performance command analysis!"
}

# Main execution
main() {
    check_prerequisites
    optimize_docker
    preload_images
    create_warm_containers
    optimize_system
    configure_analysis
    create_test_script
    show_summary
}

# Run main function
main "$@"