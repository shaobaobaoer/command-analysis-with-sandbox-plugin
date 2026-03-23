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
