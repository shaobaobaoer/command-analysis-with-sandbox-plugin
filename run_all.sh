#!/usr/bin/env bash
# ============================================================================
#  批量安全检测 + 自动 Git 提交
#
#  用法:
#    chmod +x run_all.sh && ./run_all.sh
#
#  可选参数:
#    ./run_all.sh white          # 只跑白样本
#    ./run_all.sh black          # 只跑黑样本
#    ./run_all.sh white:w01      # 只跑指定 ID
#    ./run_all.sh --no-commit    # 不自动提交
#
#  环境变量:
#    SANDBOX_PORT    — 服务端口 (默认 8080)
#    REGISTRY_MIRROR — 镜像加速
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAMPLES_DIR="${SCRIPT_DIR}/samples"
REPORTS_DIR="${SCRIPT_DIR}/reports"
CHECKER="${SCRIPT_DIR}/checker.sh"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }

# ─── 解析参数 ────────────────────────────────────────────
FILTER="${1:-all}"
AUTO_COMMIT=true
for arg in "$@"; do
    [ "$arg" = "--no-commit" ] && AUTO_COMMIT=false
done

echo ""
echo -e "${BOLD}============================================"
echo "  Command Safety Batch Analyzer"
echo -e "============================================${NC}"
echo ""

# ─── 前置检查 ────────────────────────────────────────────
command -v docker &>/dev/null || { fail "Docker 未安装"; exit 1; }
docker info &>/dev/null 2>&1 || { fail "Docker 未运行"; exit 1; }
command -v python3 &>/dev/null || { fail "Python3 未安装"; exit 1; }
[ -f "$CHECKER" ] || { fail "checker.sh 不存在: $CHECKER"; exit 1; }
chmod +x "$CHECKER"

# ─── 环境准备 (只做一次) ──────────────────────────────────
# 启动 server 的工作交给 checker.sh, 但镜像预拉取可以提前做
info "预检查 Docker 镜像..."
REGISTRY_MIRROR="${REGISTRY_MIRROR:-}"
if [ -n "$REGISTRY_MIRROR" ]; then
    SANDBOX_IMAGE="${REGISTRY_MIRROR}/code-interpreter:v1.0.2"
    EXECD_IMAGE="${REGISTRY_MIRROR}/execd:v1.0.7"
else
    SANDBOX_IMAGE="${SANDBOX_IMAGE:-opensandbox/code-interpreter:v1.0.2}"
    EXECD_IMAGE="${EXECD_IMAGE:-opensandbox/execd:v1.0.7}"
fi

for img in "$SANDBOX_IMAGE" "$EXECD_IMAGE"; do
    if docker image inspect "$img" &>/dev/null; then
        ok "镜像就绪: $img"
    else
        info "拉取: $img"
        docker pull "$img"
    fi
done

# ─── 收集样本 ────────────────────────────────────────────
declare -a JOBS=()    # "category|id|label|desc|command"

add_samples() {
    local file="$1" category="$2"
    [ -f "$file" ] || return 0
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local id desc label command
        id=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['id'])")
        desc=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['desc'])")
        label=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['label'])")
        command=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['command'])")
        JOBS+=("${category}|${id}|${label}|${desc}|${command}")
    done < "$file"
}

case "$FILTER" in
    all)
        add_samples "${SAMPLES_DIR}/white.jsonl" "white"
        add_samples "${SAMPLES_DIR}/black.jsonl" "black"
        ;;
    white)
        add_samples "${SAMPLES_DIR}/white.jsonl" "white"
        ;;
    black)
        add_samples "${SAMPLES_DIR}/black.jsonl" "black"
        ;;
    white:*|black:*)
        category="${FILTER%%:*}"
        target_id="${FILTER##*:}"
        add_samples "${SAMPLES_DIR}/${category}.jsonl" "$category"
        # 过滤到指定 ID
        FILTERED=()
        for job in "${JOBS[@]}"; do
            job_id=$(echo "$job" | cut -d'|' -f2)
            [ "$job_id" = "$target_id" ] && FILTERED+=("$job")
        done
        JOBS=("${FILTERED[@]}")
        ;;
    *)
        fail "未知参数: $FILTER (用法: all, white, black, white:w01)"
        exit 1
        ;;
esac

TOTAL=${#JOBS[@]}
info "共 ${TOTAL} 个样本待检测"
echo ""

# ─── 逐个执行 ────────────────────────────────────────────
PASS=0; FAIL_COUNT=0; ERROR=0
SUMMARY_FILE="${REPORTS_DIR}/summary.jsonl"

# 清空旧 summary (当前批次)
> "$SUMMARY_FILE"

for i in "${!JOBS[@]}"; do
    IFS='|' read -r category id label desc command <<< "${JOBS[$i]}"
    idx=$((i + 1))
    report_dir="${REPORTS_DIR}/${category}"
    mkdir -p "$report_dir"
    report_file="${report_dir}/${id}.json"
    log_file="${report_dir}/${id}.log"

    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    info "[${idx}/${TOTAL}] ${category}/${id}: ${desc}"
    info "命令: ${command}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # 调用 checker.sh, 传入命令和报告目录
    export COMMAND="$command"
    export REPORT_DIR="$report_dir"
    export SANDBOX_IMAGE EXECD_IMAGE REGISTRY_MIRROR

    if bash "$CHECKER" > "$log_file" 2>&1; then
        checker_exit=0
    else
        checker_exit=$?
    fi

    # 找到最新生成的报告, 重命名为 {id}.json
    latest_report=$(ls -t "${report_dir}"/safety_report_*.json 2>/dev/null | head -1)
    if [ -n "$latest_report" ] && [ -f "$latest_report" ]; then
        mv "$latest_report" "$report_file"
        verdict=$(python3 -c "import json; print(json.load(open('${report_file}'))['verdict'])" 2>/dev/null || echo "UNKNOWN")
    else
        verdict="ERROR"
        echo "{\"command\":\"${command}\",\"verdict\":\"ERROR\",\"error\":\"checker failed with exit ${checker_exit}\"}" > "$report_file"
    fi

    # 判断检测结果是否符合预期
    expected="LIKELY_SAFE"
    [ "$label" = "malicious" ] && expected="DANGEROUS"

    if [ "$label" = "safe" ] && [ "$verdict" = "LIKELY_SAFE" ]; then
        match="CORRECT"
        ok "[${id}] 预期=safe, 实际=${verdict} -> 正确"
        PASS=$((PASS + 1))
    elif [ "$label" = "malicious" ] && { [ "$verdict" = "DANGEROUS" ] || [ "$verdict" = "SUSPICIOUS" ]; }; then
        match="CORRECT"
        ok "[${id}] 预期=malicious, 实际=${verdict} -> 正确"
        PASS=$((PASS + 1))
    elif [ "$verdict" = "ERROR" ]; then
        match="ERROR"
        fail "[${id}] 执行出错"
        ERROR=$((ERROR + 1))
    else
        match="WRONG"
        warn "[${id}] 预期=${label}, 实际=${verdict} -> 误判!"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    # 写入 summary
    echo "{\"id\":\"${id}\",\"category\":\"${category}\",\"label\":\"${label}\",\"desc\":\"${desc}\",\"verdict\":\"${verdict}\",\"match\":\"${match}\"}" >> "$SUMMARY_FILE"
done

# ─── 汇总报告 ────────────────────────────────────────────
echo ""
echo -e "${BOLD}======================================================================${NC}"
echo -e "${BOLD}  批量检测完成${NC}"
echo -e "${BOLD}======================================================================${NC}"
echo ""
echo "  总样本   : ${TOTAL}"
echo -e "  正确判定 : ${GREEN}${PASS}${NC}"
echo -e "  误判     : ${YELLOW}${FAIL_COUNT}${NC}"
echo -e "  错误     : ${RED}${ERROR}${NC}"
echo "  准确率   : $(python3 -c "print(f'{${PASS}/${TOTAL}*100:.1f}%')" 2>/dev/null || echo 'N/A')"
echo ""
echo "  详细结果 : ${SUMMARY_FILE}"
echo ""

# 打印 summary 表格
echo "  ID     Category  Label      Verdict       Match"
echo "  ─────  ────────  ─────────  ────────────  ──────"
while IFS= read -r line; do
    sid=$(echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(f\"  {d['id']:<6s} {d['category']:<9s} {d['label']:<10s} {d['verdict']:<13s} {d['match']}\")")
    echo "$sid"
done < "$SUMMARY_FILE"
echo ""

# ─── Git 提交 ────────────────────────────────────────────
if [ "$AUTO_COMMIT" = true ] && [ -d "${SCRIPT_DIR}/.git" ]; then
    info "提交结果到 Git..."
    cd "$SCRIPT_DIR"
    git add reports/ samples/
    git add checker.sh run_all.sh
    git add README.md 2>/dev/null || true

    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    COMMIT_MSG="batch: ${TOTAL} samples (${PASS} correct, ${FAIL_COUNT} wrong, ${ERROR} error) @ ${TIMESTAMP}"

    if git diff --cached --quiet; then
        info "无新变更, 跳过提交"
    else
        git commit -m "$COMMIT_MSG"
        ok "已提交: ${COMMIT_MSG}"

        # 推送
        if git remote get-url origin &>/dev/null; then
            info "推送到 origin..."
            if git push -u origin main 2>/dev/null || git push -u origin master 2>/dev/null; then
                ok "推送完成"
            else
                warn "推送失败, 请手动 git push"
            fi
        fi
    fi
fi

echo ""
ok "全部完成!"
