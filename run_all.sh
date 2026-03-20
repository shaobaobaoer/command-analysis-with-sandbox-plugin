#!/usr/bin/env bash
# ============================================================================
#  批量安全检测 + 自动 Git 提交 (v4 — 配合 Behavioral Analysis Engine v4)
#
#  用法:
#    chmod +x run_all.sh && ./run_all.sh
#
#  可选参数:
#    ./run_all.sh white          # 只跑白样本
#    ./run_all.sh black          # 只跑黑样本
#    ./run_all.sh white:w01      # 只跑指定 ID
#    ./run_all.sh --no-commit    # 不自动提交
#    ./run_all.sh --retry N      # 失败重试次数 (默认 1)
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
FILTER="all"
AUTO_COMMIT=true
MAX_RETRY=1
args=("$@")
for i in "${!args[@]}"; do
    case "${args[$i]}" in
        --no-commit) AUTO_COMMIT=false ;;
        --retry) MAX_RETRY="${args[$((i+1))]}" ;;
        --*) ;; # skip other flags
        *)
            # Skip values consumed by --retry
            if [ "$i" -gt 0 ] && [ "${args[$((i-1))]}" = "--retry" ]; then
                continue
            fi
            FILTER="${args[$i]}"
            ;;
    esac
done

echo ""
echo -e "${BOLD}============================================"
echo "  Command Safety Batch Analyzer v4"
echo -e "============================================${NC}"
echo ""

# ─── 前置检查 ────────────────────────────────────────────
command -v docker &>/dev/null || { fail "Docker 未安装"; exit 1; }
docker info &>/dev/null 2>&1 || { fail "Docker 未运行"; exit 1; }
command -v python3 &>/dev/null || { fail "Python3 未安装"; exit 1; }
[ -f "$CHECKER" ] || { fail "checker.sh 不存在: $CHECKER"; exit 1; }
chmod +x "$CHECKER"

# ─── 环境准备 (只做一次) ──────────────────────────────────
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
        # Use ASCII record separator (0x1E) as delimiter
        JOBS+=("${category}"$'\x1e'"${id}"$'\x1e'"${label}"$'\x1e'"${desc}"$'\x1e'"${command}")
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
        FILTERED=()
        for job in "${JOBS[@]}"; do
            IFS=$'\x1e' read -r _ job_id _ _ _ <<< "$job"
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

# 清空旧 summary
> "$SUMMARY_FILE"

for i in "${!JOBS[@]}"; do
    IFS=$'\x1e' read -r category id label desc command <<< "${JOBS[$i]}"
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

    export COMMAND="$command"
    export REPORT_DIR="$report_dir"
    export SANDBOX_IMAGE EXECD_IMAGE REGISTRY_MIRROR

    # 带重试的执行
    checker_exit=1
    for attempt in $(seq 1 "$MAX_RETRY"); do
        if [ "$attempt" -gt 1 ]; then
            warn "[${id}] 重试 (${attempt}/${MAX_RETRY})..."
        fi
        if bash "$CHECKER" > "$log_file" 2>&1; then
            checker_exit=0
            break
        else
            checker_exit=$?
            if [ "$attempt" -lt "$MAX_RETRY" ]; then
                sleep 2
            fi
        fi
    done

    # 找到最新报告并重命名 (支持 .json 和 .sarif.json 两种格式)
    latest_report=$(ls -t "${report_dir}"/safety_report_*.json 2>/dev/null | grep -v sarif | head -1)
    if [ -z "$latest_report" ]; then
        latest_report=$(ls -t "${report_dir}"/safety_report_*.sarif.json 2>/dev/null | head -1)
    fi
    if [ -n "$latest_report" ] && [ -f "$latest_report" ]; then
        mv "$latest_report" "$report_file"
        # Parse SARIF format JSON - verdict is in runs[0].tool.driver.properties.verdict or invocations[0].properties.verdict
        verdict=$(python3 -c "
import json
try:
    data = json.load(open('${report_file}'))
    # Try SARIF format first
    if 'runs' in data and len(data['runs']) > 0:
        run = data['runs'][0]
        # Try tool.driver.properties
        if 'tool' in run and 'driver' in run['tool'] and 'properties' in run['tool']['driver']:
            v = run['tool']['driver']['properties'].get('verdict')
            if v:
                print(v)
                exit(0)
        # Try invocations[0].properties
        if 'invocations' in run and len(run['invocations']) > 0 and 'properties' in run['invocations'][0]:
            v = run['invocations'][0]['properties'].get('verdict')
            if v:
                print(v)
                exit(0)
    # Fallback to direct property
    if 'verdict' in data:
        print(data['verdict'])
        exit(0)
    print('UNKNOWN')
except Exception as e:
    print('UNKNOWN')
" 2>/dev/null || echo "UNKNOWN")
        risk_score=$(python3 -c "
import json
try:
    data = json.load(open('${report_file}'))
    if 'runs' in data and len(data['runs']) > 0:
        run = data['runs'][0]
        if 'tool' in run and 'driver' in run['tool'] and 'properties' in run['tool']['driver']:
            print(run['tool']['driver']['properties'].get('risk_score', -1))
            exit(0)
        if 'invocations' in run and len(run['invocations']) > 0 and 'properties' in run['invocations'][0]:
            print(run['invocations'][0]['properties'].get('risk_score', -1))
            exit(0)
    print(data.get('risk_score', -1))
except:
    print(-1)
" 2>/dev/null || echo "-1")
        mitre_count=$(python3 -c "
import json
try:
    data = json.load(open('${report_file}'))
    if 'runs' in data and len(data['runs']) > 0:
        run = data['runs'][0]
        if 'tool' in run and 'driver' in run['tool'] and 'properties' in run['tool']['driver']:
            mitre = run['tool']['driver']['properties'].get('mitre_attack', {})
            print(len(mitre) if mitre else 0)
            exit(0)
    print(len(data.get('mitre_attack', {})))
except:
    print(0)
" 2>/dev/null || echo "0")
        confidence=$(python3 -c "
import json
try:
    data = json.load(open('${report_file}'))
    if 'runs' in data and len(data['runs']) > 0:
        run = data['runs'][0]
        if 'tool' in run and 'driver' in run['tool'] and 'properties' in run['tool']['driver']:
            print(run['tool']['driver']['properties'].get('confidence', 'N/A'))
            exit(0)
        if 'invocations' in run and len(run['invocations']) > 0 and 'properties' in run['invocations'][0]:
            print(run['invocations'][0]['properties'].get('confidence', 'N/A'))
            exit(0)
    print(data.get('confidence', 'N/A'))
except:
    print('N/A')
" 2>/dev/null || echo "N/A")
    else
        verdict="ERROR"
        risk_score="-1"
        mitre_count="0"
        confidence="N/A"
        echo "{\"command\":\"${command}\",\"verdict\":\"ERROR\",\"risk_score\":-1,\"error\":\"checker failed with exit ${checker_exit} after ${MAX_RETRY} attempts\"}" > "$report_file"
    fi

    # 判断检测结果是否符合预期
    if [ "$label" = "safe" ] && { [ "$verdict" = "LIKELY_SAFE" ] || [ "$verdict" = "LOW_RISK" ]; }; then
        match="CORRECT"
        ok "[${id}] 预期=safe, 实际=${verdict} (score:${risk_score}) -> 正确"
        PASS=$((PASS + 1))
    elif [ "$label" = "malicious" ] && { [ "$verdict" = "DANGEROUS" ] || [ "$verdict" = "SUSPICIOUS" ]; }; then
        match="CORRECT"
        ok "[${id}] 预期=malicious, 实际=${verdict} (score:${risk_score}) -> 正确"
        PASS=$((PASS + 1))
    elif [ "$verdict" = "ERROR" ]; then
        match="ERROR"
        fail "[${id}] 执行出错"
        ERROR=$((ERROR + 1))
    else
        match="WRONG"
        warn "[${id}] 预期=${label}, 实际=${verdict} (score:${risk_score}) -> 误判!"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    echo "{\"id\":\"${id}\",\"category\":\"${category}\",\"label\":\"${label}\",\"desc\":\"${desc}\",\"verdict\":\"${verdict}\",\"risk_score\":${risk_score},\"mitre_count\":${mitre_count},\"confidence\":\"${confidence}\",\"match\":\"${match}\"}" >> "$SUMMARY_FILE"
done

# ─── 汇总报告 ────────────────────────────────────────────
echo ""
echo -e "${BOLD}======================================================================${NC}"
echo -e "${BOLD}  批量检测完成 — Behavioral Analysis Engine v4${NC}"
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
echo "  ID     Category  Label      Verdict       Score  MITRE  Conf    Match"
echo "  ─────  ────────  ─────────  ────────────  ─────  ─────  ──────  ──────"
while IFS= read -r line; do
    sid=$(echo "$line" | python3 -c "
import sys,json
d=json.loads(sys.stdin.read())
print(f\"  {d['id']:<6s} {d['category']:<9s} {d['label']:<10s} {d['verdict']:<13s} {d.get('risk_score','?'):>5s}  {d.get('mitre_count','?'):>5s}  {d.get('confidence','N/A'):<6s}  {d['match']}\")
" 2>/dev/null || echo "  [parse error]")
    echo "$sid"
done < "$SUMMARY_FILE"
echo ""

# ─── 分析白/黑样本性能 ────────────────────────────────────
if [ "$FILTER" = "all" ] && [ "$TOTAL" -gt 0 ]; then
    echo -e "${BOLD}  性能分析:${NC}"
    python3 -c "
import json, sys
rows = [json.loads(l) for l in open('${SUMMARY_FILE}') if l.strip()]
safe = [r for r in rows if r['label'] == 'safe']
mal  = [r for r in rows if r['label'] == 'malicious']

safe_correct = sum(1 for r in safe if r['match'] == 'CORRECT')
mal_correct  = sum(1 for r in mal if r['match'] == 'CORRECT')

# 计算误报率和漏报率
fp = sum(1 for r in safe if r['match'] == 'WRONG')    # False Positive: safe 被判恶意
fn = sum(1 for r in mal if r['match'] == 'WRONG')     # False Negative: malicious 被判安全

print(f'    白样本准确率 : {safe_correct}/{len(safe)} ({safe_correct/len(safe)*100:.0f}%)' if safe else '    白样本: N/A')
print(f'    黑样本准确率 : {mal_correct}/{len(mal)} ({mal_correct/len(mal)*100:.0f}%)' if mal else '    黑样本: N/A')
print(f'    误报率 (FPR) : {fp}/{len(safe)} ({fp/len(safe)*100:.0f}%)' if safe else '')
print(f'    漏报率 (FNR) : {fn}/{len(mal)} ({fn/len(mal)*100:.0f}%)' if mal else '')
print()

# 平均风险评分
safe_scores = [r['risk_score'] for r in safe if r.get('risk_score', -1) >= 0]
mal_scores  = [r['risk_score'] for r in mal if r.get('risk_score', -1) >= 0]
if safe_scores:
    print(f'    白样本平均风险分 : {sum(safe_scores)/len(safe_scores):.1f}/100')
if mal_scores:
    print(f'    黑样本平均风险分 : {sum(mal_scores)/len(mal_scores):.1f}/100')
" 2>/dev/null || true
    echo ""

    # 快速预判 vs 深度分析对比
    TRIAGE_SCRIPT="${SCRIPT_DIR}/triage.sh"
    if [ -x "$TRIAGE_SCRIPT" ]; then
        echo -e "${BOLD}  快速预判精度对比:${NC}"
        TRIAGE_PASS=0; TRIAGE_FAIL=0; TRIAGE_TOTAL=0
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            t_cmd=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['command'])" 2>/dev/null) || continue
            t_label=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['label'])" 2>/dev/null) || continue
            t_id=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['id'])" 2>/dev/null) || continue

            COMMAND="$t_cmd" "$TRIAGE_SCRIPT" > /tmp/.triage_result 2>/dev/null
            t_exit=$?
            t_level=$(python3 -c "import json; print(json.load(open('/tmp/.triage_result'))['level'])" 2>/dev/null || echo "ERROR")

            TRIAGE_TOTAL=$((TRIAGE_TOTAL + 1))
            if [ "$t_label" = "safe" ] && [ "$t_level" = "PASS" ]; then
                TRIAGE_PASS=$((TRIAGE_PASS + 1))
            elif [ "$t_label" = "malicious" ] && { [ "$t_level" = "BLOCK" ] || [ "$t_level" = "REVIEW" ]; }; then
                TRIAGE_PASS=$((TRIAGE_PASS + 1))
            else
                TRIAGE_FAIL=$((TRIAGE_FAIL + 1))
                warn "    预判误差: ${t_id} (label=${t_label}, triage=${t_level})"
            fi
        done < <(cat "${SAMPLES_DIR}/white.jsonl" "${SAMPLES_DIR}/black.jsonl" 2>/dev/null)

        if [ "$TRIAGE_TOTAL" -gt 0 ]; then
            echo -e "    预判准确率 : ${GREEN}${TRIAGE_PASS}/${TRIAGE_TOTAL} ($(python3 -c "print(f'{${TRIAGE_PASS}/${TRIAGE_TOTAL}*100:.1f}%')" 2>/dev/null || echo 'N/A'))${NC}"
            echo "    预判误差   : ${TRIAGE_FAIL}"
        fi
        rm -f /tmp/.triage_result
        echo ""
    fi
fi

# ─── Git 提交 ────────────────────────────────────────────
if [ "$AUTO_COMMIT" = true ] && [ -d "${SCRIPT_DIR}/.git" ]; then
    info "提交结果到 Git..."
    cd "$SCRIPT_DIR"
    git add reports/ samples/
    git add checker.sh run_all.sh
    git add README.md 2>/dev/null || true

    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    COMMIT_MSG="batch-v4: ${TOTAL} samples (${PASS} correct, ${FAIL_COUNT} wrong, ${ERROR} error) @ ${TIMESTAMP}"

    if git diff --cached --quiet; then
        info "无新变更, 跳过提交"
    else
        git commit -m "$COMMIT_MSG"
        ok "已提交: ${COMMIT_MSG}"

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
