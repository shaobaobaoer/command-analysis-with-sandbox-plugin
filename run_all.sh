#!/usr/bin/env bash
# ============================================================================
#  批量安全检测 + 自动 Git 提交
#
#  用法:
#    ./run_all.sh                    # 跑全部样本
#    ./run_all.sh white              # 只跑白样本
#    ./run_all.sh black              # 只跑黑样本
#    ./run_all.sh white:w01          # 只跑指定 ID
#    ./run_all.sh --no-commit        # 不自动 Git 提交
#    ./run_all.sh --retry 2          # 失败重试次数
#
#  环境变量:
#    SANDBOX_PORT    — 服务端口 (默认 8080)
#    REGISTRY_MIRROR — 镜像仓库前缀（国内加速）
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAMPLES_DIR="${SCRIPT_DIR}/samples"
REPORTS_DIR="${SCRIPT_DIR}/reports"
CHECKER="${SCRIPT_DIR}/checker.sh"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }

# ── 参数解析 ──────────────────────────────────────────────────────────────
FILTER="all"
AUTO_COMMIT=true
MAX_RETRY=1
args=("$@")
for i in "${!args[@]}"; do
    case "${args[$i]}" in
        --no-commit) AUTO_COMMIT=false ;;
        --retry)     MAX_RETRY="${args[$((i+1))]}" ;;
        --*)         ;;
        *)
            if [ "$i" -gt 0 ] && [ "${args[$((i-1))]}" = "--retry" ]; then
                continue
            fi
            FILTER="${args[$i]}"
            ;;
    esac
done

echo ""
echo -e "${BOLD}============================================"
echo "  Command Safety Batch Analyzer v5"
echo "  判定依据: 沙箱执行前/后行为对比"
echo -e "============================================${NC}"
echo ""

# ── 前置检查 ──────────────────────────────────────────────────────────────
command -v docker  &>/dev/null || { fail "Docker 未安装";  exit 1; }
sudo docker info   &>/dev/null 2>&1 || { fail "Docker 未运行或无权限"; exit 1; }
command -v python3 &>/dev/null || { fail "Python3 未安装"; exit 1; }
[ -f "$CHECKER" ]  || { fail "checker.sh 不存在: $CHECKER"; exit 1; }
chmod +x "$CHECKER"
mkdir -p "$REPORTS_DIR"

# ── 预拉取 Docker 镜像 ────────────────────────────────────────────────────
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
    if sudo docker image inspect "$img" &>/dev/null; then
        ok "镜像就绪: $img"
    else
        info "拉取: $img"
        sudo docker pull "$img"
    fi
done

# ── 收集样本 ──────────────────────────────────────────────────────────────
declare -a JOBS=()

add_samples() {
    local file="$1" category="$2"
    [ -f "$file" ] || return 0
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        # 将整行 JSON + category 一起 base64 编码存入，避免多行命令/特殊字符破坏数组
        local encoded
        encoded=$(printf '%s\x1e%s' "$category" "$line" | base64 -w0)
        JOBS+=("$encoded")
    done < "$file"
}

case "$FILTER" in
    all)
        add_samples "${SAMPLES_DIR}/white.jsonl" "white"
        add_samples "${SAMPLES_DIR}/black.jsonl" "black"
        ;;
    white) add_samples "${SAMPLES_DIR}/white.jsonl" "white" ;;
    black) add_samples "${SAMPLES_DIR}/black.jsonl" "black" ;;
    white:*|black:*)
        category="${FILTER%%:*}"
        target_id="${FILTER##*:}"
        add_samples "${SAMPLES_DIR}/${category}.jsonl" "$category"
        FILTERED=()
        for job in "${JOBS[@]}"; do
            job_id=$(echo "$job" | base64 -d | python3 -c "
import sys; raw=sys.stdin.read(); sep=raw.index('\x1e'); line=raw[sep+1:]
import json; print(json.loads(line)['id'])
" 2>/dev/null)
            [ "$job_id" = "$target_id" ] && FILTERED+=("$job")
        done
        JOBS=("${FILTERED[@]:-}")
        ;;
    *) fail "未知参数: $FILTER (用法: all, white, black, white:w01)"; exit 1 ;;
esac

TOTAL=${#JOBS[@]}
info "共 ${TOTAL} 个样本待检测"
echo ""

# ── 逐个执行 ──────────────────────────────────────────────────────────────
PASS=0; FAIL_COUNT=0; ERROR=0
SUMMARY_FILE="${REPORTS_DIR}/summary.jsonl"
> "$SUMMARY_FILE"

for i in "${!JOBS[@]}"; do
    # 解码 base64 → "category\x1eJSON行"
    decoded=$(echo "${JOBS[$i]}" | base64 -d)
    sep_pos=$(python3 -c "s=open('/dev/stdin','rb').read(); print(s.index(b'\\x1e'))" <<< "$decoded" 2>/dev/null || echo "")
    category=$(python3 -c "
import sys
raw = sys.stdin.buffer.read()
sep = raw.index(b'\\x1e')
print(raw[:sep].decode())
" <<< "$decoded")
    line=$(python3 -c "
import sys
raw = sys.stdin.buffer.read()
sep = raw.index(b'\\x1e')
print(raw[sep+1:].decode())
" <<< "$decoded")
    id=$(echo "$line"      | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['id'])")
    label=$(echo "$line"   | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['label'])")
    desc=$(echo "$line"    | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['desc'])")
    command=$(echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); import base64; print(base64.b64encode(d['command'].encode()).decode())")
    # command 此时是 base64 编码，直接作为 COMMAND_B64 传入
    COMMAND_B64="$command"
    idx=$((i + 1))
    report_dir="${REPORTS_DIR}/${category}"
    mkdir -p "$report_dir"
    report_file="${report_dir}/${id}.json"
    log_file="${report_dir}/${id}.log"

    # 解码命令用于显示
    cmd_display=$(echo "$COMMAND_B64" | base64 -d 2>/dev/null | head -c 120 || echo "(decode error)")

    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    info "[${idx}/${TOTAL}] ${category}/${id}: ${desc}"
    info "命令: ${cmd_display}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # COMMAND_B64 已在上面赋值，直接导出
    REPORT_DIR="$report_dir"
    export COMMAND_B64 REPORT_DIR SANDBOX_IMAGE EXECD_IMAGE REGISTRY_MIRROR

    # 记录启动时间戳（用于后续精确定位本次生成的报告）
    run_start_ts=$(date +%s)
    # 创建一个时间戳哨兵文件，用于 find -newer 定位新报告
    sentinel_file="${report_dir}/.run_sentinel_${id}"
    touch "$sentinel_file"

    checker_exit=1
    for attempt in $(seq 1 "$MAX_RETRY"); do
        [ "$attempt" -gt 1 ] && warn "[${id}] 重试 (${attempt}/${MAX_RETRY})..."
        if sudo -E bash "$CHECKER" > "$log_file" 2>&1; then
            checker_exit=0; break
        else
            checker_exit=$?
            [ "$attempt" -lt "$MAX_RETRY" ] && sleep 2
        fi
    done

    # 找本次运行生成的报告（比哨兵文件新，且不是 sarif 格式）
    latest=$(find "${report_dir}" -maxdepth 1 -newer "$sentinel_file" \
        -name 'safety_report_*.json' ! -name '*.sarif.json' \
        -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2- || true)
    rm -f "$sentinel_file"
    # 如果 find 不支持 -printf，降级为时间过滤
    if [ -z "$latest" ]; then
        latest=$(find "${report_dir}" -maxdepth 1 -newer /proc/1 \
            -name 'safety_report_*.json' ! -name '*.sarif.json' 2>/dev/null | \
            xargs ls -t 2>/dev/null | head -1 || true)
    fi
    if [ -n "$latest" ] && [ -f "$latest" ]; then
        mv "$latest" "$report_file"
        verdict=$(python3 -c "
import json
try:
    d = json.load(open('${report_file}'))
    print(d.get('verdict', 'UNKNOWN'))
except: print('UNKNOWN')
" 2>/dev/null || echo "UNKNOWN")
        risk_score=$(python3 -c "
import json
try:
    d = json.load(open('${report_file}'))
    print(d.get('risk_score', -1))
except: print(-1)
" 2>/dev/null || echo "-1")
        confidence=$(python3 -c "
import json
try:
    d = json.load(open('${report_file}'))
    print(d.get('confidence', 'N/A'))
except: print('N/A')
" 2>/dev/null || echo "N/A")
        mitre_count=$(python3 -c "
import json
try:
    d = json.load(open('${report_file}'))
    print(len(d.get('mitre_attack', {})))
except: print(0)
" 2>/dev/null || echo "0")
    else
        verdict="ERROR"; risk_score="-1"; confidence="N/A"; mitre_count="0"
        echo "{\"id\":\"${id}\",\"verdict\":\"ERROR\",\"risk_score\":-1,\"error\":\"checker failed exit=${checker_exit}\"}" > "$report_file"
    fi

    # 判定是否符合预期
    if [ "$label" = "safe" ] && { [ "$verdict" = "LIKELY_SAFE" ] || [ "$verdict" = "LOW_RISK" ]; }; then
        match="CORRECT"; ok "[${id}] 预期=safe, 实际=${verdict} (score:${risk_score}) -> 正确"
        PASS=$((PASS + 1))
    elif [ "$label" = "malicious" ] && { [ "$verdict" = "DANGEROUS" ] || [ "$verdict" = "SUSPICIOUS" ]; }; then
        match="CORRECT"; ok "[${id}] 预期=malicious, 实际=${verdict} (score:${risk_score}) -> 正确"
        PASS=$((PASS + 1))
    elif [ "$verdict" = "ERROR" ]; then
        match="ERROR"; fail "[${id}] 执行出错 (见 ${log_file})"
        ERROR=$((ERROR + 1))
    else
        match="WRONG"; warn "[${id}] 预期=${label}, 实际=${verdict} (score:${risk_score}) -> 误判!"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    echo "{\"id\":\"${id}\",\"category\":\"${category}\",\"label\":\"${label}\",\"desc\":\"${desc}\",\"verdict\":\"${verdict}\",\"risk_score\":${risk_score},\"mitre_count\":${mitre_count},\"confidence\":\"${confidence}\",\"match\":\"${match}\"}" >> "$SUMMARY_FILE"
done

# ── 汇总报告 ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}=====================================================================${NC}"
echo -e "${BOLD}  批量检测完成 — Behavioral Analysis Engine v5${NC}"
echo -e "${BOLD}=====================================================================${NC}"
echo ""
echo "  总样本   : ${TOTAL}"
echo -e "  正确判定 : ${GREEN}${PASS}${NC}"
echo -e "  误判     : ${YELLOW}${FAIL_COUNT}${NC}"
echo -e "  错误     : ${RED}${ERROR}${NC}"
if [ "$TOTAL" -gt 0 ]; then
    echo "  准确率   : $(python3 -c "print(f'{${PASS}/${TOTAL}*100:.1f}%')" 2>/dev/null || echo 'N/A')"
fi
echo ""
echo "  详细结果 : ${SUMMARY_FILE}"
echo ""

# 结果表格
echo "  ID     Category  Label      Verdict       Score  MITRE  Conf    Match"
echo "  ─────  ────────  ─────────  ────────────  ─────  ─────  ──────  ──────"
while IFS= read -r line; do
    python3 -c "
import sys,json
d=json.loads(sys.stdin.read())
print(f\"  {d['id']:<6s} {d['category']:<9s} {d['label']:<10s} {d['verdict']:<13s} {str(d.get('risk_score','?')):>5s}  {str(d.get('mitre_count','?')):>5s}  {d.get('confidence','N/A'):<6s}  {d['match']}\")
" <<< "$line" 2>/dev/null || echo "  [parse error]"
done < "$SUMMARY_FILE"
echo ""

# 白/黑样本性能分析
if [ "$FILTER" = "all" ] && [ "$TOTAL" -gt 0 ]; then
    echo -e "${BOLD}  性能分析:${NC}"
    python3 -c "
import json
rows = [json.loads(l) for l in open('${SUMMARY_FILE}') if l.strip()]
safe = [r for r in rows if r['label'] == 'safe']
mal  = [r for r in rows if r['label'] == 'malicious']
safe_ok = sum(1 for r in safe if r['match'] == 'CORRECT')
mal_ok  = sum(1 for r in mal  if r['match'] == 'CORRECT')
fp = sum(1 for r in safe if r['match'] == 'WRONG')
fn = sum(1 for r in mal  if r['match'] == 'WRONG')
print(f'    白样本准确率 : {safe_ok}/{len(safe)} ({safe_ok/len(safe)*100:.0f}%)' if safe else '')
print(f'    黑样本准确率 : {mal_ok}/{len(mal)} ({mal_ok/len(mal)*100:.0f}%)'  if mal  else '')
print(f'    误报率 (FPR) : {fp}/{len(safe)} ({fp/len(safe)*100:.0f}%)' if safe else '')
print(f'    漏报率 (FNR) : {fn}/{len(mal)} ({fn/len(mal)*100:.0f}%)'  if mal  else '')
safe_scores = [r['risk_score'] for r in safe if r.get('risk_score',-1) >= 0]
mal_scores  = [r['risk_score'] for r in mal  if r.get('risk_score',-1) >= 0]
if safe_scores: print(f'    白样本平均风险分 : {sum(safe_scores)/len(safe_scores):.1f}/100')
if mal_scores:  print(f'    黑样本平均风险分 : {sum(mal_scores)/len(mal_scores):.1f}/100')
# 误判列表
wrong = [r for r in rows if r['match'] == 'WRONG']
if wrong:
    print()
    print('    误判样本:')
    for r in wrong:
        print(f\"      [{r['id']}] label={r['label']}, verdict={r['verdict']}, score={r['risk_score']}: {r['desc']}\")
" 2>/dev/null || true
    echo ""
fi

# ── Git 提交 ──────────────────────────────────────────────────────────────
if [ "$AUTO_COMMIT" = true ] && [ -d "${SCRIPT_DIR}/.git" ]; then
    info "提交结果到 Git..."
    cd "$SCRIPT_DIR"
    git add reports/ samples/ analyzer/ checker.sh checker.py run_all.sh scoring.conf
    git add CLAUDE.md 2>/dev/null || true

    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    COMMIT_MSG="batch-v5: ${TOTAL} samples (${PASS} correct, ${FAIL_COUNT} wrong, ${ERROR} error) @ ${TIMESTAMP}"

    if git diff --cached --quiet; then
        info "无新变更，跳过提交"
    else
        git commit -m "$COMMIT_MSG"
        ok "已提交: ${COMMIT_MSG}"
        if git remote get-url origin &>/dev/null; then
            info "推送到 origin..."
            if git push -u origin main 2>/dev/null || git push -u origin master 2>/dev/null; then
                ok "推送完成"
            else
                warn "推送失败，请手动 git push"
            fi
        fi
    fi
fi

echo ""
ok "全部完成!"
