#!/usr/bin/env bash
# ============================================================================
#  快速预判引擎 — 零依赖, 毫秒级命令安全评估
#
#  不需要 Docker / Python / OpenSandbox, 纯 bash 实现
#  用于 API 网关、CI/CD pipeline、命令审批系统的前置过滤
#
#  用法:
#    COMMAND="some command" ./triage.sh
#    echo '{"command":"..."}' | ./triage.sh --json-input
#
#  输出: JSON
#    {"level":"BLOCK|REVIEW|PASS", "score":0-100, "matches":[...]}
#
#  退出码:
#    0 = PASS, 1 = REVIEW, 2 = BLOCK
# ============================================================================
set -euo pipefail

COMMAND="${COMMAND:-}"

# JSON 输入模式
if [ "${1:-}" = "--json-input" ]; then
    COMMAND=$(cat | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('command',''))" 2>/dev/null || cat)
fi

if [ -z "$COMMAND" ]; then
    echo '{"error":"COMMAND environment variable or --json-input required"}' >&2
    exit 3
fi

# ─── 恶意模式匹配 (bash 实现, 无需 Python) ───────────────────

score=0
matches=""
match_count=0

check_pattern() {
    local pattern="$1" desc="$2" mitre="$3" pts="$4"
    if echo "$COMMAND" | grep -qiE "$pattern"; then
        score=$((score + pts))
        match_count=$((match_count + 1))
        if [ -n "$matches" ]; then
            matches="${matches},"
        fi
        matches="${matches}{\"pattern\":\"${desc}\",\"mitre\":\"${mitre}\",\"score\":${pts}}"
    fi
}

# 反弹 Shell
check_pattern '/dev/tcp/' "reverse shell /dev/tcp" "T1059.004" 40
check_pattern 'bash\s+-i\s+>&' "bash interactive reverse shell" "T1059.004" 45
check_pattern 'nc\s+-[elp].*sh' "netcat shell" "T1059.004" 45
check_pattern 'socat.*exec:' "socat exec shell" "T1059.004" 40
check_pattern 'mkfifo.*/tmp/.*sh' "named pipe shell" "T1059.004" 40
check_pattern 'python.*socket.*connect.*subprocess' "python reverse shell" "T1059.004" 40

# base64/编码载荷
check_pattern 'base64\s+-d.*sh' "base64 decode to shell" "T1059.004" 40
check_pattern 'echo\s+[A-Za-z0-9+/=]{40,}.*base64\s+-d' "base64 encoded payload" "T1059.004" 35

# 下载执行
check_pattern 'curl.*\|\s*(ba)?sh' "download and execute (curl|sh)" "T1105" 25
check_pattern 'wget.*\|\s*(ba)?sh' "download and execute (wget|sh)" "T1105" 25
check_pattern 'curl.*-o\s+/tmp/.*chmod\s+\+x' "download + chmod +x" "T1105" 35

# 凭据外泄
check_pattern '/etc/shadow.*base64' "shadow exfiltration" "T1048" 40
check_pattern 'cat\s+/etc/shadow' "reading shadow file" "T1048" 25
check_pattern 'curl.*--data-binary\s+@/etc/' "file exfiltration via curl" "T1048" 40

# 持久化
check_pattern 'crontab\s+-' "crontab modification" "T1053.003" 30
check_pattern '/etc/cron\.d/' "cron.d persistence" "T1053.003" 30
check_pattern '/etc/systemd/system/.*\.service' "systemd service injection" "T1543.002" 30
check_pattern '/etc/init\.d/' "init.d persistence" "T1037.004" 30
check_pattern '/etc/rc\.local' "rc.local persistence" "T1037.004" 30

# 权限提升
check_pattern 'chmod\s+u\+s' "setting SUID bit" "T1548.001" 35
check_pattern 'useradd|adduser' "user creation" "T1136.001" 30
check_pattern '/etc/sudoers' "sudoers modification" "T1548.003" 35

# Shell 环境
check_pattern '>>\s*~/\.bashrc' "bashrc modification" "T1546.004" 30
check_pattern '>>\s*/etc/profile' "profile modification" "T1546.004" 30
check_pattern 'authorized_keys' "SSH key injection" "T1098" 30

# 反取证
check_pattern 'HISTFILE=/dev/null' "disabling history" "T1070.003" 20
check_pattern 'ln\s+-sf?\s+/dev/null.*history' "nulling history" "T1070.003" 25

# LD_PRELOAD
check_pattern 'ld\.so\.preload' "LD_PRELOAD hijack" "T1574.006" 40
check_pattern 'LD_PRELOAD=' "LD_PRELOAD injection" "T1574.006" 35

# DNS
check_pattern '>\s*/etc/resolv\.conf' "DNS hijack" "T1016" 30

# PAM
check_pattern '/etc/pam\.d/' "PAM modification" "T1556" 30

# 防火墙
check_pattern 'iptables\s+-F' "flushing iptables" "T1562.004" 30
check_pattern 'ufw\s+disable' "disabling UFW" "T1562.004" 30

# 挖矿
check_pattern '(xmrig|stratum\+tcp|cryptonight)' "cryptomining" "T1496" 35

# sed 写系统文件
check_pattern 'sed\s+-i.*(/etc/passwd|/etc/shadow|/etc/sudoers)' "sed modifying auth files" "T1098" 35

# 信号 trap 逃避
check_pattern "trap\s+''.*INT" "trap ignoring signals (anti-kill)" "T1059.004" 25
check_pattern "trap\s+''.*TERM" "trap ignoring TERM signal" "T1059.004" 25

# SSH 隧道
check_pattern 'ssh\s+-[RLD]\s+' "SSH tunnel/port forward" "T1071.001" 20
check_pattern 'ssh\s+-N\s+-f' "SSH background tunnel" "T1071.001" 25

# hex/编码逃避
check_pattern 'printf.*\\x[0-9a-f]' "printf hex evasion" "T1027.010" 25
check_pattern "\$'\\\\x[0-9a-f]" "dollar-quote hex evasion" "T1027.010" 25
# pipe to bash/sh (generic)
check_pattern "printf.*\|\s*(ba)?sh" "printf pipe to shell" "T1059.004" 30

# ─── 白名单检查 ────────────────────────────────────────────

is_legit=false
legit_reason=""
for pattern in \
    'apt-get\s+(install|update)' \
    'pip\s+install\s+' \
    'npm\s+install' \
    'yarn\s+(add|install)' \
    'cargo\s+install' \
    'docker\s+(build|run|pull)' \
    'git\s+(clone|pull|push)' \
    'make\s+(all|install|clean|test)' \
    'go\s+(build|install|get)' \
    'curl\s+.*https://.*install\.sh' \
    ; do
    if echo "$COMMAND" | grep -qiE "$pattern"; then
        is_legit=true
        legit_reason="$pattern"
        break
    fi
done

# ─── 黑名单检查 ────────────────────────────────────────────

blacklisted=false
for pattern in \
    '>\s*/etc/' '>>\s*/etc/' \
    '>\s*~/\.bashrc' '>>\s*~/\.bashrc' \
    'useradd|adduser' '/etc/sudoers' \
    'chmod\s+u\+s' '/etc/shadow' \
    'authorized_keys' '/etc/pam\.d/' \
    '/dev/tcp/' 'nc\s+-[elp]' \
    'socat.*exec:' '/etc/ld\.so\.preload' \
    'sed\s+-i.*/etc/(passwd|shadow)' \
    "trap\s+''.*INT" "trap\s+''.*TERM" \
    ; do
    if echo "$COMMAND" | grep -qiE "$pattern"; then
        blacklisted=true
        break
    fi
done

# 合法命令降分 (除非黑名单)
if [ "$is_legit" = true ] && [ "$blacklisted" = false ]; then
    score=$((score / 2))
fi

# 封顶 100
[ "$score" -gt 100 ] && score=100

# ─── 判定 ────────────────────────────────────────────────

if [ "$score" -ge 50 ] || { [ "$blacklisted" = true ] && [ "$score" -ge 25 ]; }; then
    level="BLOCK"
    exit_code=2
elif [ "$score" -ge 10 ] || [ "$match_count" -gt 0 ] || [ "$blacklisted" = true ]; then
    level="REVIEW"
    exit_code=1
else
    level="PASS"
    exit_code=0
fi

# ─── JSON 输出 ────────────────────────────────────────────

cat <<EOJSON
{
  "level": "${level}",
  "score": ${score},
  "is_legitimate": ${is_legit},
  "blacklisted": ${blacklisted},
  "patterns_matched": ${match_count},
  "matches": [${matches}],
  "command": $(printf '%s' "$COMMAND" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))" 2>/dev/null || echo "\"${COMMAND:0:200}\"")
}
EOJSON

exit $exit_code
