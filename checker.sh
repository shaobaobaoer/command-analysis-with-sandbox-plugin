#!/usr/bin/env bash
# ============================================================================
#  OpenSandbox Behavioral Analysis Engine — v3 (Deep Inspection)
#
#  世界级行为监测沙箱: 多层探针 + MITRE ATT&CK 映射 + 加权评分
#
#  用法:
#    COMMAND="some command" ./checker.sh
#
#  环境变量:
#    COMMAND        — 待检测命令
#    SANDBOX_PORT   — 服务端口 (默认: 8080)
#    SANDBOX_IMAGE  — 沙箱镜像
#    EXECD_IMAGE    — execd 镜像
#    REGISTRY_MIRROR — 镜像仓库前缀
#    REPORT_DIR     — 报告输出目录
#
#  v4 升级:
#    - 24 维度深度行为分析 (新增: 计划任务差异/隐藏进程/信号处理/容器逃逸)
#    - conntrack + iptables LOG 捕获短命网络连接
#    - MITRE ATT&CK 技术映射 (40+ 技术)
#    - 加权风险评分体系 (0-100) + 置信度评估
#    - 智能白名单降噪 (apt/pip/npm 等合法安装器)
#    - /tmp 监控 (用独立探针, 避免递归)
#    - 文件内容模式匹配 (70+ 规则: base64/反弹shell/混淆/后门/LotL)
#    - 进程族谱追踪 (命令产生的子进程树)
#    - Living-off-the-Land Binary (LOLBin) 检测
#    - 多阶段攻击链关联分析
# ============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

REGISTRY_MIRROR="${REGISTRY_MIRROR:-}"
if [ -n "$REGISTRY_MIRROR" ]; then
    DEFAULT_SANDBOX_IMAGE="${REGISTRY_MIRROR}/code-interpreter:v1.0.2"
    DEFAULT_EXECD_IMAGE="${REGISTRY_MIRROR}/execd:v1.0.7"
else
    DEFAULT_SANDBOX_IMAGE="opensandbox/code-interpreter:v1.0.2"
    DEFAULT_EXECD_IMAGE="opensandbox/execd:v1.0.7"
fi

COMMAND="${COMMAND:-curl -fsSL https://claude.ai/install.sh | bash}"
SANDBOX_PORT="${SANDBOX_PORT:-8080}"
SANDBOX_IMAGE="${SANDBOX_IMAGE:-$DEFAULT_SANDBOX_IMAGE}"
EXECD_IMAGE="${EXECD_IMAGE:-$DEFAULT_EXECD_IMAGE}"

WORK_DIR="$(mktemp -d)"
VENV_DIR="${WORK_DIR}/.venv"
CONFIG_FILE="${WORK_DIR}/sandbox.toml"
SERVER_PID=""
REPORT_DIR="${REPORT_DIR:-$(pwd)}"

cleanup() {
    info "Cleaning up..."
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null || true
    rm -rf "$WORK_DIR"
    ok "Cleanup done."
}
trap cleanup EXIT

echo ""
echo -e "${BOLD}=========================================="
echo "  OpenSandbox Behavioral Analysis Engine v4"
echo -e "==========================================${NC}"
echo ""
info "待检测命令: ${COMMAND}"
echo ""

# ── Step 1: 环境检查 ──
info "[Step 1/7] 检查环境..."
if ! command -v docker &>/dev/null; then fail "Docker 未安装"; fi
if ! docker info &>/dev/null 2>&1; then fail "Docker daemon 未运行"; fi
ok "Docker: $(docker --version | head -1)"
command -v python3 &>/dev/null || fail "Python3 未安装"
ok "Python: $(python3 --version)"
if ! command -v uv &>/dev/null; then
    info "安装 uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
    command -v uv &>/dev/null || fail "uv 安装失败"
fi
ok "uv: $(uv --version)"

# ── Step 2: 预拉取镜像 ──
info "[Step 2/7] 预拉取 Docker 镜像..."
pull_image() {
    local image="$1" label="$2"
    if docker image inspect "$image" &>/dev/null; then
        ok "${label}: ${image} (已存在)"
    else
        info "${label}: 拉取 ${image} ..."
        docker pull "$image" || fail "${label}: 拉取失败. 国内试: REGISTRY_MIRROR='sandbox-registry.cn-zhangjiakou.cr.aliyuncs.com/opensandbox' ./run.sh"
        ok "${label}: 完成"
    fi
}
pull_image "$SANDBOX_IMAGE" "沙箱镜像"
pull_image "$EXECD_IMAGE"   "Execd镜像"

# ── Step 3: 安装依赖 ──
info "[Step 3/7] 安装 Python 依赖..."
cd "$WORK_DIR"
uv venv "$VENV_DIR" --python python3 -q
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
uv pip install -q opensandbox-server opensandbox 2>&1 | tail -3
ok "opensandbox-server + SDK 已安装"

# ── Step 4: 服务端配置 ──
info "[Step 4/7] 生成服务端配置..."
cat > "$CONFIG_FILE" << TOML
[server]
host = "127.0.0.1"
port = ${SANDBOX_PORT}
log_level = "INFO"
max_sandbox_timeout_seconds = 600

[runtime]
type = "docker"
execd_image = "${EXECD_IMAGE}"

[storage]
allowed_host_paths = []

[docker]
network_mode = "bridge"
drop_capabilities = ["AUDIT_WRITE", "MKNOD", "NET_ADMIN", "NET_RAW", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_TIME", "SYS_TTY_CONFIG"]
no_new_privileges = true
pids_limit = 512

[ingress]
mode = "direct"
TOML
ok "配置写入: ${CONFIG_FILE}"

# ── Step 5: 启动服务端 ──
info "[Step 5/7] 启动 OpenSandbox Server..."
export SANDBOX_CONFIG_PATH="$CONFIG_FILE"
opensandbox-server > "${WORK_DIR}/server.log" 2>&1 &
SERVER_PID=$!
for i in $(seq 1 30); do
    if curl -sf "http://127.0.0.1:${SANDBOX_PORT}/v1/sandboxes" >/dev/null 2>&1; then
        ok "Server 就绪 (PID: ${SERVER_PID}, port: ${SANDBOX_PORT})"
        break
    fi
    [ "$i" -eq 30 ] && { cat "${WORK_DIR}/server.log"; fail "Server 启动超时"; }
    sleep 1
done

# ── Step 6: 深度安全检测 ──
info "[Step 6/7] 创建沙箱并执行深度行为分析..."
echo ""

cat > "${WORK_DIR}/checker.py" << 'PYTHON_SCRIPT'
"""
OpenSandbox Behavioral Analysis Engine v4 — Deep Inspection

24维度深度行为分析 + MITRE ATT&CK 映射 + 加权评分 + 攻击链关联

检测维度:
  1.  文件系统快照对比 (前/后 diff)
  2.  实时文件事件 (inotifywait — 系统目录 + /tmp 独立探针)
  3.  用户/权限变更 (passwd/shadow/sudoers/SSH/PAM)
  4.  持久化机制 (cron/cron.d/systemd/rc.local/init.d/at/timer)
  5.  Shell 环境篡改 (.bashrc/.profile/etc)
  6.  网络连接 (/proc/net/tcp 高频轮询 + ss)
  7.  DNS 配置变更
  8.  可疑二进制 (/tmp /var/tmp /dev/shm 可执行文件 + file 元信息)
  9.  资源消耗异常 (CPU/内存)
  10. 进程树分析 (命令子进程追踪)
  11. 文件内容模式匹配 (70+ 规则: base64/反弹shell/混淆/后门/LotL)
  12. 内核模块变更
  13. SUID/SGID 新增文件检测
  14. 环境变量/LD_PRELOAD 注入检测
  15. 关键系统二进制完整性 (bash/su/sudo/passwd/sshd hash)
  16. 符号链接攻击检测 (新增指向敏感文件的 symlink)
  17. 文件能力 (getcap) 变更检测
  18. 输出内容分析 (密钥/哈希/凭据泄露)
  19. 新增文件熵分析 (高熵 = 加密/压缩载荷)
  20. 计划任务详细差异 (crontab -l 前后逐行对比)
  21. 隐藏进程检测 (/proc 遍历 vs ps 对比)
  22. 信号处理与 trap 分析 (恶意信号劫持)
  23. 攻击链关联分析 (多维度交叉研判)
  24. 敏感文件权限变更追踪 (world-writable/权限过宽)
"""
import asyncio
import hashlib
import json
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from opensandbox import Sandbox
from opensandbox.config import ConnectionConfig

# 支持base64编码的命令传递（解决换行符问题）
import base64 as b64mod
_raw_cmd = os.environ["CHECK_COMMAND"]
if os.environ.get("COMMAND_B64"):
    try:
        COMMAND = b64mod.b64decode(os.environ["COMMAND_B64"]).decode("utf-8")
    except Exception:
        COMMAND = _raw_cmd
else:
    COMMAND = _raw_cmd
PORT = int(os.environ.get("SANDBOX_PORT", "8080"))
IMAGE = os.environ.get("SANDBOX_IMAGE", "opensandbox/code-interpreter:v1.0.2")
REPORT_DIR = os.environ.get("REPORT_DIR", "/tmp")
W = 76

# ── 加载评分配置 ──
SCORING_CONF = {}
_conf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scoring.conf")
if not os.path.exists(_conf_path):
    _conf_path = os.path.join(os.getcwd(), "scoring.conf")
if os.path.exists(_conf_path):
    with open(_conf_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _key, _val = _line.split("=", 1)
                _val = _val.split("#")[0].strip()
                SCORING_CONF[_key.strip()] = _val

DANGEROUS_THRESHOLD = int(SCORING_CONF.get("DANGEROUS_THRESHOLD", "60"))
DANGEROUS_CRITICALS = int(SCORING_CONF.get("DANGEROUS_CRITICALS", "2"))
SUSPICIOUS_THRESHOLD = int(SCORING_CONF.get("SUSPICIOUS_THRESHOLD", "25"))
LOW_RISK_THRESHOLD = int(SCORING_CONF.get("LOW_RISK_THRESHOLD", "10"))
LEGITIMATE_DIVISOR = int(SCORING_CONF.get("LEGITIMATE_DIVISOR", "2"))
ENTROPY_THRESHOLD = float(SCORING_CONF.get("ENTROPY_THRESHOLD", "6.5"))
HIDDEN_PROC_TOLERANCE = int(SCORING_CONF.get("HIDDEN_PROC_TOLERANCE", "8"))

# ═══════════════════════════════════════════════════════════════════════════
#  基础设施过滤 — execd + 监控自身产物
# ═══════════════════════════════════════════════════════════════════════════
EXECD_TMP_RE = re.compile(r"^/tmp/[0-9a-f]{32}\.(stdout|stderr)$")
INFRA_FILES = {
    "/tmp/.inotify_log", "/var/log/.inotify_log", "/tmp/.inotify_tmp_log",
    "/tmp/.net_baseline", "/tmp/.net_poll_log", "/tmp/.resolv_baseline",
    "/tmp/execd.log", "/tmp/.proc_tree_log", "/tmp/.audit_log",
    "/tmp/.conntrack_log", "/tmp/.suid_baseline", "/tmp/.suid_after",
    "/tmp/.mount_baseline", "/tmp/.mount_after",
    "/tmp/.env_baseline", "/tmp/.env_after",
    "/tmp/.modules_baseline", "/tmp/.modules_after",
    "/tmp/.caps_baseline", "/tmp/.caps_after",
}

def is_infra(path):
    return path in INFRA_FILES or bool(EXECD_TMP_RE.match(path))

# ═══════════════════════════════════════════════════════════════════════════
#  MITRE ATT&CK 技术映射表
# ═══════════════════════════════════════════════════════════════════════════
MITRE = {
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1053.003": "Scheduled Task/Job: Cron",
    "T1053.001": "Scheduled Task/Job: At",
    "T1136.001": "Create Account: Local Account",
    "T1098":     "Account Manipulation",
    "T1543.002": "Create/Modify System Process: Systemd Service",
    "T1037.004": "Boot/Logon Init Scripts: RC Scripts",
    "T1037.003": "Boot/Logon Init Scripts: Network Provider DLL",
    "T1546.004": "Event Triggered Execution: .bash_profile/.bashrc",
    "T1574.006": "Hijack Execution Flow: LD_PRELOAD",
    "T1574.001": "Hijack Execution Flow: DLL Search Order",
    "T1048":     "Exfiltration Over Alternative Protocol",
    "T1071.001": "Application Layer Protocol: Web",
    "T1105":     "Ingress Tool Transfer",
    "T1070.003": "Indicator Removal: Clear Command History",
    "T1070.004": "Indicator Removal: File Deletion",
    "T1222.002": "File/Dir Permissions Modification: Linux",
    "T1548.001": "Abuse Elevation Control: Setuid/Setgid",
    "T1556":     "Modify Authentication Process",
    "T1554":     "Compromise Client Software Binary",
    "T1047":     "Process Injection (Unix)",
    "T1611":     "Escape to Host",
    "T1014":     "Rootkit",
    "T1057":     "Process Discovery",
    "T1082":     "System Information Discovery",
    "T1016":     "System Network Configuration Discovery",
    "T1496":     "Resource Hijacking (Cryptomining)",
    "T1027":     "Obfuscated Files or Information",
    "T1027.010": "Obfuscated Files: Command Obfuscation",
    "T1036":     "Masquerading",
    "T1036.005": "Masquerading: Match Legitimate Name",
    "T1547.001": "Boot/Logon Autostart: Registry Run Keys (Linux equiv)",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1021.004": "Remote Services: SSH",
    "T1059.006": "Command and Scripting Interpreter: Python",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1140":     "Deobfuscate/Decode Files or Information",
    "T1003":     "OS Credential Dumping",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1018":     "Remote System Discovery",
    "T1049":     "System Network Connections Discovery",
    "T1033":     "System Owner/User Discovery",
    "T1083":     "File and Directory Discovery",
    "T1087.001": "Account Discovery: Local Account",
    "T1069.001": "Permission Groups Discovery: Local Groups",
    "T1007":     "System Service Discovery",
    "T1497":     "Virtualization/Sandbox Evasion",
    "T1564.001": "Hide Artifacts: Hidden Files and Directories",
    "T1053.005": "Scheduled Task/Job: Systemd Timers",
    "T1562.004": "Impair Defenses: Disable or Modify System Firewall",
    "T1070.006": "Indicator Removal: Timestomp",
    "T1055":     "Process Injection",
    "T1548.003": "Abuse Elevation: Sudo and Sudo Caching",
    "T1195":     "Supply Chain Compromise",
    "T1195.001": "Supply Chain Compromise: Compromise Software Dependencies",
    "T1552.005": "Unsecured Credentials: Cloud Instance Metadata API",
    "T1609":     "Container Administration Command",
    "T1610":     "Deploy Container",
}

# ═══════════════════════════════════════════════════════════════════════════
#  恶意内容模式匹配 (文件内容 + 命令特征)
# ═══════════════════════════════════════════════════════════════════════════
MALICIOUS_CONTENT_PATTERNS = [
    # 反弹 Shell
    (r"/dev/tcp/", "reverse shell via /dev/tcp", "T1059.004", 40),
    (r"bash\s+-i\s+>&", "interactive bash reverse shell", "T1059.004", 45),
    (r"nc\s+-[elp].*\s+/bin/(ba)?sh", "netcat shell bind", "T1059.004", 45),
    (r"python.*socket.*connect.*subprocess", "python reverse shell", "T1059.004", 40),
    (r"perl.*socket.*INET.*exec", "perl reverse shell", "T1059.004", 40),
    (r"ruby.*TCPSocket.*exec", "ruby reverse shell", "T1059.004", 40),
    (r"php.*fsockopen.*exec", "php reverse shell", "T1059.004", 40),
    (r"mkfifo\s+.*/tmp/.*\|\s*.*sh", "named pipe shell", "T1059.004", 40),
    # base64 编码载荷
    (r"echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64\s+-d", "base64 encoded payload execution", "T1059.004", 35),
    (r"base64\s+-d.*\|\s*(ba)?sh", "base64 decode piped to shell", "T1059.004", 40),
    # 下载执行
    (r"curl.*\|\s*(ba)?sh", "download and execute (curl|sh)", "T1105", 25),
    (r"wget.*\|\s*(ba)?sh", "download and execute (wget|sh)", "T1105", 25),
    (r"curl.*-o\s+/tmp/.*&&.*chmod\s+\+x", "download to /tmp and make executable", "T1105", 35),
    # 凭据/数据外泄
    (r"/etc/shadow.*base64", "shadow file exfiltration via base64", "T1048", 40),
    (r"cat\s+/etc/shadow", "reading shadow file", "T1048", 25),
    # 权限提升
    (r"chmod\s+u\+s\s+", "setting SUID bit", "T1548.001", 35),
    (r"chmod\s+[0-7]*4[0-7]{3}\s+", "setting SUID via octal", "T1548.001", 35),
    # 反取证
    (r"HISTFILE=/dev/null", "disabling bash history", "T1070.003", 20),
    (r"HISTSIZE=0", "zeroing history size", "T1070.003", 15),
    (r"ln\s+-sf?\s+/dev/null.*history", "nulling history file", "T1070.003", 25),
    (r"shred\s+.*history", "shredding history", "T1070.003", 30),
    # LD_PRELOAD
    (r"ld\.so\.preload", "LD_PRELOAD hijack", "T1574.006", 40),
    (r"LD_PRELOAD=", "LD_PRELOAD environment injection", "T1574.006", 35),
    (r"LD_LIBRARY_PATH=", "LD_LIBRARY_PATH manipulation", "T1574.001", 20),
    # 挖矿指标
    (r"(xmrig|stratum\+tcp|mining|cryptonight|monero)", "cryptocurrency mining indicators", "T1496", 35),
    # PAM 后门
    (r"/etc/pam\.d/", "PAM configuration modification", "T1556", 30),
    # authorized_keys
    (r"authorized_keys", "SSH authorized_keys manipulation", "T1098", 30),
    # 容器逃逸
    (r"(nsenter|--privileged|/var/run/docker\.sock)", "potential container escape", "T1611", 45),
    # 命令混淆/逃避
    (r"\\x[0-9a-f]{2}", "hex-encoded characters in command", "T1027.010", 25),
    (r"\$\(echo\s+[A-Za-z0-9+/=]+\s*\|\s*base64\s+-d\)", "base64 command substitution", "T1027.010", 30),
    (r"eval\s+\$\(", "eval with command substitution", "T1059.004", 25),
    (r"printf\s+.*\\\\x[0-9a-f]", "printf hex evasion", "T1027.010", 25),
    (r"\$\{.*#.*\}", "bash parameter manipulation evasion", "T1027.010", 20),
    (r"echo\s+.*\|\s*xxd\s+-r", "xxd hex decode execution", "T1027.010", 30),
    (r"python[23]?\s+-c\s+.*exec\(", "python exec() payload", "T1059.004", 25),
    (r"python[23]?\s+-c\s+.*__import__", "python __import__ payload", "T1059.004", 25),
    # 延迟执行
    (r"sleep\s+\d+\s*&&", "delayed command execution", "T1059.004", 15),
    (r"at\s+now\s*\+", "at job scheduling", "T1053.001", 25),
    (r"nohup\s+.*&\s*$", "nohup background persistent process", "T1059.004", 15),
    # 防御规避
    (r"unset\s+HISTFILE", "unsetting HISTFILE", "T1070.003", 20),
    (r"kill\s+-9\s+.*syslog", "killing syslog", "T1562.001", 35),
    (r"systemctl\s+(stop|disable)\s+.*(audit|syslog|rsyslog|firewall)", "disabling security service", "T1562.001", 35),
    (r"iptables\s+-F", "flushing iptables rules", "T1562.001", 30),
    (r"setenforce\s+0", "disabling SELinux", "T1562.001", 30),
    # 其他持久化
    (r"/etc/cron\.d/", "cron.d persistence", "T1053.003", 30),
    (r"/etc/init\.d/", "init.d persistence", "T1037.004", 30),
    # 信息收集 (侦察)
    (r"cat\s+/etc/passwd\s*\|", "piping passwd file (exfil prep)", "T1048", 15),
    (r"find\s+/\s+.*-perm\s+-4000", "SUID file enumeration", "T1548.001", 10),
    # 隐藏文件/目录
    (r"mkdir\s+-p\s+/tmp/\.", "creating hidden directory in /tmp", "T1564.001", 20),
    (r">\s*/tmp/\.", "writing hidden file in /tmp", "T1564.001", 15),
    # Living-off-the-Land (LotL) 利用系统自带工具
    (r"python[23]?\s+-m\s+http\.server", "python HTTP server (potential staging/exfil)", "T1105", 15),
    (r"python[23]?\s+-m\s+SimpleHTTPServer", "python2 HTTP server (potential staging)", "T1105", 15),
    (r"openssl\s+s_client.*connect", "openssl reverse connection", "T1071.001", 25),
    (r"openssl\s+enc\s+-aes", "openssl encryption (data staging)", "T1027", 20),
    (r"socat\s+.*exec:", "socat exec (reverse shell variant)", "T1059.004", 40),
    (r"busybox\s+.*nc\s+-", "busybox netcat (reverse shell variant)", "T1059.004", 35),
    (r"bash\s+-c\s+.*>/dev/tcp/", "bash /dev/tcp redirect", "T1059.004", 45),
    (r"exec\s+\d+<>/dev/tcp/", "bash fd redirect to /dev/tcp", "T1059.004", 45),
    # 进程伪装
    (r"exec\s+-a\s+", "process name masquerading via exec -a", "T1036.005", 25),
    (r"prctl.*PR_SET_NAME", "process name change via prctl", "T1036.005", 25),
    # 时间戳篡改
    (r"touch\s+-t\s+", "timestomping via touch -t", "T1070.006", 20),
    (r"touch\s+-r\s+", "timestamp cloning via touch -r", "T1070.006", 15),
    # sudo 缓存滥用
    (r"sudo\s+-k", "sudo credential cache manipulation", "T1548.003", 10),
    (r"echo.*\|\s*sudo\s+-S", "sudo password piping", "T1548.003", 30),
    # 信息收集/侦察
    (r"cat\s+/proc/version", "kernel version enumeration", "T1082", 5),
    (r"cat\s+/etc/issue", "OS identification", "T1082", 5),
    (r"ss\s+-[tulnp]", "socket enumeration (reconnaissance)", "T1049", 5),
    (r"last\s+-[aif]", "login history enumeration", "T1033", 5),
    (r"id\s+&&", "user identity check (chained)", "T1033", 5),
    (r"getent\s+passwd", "user enumeration via getent", "T1087.001", 10),
    (r"cat\s+/etc/group", "group enumeration", "T1069.001", 5),
    # 沙箱/VM 逃逸探测
    (r"systemd-detect-virt", "virtualization detection (sandbox evasion)", "T1497", 15),
    (r"dmidecode", "hardware enumeration (VM detection)", "T1497", 10),
    (r"cat\s+/proc/cpuinfo.*model", "CPU model check (VM detection)", "T1497", 10),
    (r"ls\s+/dev/vd[a-z]", "virtio disk check (VM detection)", "T1497", 10),
    # 更多数据外泄手法
    (r"xxd\s+.*\|\s*curl", "binary exfiltration via xxd+curl", "T1048", 35),
    (r"tar\s+.*\|\s*curl", "archive exfiltration via tar+curl", "T1048", 30),
    (r"tar\s+.*\|\s*nc\s+", "archive exfiltration via tar+nc", "T1048", 35),
    (r"curl\s+.*--data-binary\s+@/etc/", "file exfiltration via curl POST", "T1048", 40),
    (r"wget\s+--post-file", "file exfiltration via wget POST", "T1048", 35),
    # 编译后门
    (r"gcc\s+.*-shared.*-o\s+.*/tmp/", "compiling shared library in /tmp", "T1055", 30),
    (r"gcc\s+.*-shared.*\.so", "compiling shared object (potential rootkit)", "T1014", 25),
    # systemd timer 持久化
    (r"\.timer.*OnCalendar", "systemd timer persistence", "T1053.005", 30),
    (r"systemctl\s+enable", "enabling systemd service (persistence)", "T1543.002", 20),
    # 进程注入
    (r"gdb\s+-p\s+", "GDB process attach (process injection)", "T1055", 35),
    (r"ptrace", "ptrace usage (process injection)", "T1055", 30),
    (r"/proc/\d+/mem", "direct process memory access", "T1055", 35),
    # 网络隧道
    (r"ssh\s+-[RLD]\s+", "SSH tunnel/port forwarding", "T1071.001", 20),
    (r"ssh\s+-N\s+-f", "SSH background tunnel", "T1071.001", 25),
    # 防火墙操作
    (r"ufw\s+disable", "disabling UFW firewall", "T1562.004", 30),
    (r"systemctl\s+stop\s+firewalld", "stopping firewalld", "T1562.004", 30),
    (r"iptables\s+-P\s+.*ACCEPT", "setting default ACCEPT policy", "T1562.004", 25),
    # 云元数据访问 (SSRF/凭据窃取)
    (r"169\.254\.169\.254", "cloud metadata endpoint access (credential theft)", "T1552.001", 35),
    (r"metadata\.google\.internal", "GCP metadata access", "T1552.001", 35),
    (r"100\.100\.100\.200", "Alibaba Cloud metadata access", "T1552.001", 35),
    # 供应链攻击指标
    (r"pip\s+install.*--index-url\s+http://", "pip install from HTTP (supply chain risk)", "T1195", 30),
    (r"npm\s+install.*--registry\s+http://", "npm install from HTTP registry", "T1195", 30),
    (r"pip\s+install\s+.*-e\s+git\+http://", "pip install editable from HTTP", "T1195", 25),
    # 容器逃逸新手法
    (r"/var/run/docker\.sock", "Docker socket access (container escape)", "T1611", 40),
    (r"mount.*cgroup", "cgroup mount (container escape vector)", "T1611", 35),
    (r"capsh\s+--print", "capability enumeration (privilege check)", "T1548.001", 10),
    # Kubernetes 相关
    (r"/var/run/secrets/kubernetes", "K8s service account token access", "T1552.001", 30),
    (r"kubectl\s+.*--token", "kubectl with explicit token", "T1552.001", 20),
    # 内存驻留
    (r"memfd_create", "memfd_create (fileless execution)", "T1059.004", 35),
    (r"/dev/shm/.*\|.*sh", "shared memory execution", "T1059.004", 30),
    (r"/proc/self/exe", "self-re-execution (fileless technique)", "T1059.004", 25),
]

# 合法安装器的白名单特征 — 降低这些场景的分数
LEGITIMATE_PATTERNS = [
    # 包管理器操作
    (r"apt-get\s+(install|update|upgrade)", "package manager operation"),
    (r"pip\s+install\s+", "pip install"),
    (r"npm\s+install\s+", "npm install"),
    (r"yarn\s+(add|install)", "yarn install"),
    (r"gem\s+install\s+", "gem install"),
    (r"cargo\s+install\s+", "cargo install"),
    # 已知安装器
    (r"astral\.sh/uv/install", "uv installer"),
    (r"install\.python-poetry\.org", "poetry installer"),
    (r"nvm-sh/nvm.*install", "nvm installer"),
    (r"rustup\.rs", "rustup installer"),
    (r"raw\.githubusercontent\.com/nvm-sh", "nvm installer"),
    (r"get\.sdkman\.io", "sdkman installer"),
    # Note: only match install.sh when fetched from HTTPS (not local file writes)
    (r"curl\s+.*https://.*install\.sh", "HTTPS installer script"),
    (r"wget\s+.*https://.*install\.sh", "HTTPS installer script"),
    # 系统管理常见操作
    (r"apt-get\s+remove\s+", "package removal"),
    (r"dpkg\s+-[il]\s+", "dpkg install/list"),
    (r"yum\s+(install|update)\s+", "yum package management"),
    (r"dnf\s+(install|update)\s+", "dnf package management"),
    (r"pacman\s+-S\s+", "pacman package install"),
    (r"brew\s+install\s+", "homebrew install"),
    (r"snap\s+install\s+", "snap install"),
    (r"flatpak\s+install\s+", "flatpak install"),
    # 常见开发工具
    (r"docker\s+(build|run|pull|push)", "docker operation"),
    (r"kubectl\s+(apply|get|describe)", "kubernetes operation"),
    (r"terraform\s+(plan|apply|init)", "terraform operation"),
    (r"ansible-playbook\s+", "ansible operation"),
    (r"go\s+(build|install|get|mod)\s+", "go toolchain"),
    (r"mvn\s+(clean|install|package)", "maven build"),
    (r"gradle\s+(build|test)", "gradle build"),
    (r"make\s+(all|install|clean|test|build)", "makefile target"),
    (r"cmake\s+", "cmake build"),
    (r"git\s+(clone|pull|push|fetch|checkout|merge|rebase)", "git operation"),
]

# Anti-evasion: commands that should NEVER be whitelisted regardless of other patterns
BLACKLIST_OVERRIDES = [
    r">\s*/etc/",             # Writing to /etc
    r">>\s*/etc/",            # Appending to /etc
    r">\s*~/\.bashrc",        # Overwriting .bashrc
    r">>\s*~/\.bashrc",       # Appending to .bashrc
    r">\s*~/\.bash_profile",  # Overwriting .bash_profile
    r">>\s*~/\.bash_profile", # Appending to .bash_profile
    r">\s*~/\.profile",       # Overwriting .profile
    r">>\s*~/\.profile",      # Appending to .profile
    r"crontab\s+-",           # Setting crontab
    r"useradd|adduser",       # Creating users
    r"usermod\s+",            # Modifying users
    r"/etc/sudoers",          # Modifying sudoers
    r"chmod\s+u\+s",          # Setting SUID
    r"chmod\s+[0-7]*4[0-7]{3}", # Setting SUID via octal
    r"/etc/passwd",           # Modifying passwd
    r"/etc/shadow",           # Accessing shadow
    r"authorized_keys",       # Modifying SSH keys
    r"/etc/ld\.so\.preload",  # LD_PRELOAD hijack
    r"/etc/pam\.d/",          # PAM modification
    r"/etc/systemd/system/",  # Systemd service injection
    r"/etc/init\.d/",         # Init.d injection
    r"/etc/rc\.local",        # RC local injection
    r"/etc/cron\.",           # Cron directory manipulation
    r"iptables\s+-F",         # Flushing firewall
    r"iptables\s+-P\s+.*ACCEPT", # Opening firewall
    r"/dev/tcp/",             # Bash reverse shell
    r"mkfifo.*\|.*sh",        # Named pipe shell
    r"nc\s+-[elp]",           # Netcat listener/shell
    r"socat\s+.*exec:",       # Socat exec shell
]

def is_likely_legitimate_command(cmd):
    """检查命令是否匹配已知合法模式, 但黑名单优先"""
    # 黑名单覆盖: 如果匹配任何黑名单模式, 立即返回 False
    for bp in BLACKLIST_OVERRIDES:
        if re.search(bp, cmd, re.IGNORECASE):
            return False
    for pattern, _ in LEGITIMATE_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            return True
    return False

# ═══════════════════════════════════════════════════════════════════════════
#  命令去混淆引擎 — 在静态分析前尝试还原真实命令
# ═══════════════════════════════════════════════════════════════════════════

def deobfuscate_command(cmd):
    """多层去混淆: base64 -> hex -> variable expansion -> eval unwrap
    返回 (deobfuscated_cmd, layers_decoded) 元组"""
    import base64 as b64mod
    layers = []
    current = cmd

    # Layer 1: 提取并解码 base64 编码的载荷
    b64_patterns = [
        # echo 'BASE64' | base64 -d
        r"echo\s+['\"]?([A-Za-z0-9+/=]{20,})['\"]?\s*\|\s*base64\s+-d",
        # $(echo BASE64 | base64 -d)
        r"\$\(echo\s+['\"]?([A-Za-z0-9+/=]{20,})['\"]?\s*\|\s*base64\s+-d\)",
    ]
    for pattern in b64_patterns:
        match = re.search(pattern, current)
        if match:
            try:
                decoded = b64mod.b64decode(match.group(1)).decode("utf-8", errors="replace")
                layers.append(("base64", match.group(1)[:40], decoded[:200]))
                current = current[:match.start()] + decoded + current[match.end():]
            except Exception:
                pass

    # Layer 2: 提取 hex 编码 (\x41\x42 -> AB)
    hex_pattern = r'((?:\\x[0-9a-fA-F]{2}){4,})'
    match = re.search(hex_pattern, current)
    if match:
        try:
            hex_str = match.group(1)
            decoded = bytes(int(h, 16) for h in re.findall(r'\\x([0-9a-fA-F]{2})', hex_str)).decode("utf-8", errors="replace")
            layers.append(("hex", hex_str[:40], decoded[:200]))
            current = current[:match.start()] + decoded + current[match.end():]
        except Exception:
            pass

    # Layer 3: 解开 eval/exec 包装
    eval_patterns = [
        r'eval\s+["\'](.+?)["\']',
        r'eval\s+\$\((.+?)\)',
        r'python[23]?\s+-c\s+["\'].*exec\(["\'](.+?)["\']\)',
    ]
    for pattern in eval_patterns:
        match = re.search(pattern, current, re.DOTALL)
        if match:
            inner = match.group(1)
            layers.append(("eval_unwrap", "", inner[:200]))
            current = current + " ; " + inner

    # Layer 4: 简单变量替换 (常见混淆手法)
    # $'\x62\x61\x73\x68' -> bash
    dollar_quote = r"\$'((?:\\x[0-9a-fA-F]{2})+)'"
    match = re.search(dollar_quote, current)
    if match:
        try:
            hex_str = match.group(1)
            decoded = bytes(int(h, 16) for h in re.findall(r'\\x([0-9a-fA-F]{2})', hex_str)).decode("utf-8", errors="replace")
            layers.append(("dollar_quote", hex_str[:40], decoded[:200]))
            current = current[:match.start()] + decoded + current[match.end():]
        except Exception:
            pass

    return current, layers


# ═══════════════════════════════════════════════════════════════════════════
#  风险建议引擎 — 根据判定给出可操作的建议
# ═══════════════════════════════════════════════════════════════════════════

def generate_recommendations(verdict, findings, confidence):
    """根据分析结果生成可操作的安全建议"""
    recs = []
    finding_dims = set(f.dimension for f in findings)
    finding_descs = " ".join(f.description for f in findings).lower()

    if verdict == "DANGEROUS":
        recs.append("BLOCK: 强烈建议阻止此命令执行")
        if "持久化" in finding_dims or "计划任务差异" in finding_dims:
            recs.append("检查 crontab -l、/etc/cron.d/、systemd services 是否被篡改")
        if "用户/权限" in finding_dims:
            recs.append("检查 /etc/passwd、/etc/shadow、/etc/sudoers 是否有未授权变更")
        if "authorized_keys" in finding_descs:
            recs.append("审查 ~/.ssh/authorized_keys 中是否有未知公钥")
        if "reverse shell" in finding_descs or "/dev/tcp" in finding_descs:
            recs.append("检查网络连接: ss -tunap | grep ESTABLISHED")
        if "ld_preload" in finding_descs or "ld.so.preload" in finding_descs:
            recs.append("检查 /etc/ld.so.preload 和 LD_PRELOAD 环境变量")
        if "攻击链" in finding_dims:
            recs.append("多维度攻击已确认, 建议全面安全审计")

    elif verdict == "SUSPICIOUS":
        recs.append("REVIEW: 建议人工审核此命令后再决定是否放行")
        if confidence == "LOW":
            recs.append("置信度较低, 可能为误报, 请结合上下文判断")

    elif verdict == "LOW_RISK":
        recs.append("ALLOW: 风险较低, 可考虑放行但建议记录审计日志")

    else:  # LIKELY_SAFE
        recs.append("ALLOW: 命令安全, 可放行")

    return recs


# ═══════════════════════════════════════════════════════════════════════════
#  快速预判引擎 — 不启动沙箱, 纯静态秒级评估
# ═══════════════════════════════════════════════════════════════════════════

def fast_triage(cmd):
    """纯静态命令预判, 返回 (risk_level, score, matched_patterns, deob_info)
    用于 API 集成的秒级决策:
      - BLOCK:  高置信恶意, 建议直接阻断
      - REVIEW: 需沙箱深度分析
      - PASS:   高置信安全, 可直接放行
    """
    deobfuscated, deob_layers = deobfuscate_command(cmd)
    scan_cmds = [cmd]
    if deobfuscated != cmd:
        scan_cmds.append(deobfuscated)

    matched = []
    total_score = 0
    for target in scan_cmds:
        seen = set()
        for pattern, desc, mitre_id, score in MALICIOUS_CONTENT_PATTERNS:
            if desc in seen:
                continue
            if re.search(pattern, target, re.IGNORECASE):
                seen.add(desc)
                matched.append({"pattern": desc, "mitre": mitre_id, "score": score})
                total_score += score

    # 检查黑名单
    blacklisted = False
    for bp in BLACKLIST_OVERRIDES:
        for target in scan_cmds:
            if re.search(bp, target, re.IGNORECASE):
                blacklisted = True
                break

    # 检查白名单
    is_legit = is_likely_legitimate_command(cmd)
    if is_legit and not blacklisted:
        total_score = total_score // 2

    # 判定
    if total_score >= 50 or (blacklisted and total_score >= 25):
        level = "BLOCK"
    elif total_score >= 10 or matched or blacklisted:
        level = "REVIEW"
    else:
        level = "PASS"

    return {
        "level": level,
        "static_score": min(100, total_score),
        "is_legitimate": is_legit,
        "blacklisted": blacklisted,
        "patterns_matched": len(matched),
        "matches": matched[:20],
        "deobfuscation_layers": len(deob_layers),
    }


# ═══════════════════════════════════════════════════════════════════════════
#  人类可读摘要生成器
# ═══════════════════════════════════════════════════════════════════════════

def generate_text_summary(report):
    """生成一段简洁的人类可读分析摘要"""
    v = report["verdict"]
    score = report["risk_score"]
    conf = report.get("confidence", "N/A")
    cmd = report["command"]
    findings = report.get("findings", [])
    recs = report.get("recommendations", [])
    tactics = report.get("mitre_tactics", {})

    # 标题行
    icon_map = {"DANGEROUS": "🚨", "SUSPICIOUS": "⚠️", "LOW_RISK": "🔶", "LIKELY_SAFE": "✅"}
    icon = icon_map.get(v, "❓")

    lines = []
    lines.append(f"{icon} 判定: {v} (风险分: {score}/100, 置信度: {conf})")
    lines.append(f"命令: {cmd[:120]}")
    lines.append("")

    if findings:
        criticals = [f for f in findings if f.get("severity") == "CRITICAL"]
        warns = [f for f in findings if f.get("severity") == "WARN"]
        lines.append(f"发现 {len(findings)} 个问题 ({len(criticals)} 严重, {len(warns)} 警告):")
        for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "WARN": 1, "INFO": 2}.get(x.get("severity", "INFO"), 3))[:8]:
            sev = f.get("severity", "?")
            dim = f.get("dimension", "?")
            desc = f.get("description", "?")
            mitre = ", ".join(m["id"] for m in f.get("mitre_attack", []))
            mitre_str = f" [{mitre}]" if mitre else ""
            lines.append(f"  [{sev}] {dim}: {desc}{mitre_str}")
        if len(findings) > 8:
            lines.append(f"  ... 还有 {len(findings)-8} 个发现")
    else:
        lines.append("全部 24 维度检查通过, 命令安全。")

    if tactics:
        lines.append("")
        lines.append(f"涉及 ATT&CK 战术: {', '.join(sorted(tactics.keys()))}")

    if recs:
        lines.append("")
        lines.append("建议:")
        for rec in recs[:3]:
            lines.append(f"  • {rec}")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
#  SARIF 输出生成器 — 行业标准安全分析结果格式
# ═══════════════════════════════════════════════════════════════════════════

def generate_sarif(report):
    """将分析报告转换为 SARIF v2.1.0 格式 (GitHub Code Scanning / GitLab SAST)"""
    severity_map = {
        "CRITICAL": "error",
        "WARN": "warning",
        "INFO": "note",
    }
    level_map = {
        "DANGEROUS": "error",
        "SUSPICIOUS": "warning",
        "LOW_RISK": "note",
        "LIKELY_SAFE": "none",
    }

    rules = []
    results = []
    rule_ids = set()

    for i, finding in enumerate(report.get("findings", [])):
        # 构建 rule ID
        mitre_ids = [m["id"] for m in finding.get("mitre_attack", [])]
        rule_id = mitre_ids[0] if mitre_ids else f"CMD-{i+1:03d}"
        if rule_id in rule_ids:
            rule_id = f"{rule_id}-{i}"
        rule_ids.add(rule_id)

        # SARIF rule
        rule = {
            "id": rule_id,
            "name": finding.get("dimension", "Unknown"),
            "shortDescription": {"text": finding.get("description", "")[:256]},
            "helpUri": f"https://attack.mitre.org/techniques/{mitre_ids[0].replace('.', '/')}" if mitre_ids else "",
            "properties": {
                "tags": [f"security", f"command-safety"] + [f"mitre/{m}" for m in mitre_ids],
            },
        }
        if mitre_ids:
            mitre_desc = ", ".join(m + " (" + MITRE.get(m, "") + ")" for m in mitre_ids)
            rule["help"] = {
                "text": "MITRE ATT&CK: " + mitre_desc
            }
        rules.append(rule)

        # SARIF result
        result = {
            "ruleId": rule_id,
            "level": severity_map.get(finding.get("severity", "INFO"), "note"),
            "message": {
                "text": finding.get("description", ""),
            },
            "properties": {
                "risk_score": finding.get("risk_score", 0),
                "dimension": finding.get("dimension", ""),
            },
        }
        if finding.get("evidence"):
            result["properties"]["evidence"] = finding["evidence"][:500]
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Command Safety Analyzer",
                    "version": report.get("version", "4.4"),
                    "informationUri": "https://github.com/command-safety-analyzer",
                    "rules": rules,
                    "properties": {
                        "verdict": report.get("verdict", "UNKNOWN"),
                        "risk_score": report.get("risk_score", -1),
                        "confidence": report.get("confidence", "N/A"),
                    },
                },
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "properties": {
                    "command": report.get("command", ""),
                    "verdict": report.get("verdict", ""),
                    "risk_score": report.get("risk_score", -1),
                    "confidence": report.get("confidence", ""),
                    "timestamp": report.get("timestamp", ""),
                },
            }],
        }],
    }
    return sarif


# ═══════════════════════════════════════════════════════════════════════════
#  命令链分解器 — 拆分多阶段命令并逐段分析
# ═══════════════════════════════════════════════════════════════════════════

def decompose_command_chain(cmd):
    """将复合命令拆分为独立阶段, 返回 [(stage_cmd, connector)] 列表
    支持: ; && || | 以及子 shell $()"""
    import shlex
    stages = []
    # 简单分割 (不处理嵌套引号内的分隔符 — 对分析够用)
    # 按优先级处理: ; 最低, && || 中等, | 最高
    current = ""
    i = 0
    in_quote = None
    while i < len(cmd):
        c = cmd[i]
        # 跟踪引号
        if c in ("'", '"') and in_quote is None:
            in_quote = c
            current += c
        elif c == in_quote:
            in_quote = None
            current += c
        elif in_quote:
            current += c
        # 分隔符检测 (不在引号内)
        elif c == ';':
            if current.strip():
                stages.append((current.strip(), ";"))
            current = ""
        elif c == '&' and i + 1 < len(cmd) and cmd[i + 1] == '&':
            if current.strip():
                stages.append((current.strip(), "&&"))
            current = ""
            i += 1
        elif c == '|' and i + 1 < len(cmd) and cmd[i + 1] == '|':
            if current.strip():
                stages.append((current.strip(), "||"))
            current = ""
            i += 1
        elif c == '|':
            if current.strip():
                stages.append((current.strip(), "|"))
            current = ""
        else:
            current += c
        i += 1

    if current.strip():
        stages.append((current.strip(), "END"))

    return stages


# ═══════════════════════════════════════════════════════════════════════════
#  辅助函数
# ═══════════════════════════════════════════════════════════════════════════
def section(t):
    print(f"\n{'='*W}\n  {t}\n{'='*W}", flush=True)

def sub(t):
    print(f"\n  --- {t} ---", flush=True)

async def run_cmd(sb, cmd, timeout_sec=120):
    try:
        r = await asyncio.wait_for(sb.commands.run(cmd), timeout=timeout_sec)
        out = "\n".join(m.text for m in r.logs.stdout) if r.logs.stdout else ""
        err = "\n".join(m.text for m in r.logs.stderr) if r.logs.stderr else ""
        return out, err
    except asyncio.TimeoutError:
        return "", f"[TIMEOUT {timeout_sec}s]"
    except Exception as e:
        return "", f"[ERROR] {e}"

# ── 快照采集函数 ──────────────────────────────────────────────────────────

async def snap_fs(sb):
    """文件快照, 排除基础设施文件"""
    o, _ = await run_cmd(sb,
        "find / -xdev -not -path '/proc/*' -not -path '/sys/*' "
        "-not -path '/dev/*' -not -path '/run/*' "
        "-type f -printf '%s %T@ %p\\n' 2>/dev/null | sort", 60)
    result = set()
    for line in (o.strip().splitlines() if o.strip() else []):
        parts = line.split(" ", 2)
        path = parts[2] if len(parts) == 3 else line
        if not is_infra(path):
            result.add(line)
    return result

async def snap_ps(sb):
    o, _ = await run_cmd(sb, "ps auxf 2>/dev/null || ps aux")
    return o

async def snap_persist(sb):
    """持久化机制全面快照: cron + systemd + rc.local + init.d + at + timer
       返回完整内容而非 md5, 以便后续做精确差值分析"""
    o, _ = await run_cmd(sb,
        "{ "
        "echo '=== CRONTAB ==='; crontab -l 2>/dev/null || true; "
        "echo '=== /etc/crontab ==='; cat /etc/crontab 2>/dev/null || true; "
        "echo '=== cron.d ==='; for f in /etc/cron.d/*; do [ -f \"$f\" ] && echo \"--- $f ---\" && cat \"$f\"; done 2>/dev/null || true; "
        "echo '=== cron.daily ==='; ls /etc/cron.daily/ 2>/dev/null | sort || true; "
        "echo '=== systemd user ==='; ls ~/.config/systemd/user/*.service 2>/dev/null || true; "
        "echo '=== systemd system ==='; ls /etc/systemd/system/*.service 2>/dev/null || true; "
        "echo '=== rc.local ==='; cat /etc/rc.local 2>/dev/null || true; "
        "echo '=== init.d ==='; ls /etc/init.d/ 2>/dev/null | sort || true; "
        "echo '=== at queue ==='; atq 2>/dev/null || true; "
        "echo '=== systemd timers ==='; systemctl list-timers --no-pager 2>/dev/null || true; "
        "}")
    return o

async def snap_auth(sb):
    """用户/权限全面快照"""
    o, _ = await run_cmd(sb,
        "awk -F: '{print $1\":\"$3\":\"$7}' /etc/passwd 2>/dev/null | sort; "
        "echo '---SHADOW---'; "
        "wc -l /etc/shadow 2>/dev/null || true; "
        "echo '---SUDOERS---'; "
        "cat /etc/sudoers 2>/dev/null | md5sum; "
        "ls /etc/sudoers.d/ 2>/dev/null | sort || true; "
        "echo '---SSH---'; "
        "find /root/.ssh /home -name 'authorized_keys' -exec md5sum {} \\; 2>/dev/null || echo 'no-ssh'; "
        "echo '---PAM---'; "
        "ls /etc/pam.d/ 2>/dev/null | sort | md5sum")
    return o

async def snap_shell(sb):
    """Shell 配置快照 — 包括全局和用户级, 返回完整内容以便差值分析"""
    o, _ = await run_cmd(sb,
        "echo '=== bashrc ==='; cat ~/.bashrc 2>/dev/null || true; "
        "echo '=== bash_profile ==='; cat ~/.bash_profile 2>/dev/null || true; "
        "echo '=== profile ==='; cat ~/.profile 2>/dev/null || true; "
        "echo '=== bash_logout ==='; cat ~/.bash_logout 2>/dev/null || true; "
        "echo '=== etc_profile ==='; cat /etc/profile 2>/dev/null || true; "
        "echo '=== etc_bashrc ==='; cat /etc/bash.bashrc 2>/dev/null || true; "
        "echo '=== etc_environment ==='; cat /etc/environment 2>/dev/null || true; "
        "echo '=== profile.d ==='; cat /etc/profile.d/*.sh 2>/dev/null || true")
    return o

async def snap_suid(sb):
    """SUID/SGID 文件快照 - 使用稳定格式避免时间戳差异"""
    o, _ = await run_cmd(sb,
        "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f "
        "-printf '%m %u %g %p\\n' 2>/dev/null | sort", 30)
    return set(o.strip().splitlines()) if o.strip() else set()

async def snap_mounts(sb):
    """挂载点快照"""
    o, _ = await run_cmd(sb, "mount 2>/dev/null | sort")
    return o

async def snap_modules(sb):
    """内核模块快照"""
    o, _ = await run_cmd(sb, "lsmod 2>/dev/null | sort || cat /proc/modules 2>/dev/null | sort || echo 'N/A'")
    return o

async def snap_env(sb):
    """环境变量快照 (关注安全相关)"""
    o, _ = await run_cmd(sb,
        "env 2>/dev/null | grep -E "
        "'(LD_PRELOAD|LD_LIBRARY_PATH|PATH|HOME|SHELL|USER|SUDO|HTTP_PROXY|HTTPS_PROXY)' "
        "| sort || true")
    return o

async def snap_caps(sb):
    """进程能力快照"""
    o, _ = await run_cmd(sb,
        "cat /proc/1/status 2>/dev/null | grep -i cap || true")
    return o

async def snap_critical_bins(sb):
    """关键系统二进制文件 hash 快照"""
    o, _ = await run_cmd(sb,
        "md5sum /bin/bash /bin/sh /bin/su /usr/bin/sudo /usr/bin/passwd "
        "/usr/bin/crontab /usr/sbin/sshd /bin/login "
        "/usr/bin/ssh /usr/bin/newgrp 2>/dev/null | sort || true", 15)
    return o

async def snap_symlinks(sb):
    """关键目录中的符号链接快照"""
    o, _ = await run_cmd(sb,
        "find /etc /root /home /tmp /usr/local/bin -maxdepth 3 -type l "
        "-exec ls -la {} \\; 2>/dev/null | sort || true", 20)
    return set(o.strip().splitlines()) if o.strip() else set()

async def snap_file_caps(sb):
    """文件能力 (getcap) 快照"""
    o, _ = await run_cmd(sb,
        "getcap -r / 2>/dev/null | sort || true", 20)
    return set(o.strip().splitlines()) if o.strip() else set()

def calculate_entropy(data):
    """计算字节串的 Shannon 熵 (0-8, 越高越随机)"""
    if not data:
        return 0.0
    import math
    freq = defaultdict(int)
    for c in data:
        freq[c] += 1
    length = len(data)
    entropy = -sum((count/length) * math.log2(count/length)
                    for count in freq.values() if count > 0)
    return round(entropy, 2)

# ── 网络分析 ────────────────────────────────────────────────────────────

def parse_proc_net(raw):
    conns = set()
    for line in raw.splitlines():
        parts = line.strip().split()
        if len(parts) < 4 or parts[0] == "sl":
            continue
        try:
            ip_hex, port_hex = parts[2].split(":")
            n = int(ip_hex, 16)
            ip = f"{n&0xFF}.{(n>>8)&0xFF}.{(n>>16)&0xFF}.{(n>>24)&0xFF}"
            port = int(port_hex, 16)
            if ip != "0.0.0.0" and port != 0:
                conns.add((ip, port))
        except (ValueError, IndexError):
            continue
    return conns

def is_internal(ip):
    return (ip.startswith("127.") or ip.startswith("172.17.") or
            ip.startswith("172.18.") or ip.startswith("10.") or
            ip.startswith("169.254.") or ip == "0.0.0.0")

def extract_path(entry):
    parts = entry.split(" ", 2)
    return parts[2] if len(parts) == 3 else entry

# ═══════════════════════════════════════════════════════════════════════════
#  评分引擎
# ═══════════════════════════════════════════════════════════════════════════

class Finding:
    """单条发现"""
    def __init__(self, severity, dimension, description, score, mitre_ids=None, evidence=None):
        self.severity = severity          # CRITICAL / WARN / INFO
        self.dimension = dimension        # 检测维度名
        self.description = description    # 发现描述
        self.score = score                # 风险分 (0-50, 越高越危险)
        self.mitre_ids = mitre_ids or []  # MITRE ATT&CK 技术 ID
        self.evidence = evidence or ""    # 原始证据

    def to_dict(self):
        d = {
            "severity": self.severity,
            "dimension": self.dimension,
            "description": self.description,
            "risk_score": self.score,
        }
        if self.mitre_ids:
            d["mitre_attack"] = [
                {"id": mid, "name": MITRE.get(mid, "Unknown")}
                for mid in self.mitre_ids
            ]
        if self.evidence:
            d["evidence"] = self.evidence[:500]
        return d


class ScoringEngine:
    """加权风险评分引擎 v4 — 含置信度评估 + 攻击链加成"""

    def __init__(self, command):
        self.command = command
        self.findings = []
        self.is_legitimate = is_likely_legitimate_command(command)

    def add(self, severity, dimension, desc, score, mitre_ids=None, evidence=None):
        # 合法命令降低部分维度的分数
        if self.is_legitimate and severity != "CRITICAL":
            score = max(0, score // LEGITIMATE_DIVISOR)
        self.findings.append(Finding(severity, dimension, desc, score, mitre_ids, evidence))

    def total_score(self):
        return min(100, sum(f.score for f in self.findings))

    def verdict(self):
        score = self.total_score()
        criticals = [f for f in self.findings if f.severity == "CRITICAL"]
        # 攻击链发现会加重判定
        chain_findings = [f for f in self.findings if f.dimension == "攻击链"]
        if score >= DANGEROUS_THRESHOLD or len(criticals) >= DANGEROUS_CRITICALS or (chain_findings and criticals):
            return "DANGEROUS"
        elif score >= SUSPICIOUS_THRESHOLD or criticals:
            return "SUSPICIOUS"
        elif score >= LOW_RISK_THRESHOLD:
            return "LOW_RISK"
        else:
            return "LIKELY_SAFE"

    def confidence(self):
        """评估判定的置信度 (HIGH/MEDIUM/LOW)"""
        score = self.total_score()
        criticals = len([f for f in self.findings if f.severity == "CRITICAL"])
        unique_dims = len(set(f.dimension for f in self.findings))
        chain_findings = len([f for f in self.findings if f.dimension == "攻击链"])

        verdict = self.verdict()
        if verdict == "DANGEROUS":
            if criticals >= 3 or (criticals >= 2 and unique_dims >= 3) or chain_findings >= 2:
                return "HIGH"
            elif criticals >= 1 and unique_dims >= 2:
                return "MEDIUM"
            else:
                return "LOW"
        elif verdict == "SUSPICIOUS":
            if unique_dims >= 3:
                return "HIGH"
            elif unique_dims >= 2:
                return "MEDIUM"
            else:
                return "LOW"
        elif verdict == "LIKELY_SAFE":
            if score == 0:
                return "HIGH"
            else:
                return "MEDIUM"
        else:  # LOW_RISK
            return "MEDIUM"

    def mitre_summary(self):
        """汇总所有涉及的 MITRE ATT&CK 技术"""
        techniques = {}
        for f in self.findings:
            for mid in f.mitre_ids:
                if mid not in techniques:
                    techniques[mid] = {"name": MITRE.get(mid, "Unknown"), "findings": []}
                techniques[mid]["findings"].append(f.description)
        return techniques

    def tactic_summary(self):
        """按 ATT&CK 战术分组"""
        TACTIC_MAP = {
            "T1059": "Execution", "T1053": "Persistence", "T1543": "Persistence",
            "T1037": "Persistence", "T1546": "Persistence", "T1547": "Persistence",
            "T1136": "Persistence", "T1098": "Persistence",
            "T1548": "Privilege Escalation", "T1574": "Privilege Escalation",
            "T1055": "Privilege Escalation",
            "T1070": "Defense Evasion", "T1027": "Defense Evasion",
            "T1036": "Defense Evasion", "T1014": "Defense Evasion",
            "T1562": "Defense Evasion", "T1564": "Defense Evasion",
            "T1140": "Defense Evasion", "T1497": "Defense Evasion",
            "T1556": "Credential Access", "T1003": "Credential Access",
            "T1552": "Credential Access",
            "T1057": "Discovery", "T1082": "Discovery", "T1016": "Discovery",
            "T1049": "Discovery", "T1033": "Discovery", "T1083": "Discovery",
            "T1087": "Discovery", "T1069": "Discovery", "T1018": "Discovery",
            "T1007": "Discovery",
            "T1048": "Exfiltration", "T1105": "Command and Control",
            "T1071": "Command and Control", "T1021": "Lateral Movement",
            "T1496": "Impact", "T1611": "Execution",
        }
        tactics = defaultdict(list)
        for f in self.findings:
            for mid in f.mitre_ids:
                prefix = mid.split(".")[0]
                tactic = TACTIC_MAP.get(prefix, "Unknown")
                tactics[tactic].append(mid)
        return dict(tactics)


# ═══════════════════════════════════════════════════════════════════════════
#  主分析流程
# ═══════════════════════════════════════════════════════════════════════════

async def main():
    evidence = {}
    config = ConnectionConfig(domain=f"localhost:{PORT}", request_timeout=timedelta(seconds=600))
    engine = ScoringEngine(COMMAND)

    # ── 1/9 创建沙箱 ──
    section("1/9  创建隔离沙箱")
    print(f"  镜像: {IMAGE}", flush=True)
    try:
        sandbox = await asyncio.wait_for(
            Sandbox.create(IMAGE, connection_config=config, timeout=timedelta(minutes=10)),
            timeout=120)
    except asyncio.TimeoutError:
        print("\n  !! 创建超时 (120s). 检查 docker ps -a"); raise SystemExit(1)
    except Exception as e:
        print(f"\n  !! 创建失败: {e}"); raise SystemExit(1)
    print(f"  Sandbox ID: {sandbox.id}")

    async with sandbox:

        # ── 2/9 安装监控工具 ──
        section("2/9  安装监控工具 (快照前, 避免污染基线)")
        await run_cmd(sandbox,
            "apt-get update -qq 2>/dev/null && "
            "apt-get install -y -qq inotify-tools procps 2>/dev/null || "
            "yum install -y -q inotify-tools procps-ng 2>/dev/null || "
            "apk add inotify-tools procps 2>/dev/null || "
            "echo 'skip'", timeout_sec=120)
        print("  监控工具已安装")

        # ── 3/9 全维度基线采集 ──
        section("3/9  采集执行前基线 (24 维度)")
        t0 = time.time()

        (pre_fs, pre_ps, pre_persist, pre_auth, pre_shell,
         pre_suid, pre_mounts, pre_modules, pre_env, pre_caps,
         pre_bins, pre_symlinks, pre_file_caps) = await asyncio.gather(
            snap_fs(sandbox), snap_ps(sandbox),
            snap_persist(sandbox), snap_auth(sandbox), snap_shell(sandbox),
            snap_suid(sandbox), snap_mounts(sandbox), snap_modules(sandbox),
            snap_env(sandbox), snap_caps(sandbox),
            snap_critical_bins(sandbox), snap_symlinks(sandbox), snap_file_caps(sandbox))

        print(f"  文件数       : {len(pre_fs)}")
        print(f"  SUID/SGID    : {len(pre_suid)}")
        print(f"  符号链接     : {len(pre_symlinks)}")
        print(f"  文件能力     : {len(pre_file_caps)}")
        print(f"  基线采集耗时 : {time.time()-t0:.1f}s")
        try:
            pre_m = await sandbox.get_metrics()
            print(f"  CPU          : {pre_m.cpu_used_percentage:.1f}%")
            print(f"  Memory       : {pre_m.memory_used_in_mib:.1f}/{pre_m.memory_total_in_mib:.1f} MiB")
        except Exception:
            pre_m = None

        # ── 4/9 启动多层探针 + 执行命令 ──
        section("4/9  启动多层探针 + 执行待测命令")

        # 探针 1: inotifywait 监控系统关键目录
        await run_cmd(sandbox,
            "nohup inotifywait -mr -e create,modify,delete,moved_to,attrib "
            "--timefmt '%Y-%m-%dT%H:%M:%S' --format '%T %e %w%f' "
            "/usr/local/bin /usr/bin /usr/sbin /etc /root /home "
            "> /var/log/.inotify_log 2>/dev/null &", 10)
        print("  [探针1] inotify: /usr/local/bin /usr/bin /usr/sbin /etc /root /home")

        # 探针 2: inotifywait 独立监控 /tmp (避免递归, 日志写到 /var/log)
        await run_cmd(sandbox,
            "nohup inotifywait -mr -e create,modify,delete,moved_to,attrib "
            "--timefmt '%Y-%m-%dT%H:%M:%S' --format '%T %e %w%f' "
            "--exclude '\\.(stdout|stderr|inotify|net_|resolv_|proc_|audit_|suid_|mount_|modules_|env_|caps_|conntrack_)' "
            "/tmp /var/tmp /dev/shm "
            "> /tmp/.inotify_tmp_log 2>/dev/null &", 10)
        print("  [探针2] inotify: /tmp /var/tmp /dev/shm (独立探针)")

        # 探针 3: 网络连接轮询 (高频)
        await run_cmd(sandbox, "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null > /tmp/.net_baseline", 5)
        await run_cmd(sandbox,
            "nohup sh -c 'while true; do "
            "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null; "
            "sleep 0.5; done > /tmp/.net_poll_log 2>/dev/null' &", 5)
        print("  [探针3] network: /proc/net/tcp 轮询 (0.5s)")

        # 探针 4: DNS 基线
        await run_cmd(sandbox, "cp /etc/resolv.conf /tmp/.resolv_baseline 2>/dev/null || true", 5)

        # 探针 5: 进程树追踪 (记录命令执行期间产生的所有进程)
        await run_cmd(sandbox,
            "nohup sh -c 'while true; do "
            "ps auxf 2>/dev/null || ps aux 2>/dev/null; "
            "echo \"=== $(date +%s) ===\"; "
            "sleep 1; done > /tmp/.proc_tree_log 2>/dev/null' &", 5)
        print("  [探针5] process: 进程树轮询 (1s)")

        # ── 命令链分解 ──
        sub("命令链分解分析")
        chain_stages = decompose_command_chain(COMMAND)
        if len(chain_stages) > 1:
            print(f"    命令包含 {len(chain_stages)} 个执行阶段:")
            stage_risk_map = {}
            for idx, (stage_cmd, connector) in enumerate(chain_stages):
                # 对每个阶段进行快速风险评估
                stage_matches = []
                for pattern, desc, mitre_id, score in MALICIOUS_CONTENT_PATTERNS:
                    if re.search(pattern, stage_cmd, re.IGNORECASE):
                        stage_matches.append(desc)
                risk_indicator = "!!" if stage_matches else "OK"
                print(f"    [{idx+1}] [{risk_indicator}] {stage_cmd[:80]} {connector}")
                if stage_matches:
                    print(f"        匹配: {', '.join(stage_matches[:3])}")
                stage_risk_map[idx] = stage_matches

            # 检测隐蔽的多阶段攻击: 前面是合法操作, 后面是恶意
            safe_then_evil = False
            for idx in range(len(chain_stages) - 1):
                is_early_legit = any(
                    re.search(p, chain_stages[idx][0], re.IGNORECASE)
                    for p, _ in LEGITIMATE_PATTERNS
                )
                is_later_evil = bool(stage_risk_map.get(idx + 1, []))
                if is_early_legit and is_later_evil:
                    safe_then_evil = True
                    engine.add("WARN", "命令链", f"检测到合法命令掩护恶意阶段 (阶段 {idx+1} -> {idx+2})",
                              15, ["T1059.004"],
                              f"合法: {chain_stages[idx][0][:80]}\n恶意: {chain_stages[idx+1][0][:80]}")
                    print(f"    !! 阶段 {idx+1} (合法) 掩护阶段 {idx+2} (恶意)")

            evidence["command_chain"] = {
                "stages": len(chain_stages),
                "connectors": [c for _, c in chain_stages],
                "safe_then_evil": safe_then_evil,
            }
        else:
            print("    单阶段命令")

        # ── 命令去混淆 ──
        sub("命令去混淆分析")
        deobfuscated, deob_layers = deobfuscate_command(COMMAND)
        if deob_layers:
            for layer_type, encoded, decoded in deob_layers:
                print(f"    !! [{layer_type}] 发现编码层: {encoded}...")
                print(f"       解码结果: {decoded[:100]}")
                engine.add("WARN", "去混淆", f"命令包含 {layer_type} 编码层",
                          15, ["T1140"], f"{layer_type}: {decoded[:200]}")
            print(f"    去混淆后命令: {deobfuscated[:120]}")
            evidence["deobfuscation_layers"] = [
                {"type": t, "encoded": e[:100], "decoded": d[:200]}
                for t, e, d in deob_layers
            ]
        else:
            print("    PASS  未发现编码/混淆层")

        # ── 命令静态分析 (执行前) ──
        sub("命令静态分析")
        # 同时扫描原始命令和去混淆后的命令
        scan_targets = [("原始命令", COMMAND)]
        if deobfuscated != COMMAND:
            scan_targets.append(("去混淆命令", deobfuscated))

        cmd_findings = []
        seen_descs = set()
        for target_name, target_cmd in scan_targets:
            for pattern, desc, mitre_id, score in MALICIOUS_CONTENT_PATTERNS:
                if desc in seen_descs:
                    continue
                if re.search(pattern, target_cmd, re.IGNORECASE):
                    seen_descs.add(desc)
                    cmd_findings.append((desc, mitre_id, score))
                    sev = "CRITICAL" if score >= 35 else "WARN"
                    engine.add(sev, "静态分析", f"命令匹配恶意模式: {desc}",
                              score, [mitre_id], target_cmd[:200])
                    suffix = f" (via {target_name})" if target_name != "原始命令" else ""
                    print(f"    !! [{mitre_id}] {desc} (score: {score}){suffix}")
        if not cmd_findings:
            print("    PASS  未匹配已知恶意模式")
        if engine.is_legitimate:
            print(f"    [INFO] 命令匹配合法安装器模式, 部分告警已降权")

        # ── 执行待测命令 ──
        print(f"\n  $ {COMMAND}")
        print(f"  {'─'*60}", flush=True)
        t1 = time.time()
        # 包裹命令以捕获退出码
        wrapped_cmd = f"{{ {COMMAND} ; }}; echo \"__EXIT_CODE__$?\""
        stdout_raw, stderr = await run_cmd(sandbox, wrapped_cmd, timeout_sec=300)
        dur = time.time() - t1

        # 提取退出码
        exit_code = -1
        stdout = stdout_raw
        if "__EXIT_CODE__" in stdout_raw:
            lines = stdout_raw.splitlines()
            for i, line in enumerate(lines):
                if line.startswith("__EXIT_CODE__"):
                    try:
                        exit_code = int(line.replace("__EXIT_CODE__", ""))
                    except ValueError:
                        pass
                    stdout = "\n".join(lines[:i])
                    break

        stdout_lines = stdout.splitlines() if stdout else []
        stderr_lines = stderr.splitlines() if stderr else []
        print(f"\n  耗时     : {dur:.1f}s")
        print(f"  退出码   : {exit_code}")
        print(f"  stdout   : {len(stdout_lines)} 行")
        print(f"  stderr   : {len(stderr_lines)} 行")
        if stdout_lines:
            sub("stdout (前 50 行)")
            for l in stdout_lines[:50]:
                print(f"    | {l}")
            if len(stdout_lines) > 50:
                print(f"    | ... ({len(stdout_lines)-50} more)")
        if stderr_lines:
            sub("stderr (前 30 行)")
            for l in stderr_lines[:30]:
                print(f"    | {l}")

        evidence["stdout_lines"] = len(stdout_lines)
        evidence["stderr_lines"] = len(stderr_lines)
        evidence["exec_duration_sec"] = round(dur, 1)

        # ── 5/9 等待 + 采集执行后快照 ──
        section("5/9  采集执行后快照 (全维度)")
        await asyncio.sleep(3)  # 给短暂延迟的行为更多时间暴露

        (post_fs, post_ps, post_persist, post_auth, post_shell,
         post_suid, post_mounts, post_modules, post_env, post_caps,
         post_bins, post_symlinks, post_file_caps) = await asyncio.gather(
            snap_fs(sandbox), snap_ps(sandbox),
            snap_persist(sandbox), snap_auth(sandbox), snap_shell(sandbox),
            snap_suid(sandbox), snap_mounts(sandbox), snap_modules(sandbox),
            snap_env(sandbox), snap_caps(sandbox),
            snap_critical_bins(sandbox), snap_symlinks(sandbox), snap_file_caps(sandbox))

        try:
            post_m = await sandbox.get_metrics()
        except Exception:
            post_m = None

        # 收集所有探针日志
        inotify_sys_log, _ = await run_cmd(sandbox, "cat /var/log/.inotify_log 2>/dev/null")
        inotify_tmp_log, _ = await run_cmd(sandbox, "cat /tmp/.inotify_tmp_log 2>/dev/null")
        net_poll_log, _ = await run_cmd(sandbox, "cat /tmp/.net_poll_log 2>/dev/null")
        resolv_after, _ = await run_cmd(sandbox, "cat /etc/resolv.conf 2>/dev/null")
        resolv_before, _ = await run_cmd(sandbox, "cat /tmp/.resolv_baseline 2>/dev/null")
        proc_tree_log, _ = await run_cmd(sandbox, "cat /tmp/.proc_tree_log 2>/dev/null")
        post_net, _ = await run_cmd(sandbox,
            "ss -tunap 2>/dev/null || cat /proc/net/tcp /proc/net/tcp6 2>/dev/null || echo N/A")

        inotify_log = inotify_sys_log + "\n" + inotify_tmp_log
        print(f"  文件数       : {len(post_fs)}")
        print(f"  SUID/SGID    : {len(post_suid)}")
        print(f"  inotify 系统 : {len(inotify_sys_log.splitlines())} 条")
        print(f"  inotify /tmp : {len(inotify_tmp_log.splitlines())} 条")

        # ── 6/9 网络行为分析 ──
        section("6/9  网络行为深度分析")

        baseline_conns = parse_proc_net(
            (await run_cmd(sandbox, "cat /tmp/.net_baseline 2>/dev/null"))[0])
        poll_conns = parse_proc_net(net_poll_log)
        new_conns_raw = poll_conns - baseline_conns
        external = {(ip, p) for ip, p in new_conns_raw if not is_internal(ip)}
        internal = new_conns_raw - external

        sub("外部连接 (出站)")
        if external:
            for ip, port in sorted(external):
                proto = "HTTPS" if port == 443 else "HTTP" if port == 80 else f":{port}"
                print(f"    -> {ip}:{port} ({proto})")

            # 非标准端口的外部连接更可疑
            suspicious_ports = [(ip, p) for ip, p in external if p not in (80, 443, 53, 8080, 8443)]
            if suspicious_ports:
                engine.add("WARN", "网络", f"外部非标准端口连接: {suspicious_ports}",
                          20, ["T1071.001"],
                          str(suspicious_ports))

            # C2 常见端口检测
            c2_ports = {4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337, 12345,
                       4443, 8443, 1337, 6667, 6697}  # 常见 C2/IRC/RAT 端口
            c2_conns = [(ip, p) for ip, p in external if p in c2_ports]
            if c2_conns:
                engine.add("CRITICAL", "网络", f"检测到 C2 常见端口连接: {c2_conns}",
                          35, ["T1071.001"],
                          str(c2_conns))
                for ip, p in c2_conns:
                    print(f"    !! C2 端口: {ip}:{p}")

            # 多目标连接检测 (信息收集/扫描)
            unique_ips = set(ip for ip, _ in external)
            if len(unique_ips) >= 5:
                engine.add("WARN", "网络", f"连接到 {len(unique_ips)} 个不同 IP (可能在扫描)",
                          15, ["T1018"],
                          str(sorted(unique_ips)[:20]))

            # 高端口连接检测 (>= 49152 临时端口范围内的监听)
            high_port_conns = [(ip, p) for ip, p in external if p >= 49152]
            if high_port_conns:
                engine.add("INFO", "网络", f"高位端口连接: {high_port_conns[:5]}",
                          5, ["T1071.001"], str(high_port_conns[:5]))
        else:
            print("    (无外部连接)")

        if internal:
            print(f"\n    [{len(internal)} 个内部连接已忽略]")

        evidence["external_connections"] = [f"{ip}:{p}" for ip, p in sorted(external)]
        evidence["c2_port_hits"] = [f"{ip}:{p}" for ip, p in sorted(external) if p in {4444,5555,6666,7777,8888,9999,1234,31337,12345,4443,8443,1337,6667,6697}] if external else []

        # ── DNS 分析 ──
        sub("DNS 配置")
        if resolv_before.strip() == resolv_after.strip():
            print("    PASS  /etc/resolv.conf 未被修改")
        else:
            engine.add("CRITICAL", "DNS", "/etc/resolv.conf 被修改 (DNS 劫持)",
                      30, ["T1016"], resolv_after[:200])
            print("    !! /etc/resolv.conf 已被修改!")
            print(f"    Before: {resolv_before.strip()[:80]}")
            print(f"    After:  {resolv_after.strip()[:80]}")

        # ── 7/9 全维度安全对比 ──
        section("7/9  全维度安全对比分析 (24 维度)")

        # ━━ 维度 1: 文件变更 ━━
        new_files = post_fs - pre_fs
        deleted_files = pre_fs - post_fs
        new_paths = sorted(extract_path(f) for f in new_files)
        del_paths = sorted(extract_path(f) for f in deleted_files)

        sub(f"[D1] 文件变更 (+{len(new_paths)} / -{len(del_paths)})")
        if new_paths:
            print(f"    新增 {len(new_paths)} 个:")
            for p in new_paths[:100]:
                print(f"      + {p}")
            if len(new_paths) > 100:
                print(f"      ... 还有 {len(new_paths)-100} 个")
        else:
            print("    (无新增)")
        if del_paths:
            print(f"    删除 {len(del_paths)} 个:")
            for p in del_paths[:30]:
                print(f"      - {p}")

        evidence["files_added"] = len(new_paths)
        evidence["files_deleted"] = len(del_paths)

        SENSITIVE = ["/etc/passwd", "/etc/shadow", "/etc/sudoers",
                     "/root/.ssh", "/etc/ssh/", "/usr/sbin/",
                     "/etc/ld.so", "/etc/pam.d/", "/etc/security/",
                     "/etc/systemd/system/", "/etc/init.d/",
                     "/etc/cron", "/etc/profile"]
        # 包管理器合法操作会更新的路径 — 当命令是合法安装器时排除
        PKG_MGR_SAFE = {"/etc/ld.so.cache", "/etc/ld.so.conf.d/",
                        "/etc/apt/", "/etc/dpkg/", "/etc/alternatives/",
                        "/etc/default/", "/etc/logrotate.d/",
                        "/etc/bash_completion.d/", "/etc/profile.d/",
                        "/etc/init.d/", "/etc/systemd/system/"}
        suspicious_paths = [p for p in new_paths if any(p.startswith(s) for s in SENSITIVE)]
        if engine.is_legitimate and suspicious_paths:
            # 合法安装器:只保留真正异常的路径(排除包管理器常规更新)
            suspicious_paths = [p for p in suspicious_paths
                               if not any(p.startswith(safe) or p == safe.rstrip('/')
                                          for safe in PKG_MGR_SAFE)]
        if suspicious_paths:
            engine.add("CRITICAL", "文件变更", f"敏感路径写入: {suspicious_paths[:10]}",
                      35, ["T1222.002"], str(suspicious_paths[:10]))
            print(f"    !! 敏感路径写入: {suspicious_paths[:10]}")

        # ━━ 维度 2: 实时文件事件 (系统目录) ━━
        sub("[D2] 实时文件事件 (inotifywait)")
        sys_events = [l for l in inotify_sys_log.splitlines() if l.strip()]
        tmp_events = [l for l in inotify_tmp_log.splitlines() if l.strip()]
        # 过滤掉基础设施文件的事件
        tmp_events = [l for l in tmp_events
                      if not any(inf in l for inf in [".inotify", ".net_", ".resolv_",
                                                       ".proc_", ".audit_", ".suid_",
                                                       ".mount_", ".modules_", ".env_",
                                                       ".caps_", ".conntrack_", "execd"])]

        if sys_events:
            print(f"    系统目录事件 ({len(sys_events)} 条):")
            for l in sys_events[:60]:
                print(f"      {l}")
            if len(sys_events) > 60:
                print(f"      ... 还有 {len(sys_events)-60} 条")
        else:
            print("    系统目录: (无事件)")

        if tmp_events:
            print(f"    临时目录事件 ({len(tmp_events)} 条):")
            for l in tmp_events[:30]:
                print(f"      {l}")
        else:
            print("    临时目录: (无事件)")

        evidence["inotify_sys_events"] = len(sys_events)
        evidence["inotify_tmp_events"] = len(tmp_events)

        # ━━ 维度 3: 用户/权限 ━━
        sub("[D3] 用户与权限")
        if pre_auth.strip() == post_auth.strip():
            print("    PASS  /etc/passwd, shadow, sudoers, SSH, PAM 无变化")
        else:
            engine.add("CRITICAL", "用户/权限", "用户/权限配置被修改",
                      40, ["T1136.001", "T1098"],
                      f"Before hash: {hashlib.md5(pre_auth.encode()).hexdigest()}\n"
                      f"After hash: {hashlib.md5(post_auth.encode()).hexdigest()}")
            print("    !! FAIL  用户/权限配置已变更!")
            # 详细对比
            pre_lines = set(pre_auth.strip().splitlines())
            post_lines = set(post_auth.strip().splitlines())
            added = post_lines - pre_lines
            removed = pre_lines - post_lines
            if added:
                print(f"    新增行:")
                for l in list(added)[:10]:
                    print(f"      + {l}")
            if removed:
                print(f"    删除行:")
                for l in list(removed)[:10]:
                    print(f"      - {l}")

        # ━━ 维度 4: 持久化 ━━
        sub("[D4] 持久化 (cron/systemd/rc.local/init.d/at)")
        if pre_persist.strip() == post_persist.strip():
            print("    PASS  无新增")
        else:
            # 详细分析哪些持久化机制发生了变化
            def extract_section(content, marker):
                """从 persist 内容中提取特定 section"""
                lines = content.splitlines()
                in_section = False
                section_lines = []
                for line in lines:
                    if marker in line:
                        in_section = True
                        continue
                    if in_section:
                        if line.startswith('===') and marker not in line:
                            break
                        section_lines.append(line)
                return '\n'.join(section_lines)

            sections = ['CRONTAB', '/etc/crontab', 'cron.d', 'systemd system', 'rc.local', 'init.d', 'at queue', 'systemd timers']
            changes = []
            for sec in sections:
                pre_sec = extract_section(pre_persist, sec)
                post_sec = extract_section(post_persist, sec)
                if pre_sec.strip() != post_sec.strip():
                    changes.append(sec)

            # 当命令是合法安装器时，某些变化是正常的（如 pip 可能更新 systemd service）
            if engine.is_legitimate and changes:
                # 对于包管理器操作，systemd/pip 相关变化可能是正常的
                if all('systemd' in c or 'pip' in COMMAND.lower() for c in changes):
                    print(f"    ! 持久化配置变更 (可能是包管理器正常操作): {changes}")
                    engine.add("WARN", "持久化", f"持久化配置文件变化: {changes}",
                              10, ["T1053.003"])
                else:
                    engine.add("CRITICAL", "持久化", "持久化机制被修改 (cron/systemd/rc.local)",
                              35, ["T1053.003", "T1543.002", "T1037.004"])
                    print(f"    !! FAIL  持久化配置已变更! ({', '.join(changes)})")
            else:
                engine.add("CRITICAL", "持久化", "持久化机制被修改 (cron/systemd/rc.local)",
                          35, ["T1053.003", "T1543.002", "T1037.004"])
                print(f"    !! FAIL  持久化配置已变更! ({', '.join(changes) if changes else '未知'})")

        # ━━ 维度 5: Shell 环境 ━━
        sub("[D5] Shell 环境 (.bashrc/.profile/etc)")
        if pre_shell.strip() == post_shell.strip():
            print("    PASS  无变化")
        else:
            engine.add("WARN", "Shell环境", "Shell 配置文件被修改",
                      20, ["T1546.004"])
            print("    !! FAIL  Shell 配置被修改")
            # 显示变更后的 shell 配置
            c, _ = await run_cmd(sandbox,
                "diff <(echo '') <(cat ~/.bashrc ~/.bash_profile ~/.profile 2>/dev/null) 2>/dev/null "
                "| head -30 || cat ~/.bashrc 2>/dev/null | tail -10")
            for l in c.splitlines()[:15]:
                print(f"      {l}")

        # ━━ 维度 6: 残留进程 + 进程树分析 ━━
        sub("[D6] 进程树分析")
        # 分析执行期间产生的所有进程
        proc_lines = proc_tree_log.splitlines() if proc_tree_log else []
        # 从进程日志中提取独特的命令
        observed_cmds = set()
        for l in proc_lines:
            if l.startswith("=== ") or not l.strip():
                continue
            parts = l.split(None, 10)
            if len(parts) >= 11:
                cmd = parts[10]
                # 过滤监控自身
                if not any(x in cmd for x in ["inotifywait", ".net_poll", ".proc_tree",
                                                "sleep 0.5", "sleep 1", "ps aux"]):
                    observed_cmds.add(cmd[:120])

        if observed_cmds:
            print(f"    观察到 {len(observed_cmds)} 个独立进程:")
            for cmd in sorted(observed_cmds)[:20]:
                print(f"      > {cmd}")
        else:
            print("    (无额外进程)")

        # 残留进程检查
        print("\n    残留进程 (执行后):")
        residual = []
        for l in post_ps.splitlines():
            if any(x in l for x in ["inotifywait", ".net_poll", ".proc_tree",
                                      "sleep 0.5", "sleep 1"]):
                continue
            if l.strip():
                residual.append(l)
                print(f"      {l}")

        # ━━ 维度 7: 残留网络连接 ━━
        sub("[D7] 残留网络连接")
        net_lines = [l for l in post_net.splitlines() if l.strip()]
        if net_lines:
            for l in net_lines[:15]:
                print(f"      {l}")
        else:
            print("    (无)")

        # ━━ 维度 8: 资源消耗 ━━
        sub("[D8] 资源消耗")
        if pre_m and post_m:
            cpu_delta = post_m.cpu_used_percentage - pre_m.cpu_used_percentage
            mem_delta = post_m.memory_used_in_mib - pre_m.memory_used_in_mib
            print(f"    CPU    : {pre_m.cpu_used_percentage:.1f}% -> {post_m.cpu_used_percentage:.1f}% (Δ {cpu_delta:+.1f}%)")
            print(f"    Memory : {pre_m.memory_used_in_mib:.1f} -> {post_m.memory_used_in_mib:.1f} MiB (Δ {mem_delta:+.1f} MiB)")
            if post_m.cpu_used_percentage > 80:
                engine.add("WARN", "资源", f"CPU 异常高 ({post_m.cpu_used_percentage:.1f}%)",
                          15, [], f"CPU: {post_m.cpu_used_percentage:.1f}%")
            if mem_delta > 200:
                engine.add("WARN", "资源", f"内存异常增长 (+{mem_delta:.0f} MiB)",
                          10, [], f"Memory delta: {mem_delta:.0f} MiB")
        else:
            print("    (不可用)")

        # ━━ 维度 9: 可疑二进制 ━━
        sub("[D9] 可疑二进制 (/tmp /var/tmp /dev/shm)")
        sus, _ = await run_cmd(sandbox,
            "find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null "
            "| grep -vE '/[0-9a-f]{32}\\.(stdout|stderr)$' "
            "| grep -vE '/(\\.|execd)' "
            "|| echo none")
        sus_clean = sus.strip()
        if sus_clean and sus_clean != "none":
            sus_files = [f for f in sus_clean.splitlines() if f.strip()]
            if sus_files:
                engine.add("WARN", "可疑二进制", f"临时目录可执行文件: {sus_files}",
                          25, ["T1105"], sus_clean[:300])
                for f in sus_files[:10]:
                    print(f"    !! {f}")
                    # 获取文件元信息
                    meta, _ = await run_cmd(sandbox, f"file '{f}' 2>/dev/null; ls -la '{f}' 2>/dev/null", 5)
                    if meta.strip():
                        print(f"       {meta.strip()}")
            else:
                print("    PASS")
        else:
            print("    PASS")

        # ━━ 维度 10: SUID/SGID 变更 ━━
        sub("[D10] SUID/SGID 文件变更")
        new_suid = post_suid - pre_suid
        removed_suid = pre_suid - post_suid
        if new_suid:
            engine.add("CRITICAL", "SUID/SGID", f"新增 SUID/SGID 文件: {len(new_suid)}",
                      40, ["T1548.001"], "\n".join(list(new_suid)[:10]))
            print(f"    !! 新增 {len(new_suid)} 个 SUID/SGID 文件:")
            for f in list(new_suid)[:10]:
                print(f"      + {f}")
        else:
            print("    PASS  无新增 SUID/SGID 文件")
        if removed_suid:
            print(f"    [INFO] 移除 {len(removed_suid)} 个 SUID/SGID 文件")

        # ━━ 维度 11: 内核模块变更 ━━
        sub("[D11] 内核模块")
        if pre_modules.strip() == post_modules.strip():
            print("    PASS  无变化")
        else:
            engine.add("CRITICAL", "内核模块", "内核模块列表变更",
                      45, ["T1014"], post_modules[:200])
            print("    !! FAIL  内核模块列表已变更!")

        # ━━ 维度 12: 挂载点变更 ━━
        sub("[D12] 挂载点")
        if pre_mounts.strip() == post_mounts.strip():
            print("    PASS  无变化")
        else:
            engine.add("WARN", "挂载点", "挂载点配置变更",
                      20, ["T1611"], post_mounts[:200])
            print("    !! FAIL  挂载点已变更!")

        # ━━ 维度 13: 环境变量 (LD_PRELOAD 等) ━━
        sub("[D13] 安全相关环境变量")
        if pre_env.strip() == post_env.strip():
            print("    PASS  无变化")
        else:
            # 检查具体变更
            pre_env_set = set(pre_env.strip().splitlines())
            post_env_set = set(post_env.strip().splitlines())
            new_envs = post_env_set - pre_env_set
            for env_line in new_envs:
                if "LD_PRELOAD" in env_line:
                    engine.add("CRITICAL", "环境变量", f"LD_PRELOAD 被设置: {env_line}",
                              40, ["T1574.006"], env_line)
                elif "LD_LIBRARY_PATH" in env_line:
                    engine.add("WARN", "环境变量", f"LD_LIBRARY_PATH 变更: {env_line}",
                              15, ["T1574.001"], env_line)
                else:
                    print(f"    [INFO] 新增/变更: {env_line}")
            if not any("LD_PRELOAD" in e or "LD_LIBRARY_PATH" in e for e in new_envs):
                print("    PASS  无危险环境变量变更")

        # ━━ 维度 14: 文件内容模式分析 ━━
        sub("[D14] 关键文件内容分析")
        # 检查 .bashrc/.profile 等是否包含恶意内容
        shell_content, _ = await run_cmd(sandbox,
            "cat ~/.bashrc ~/.bash_profile ~/.profile /etc/profile "
            "/etc/bash.bashrc /etc/environment 2>/dev/null || true")

        content_hits = []
        for pattern, desc, mitre_id, score in MALICIOUS_CONTENT_PATTERNS:
            if re.search(pattern, shell_content, re.IGNORECASE):
                content_hits.append((desc, mitre_id, score))
                # 只有在快照对比发现变更时才加分 (避免与基线内容冲突)
                if pre_shell.strip() != post_shell.strip():
                    engine.add("CRITICAL", "内容分析", f"Shell 配置含恶意内容: {desc}",
                              score, [mitre_id], desc)
                    print(f"    !! [{mitre_id}] {desc}")

        # 检查新增文件的内容
        new_file_content_checked = 0
        for path in new_paths[:30]:  # 检查前 30 个新增文件
            if any(path.endswith(ext) for ext in ['.sh', '.py', '.pl', '.rb', '.php', '.service',
                                                    '.conf', '.cfg', '.txt', '.log']):
                fc, _ = await run_cmd(sandbox, f"head -50 '{path}' 2>/dev/null || true", 5)
                if fc.strip():
                    new_file_content_checked += 1
                    for pattern, desc, mitre_id, score in MALICIOUS_CONTENT_PATTERNS:
                        if re.search(pattern, fc, re.IGNORECASE):
                            engine.add("CRITICAL", "内容分析",
                                      f"新文件 {path} 含恶意内容: {desc}",
                                      score, [mitre_id], fc[:200])
                            print(f"    !! [{mitre_id}] {path}: {desc}")

        if not content_hits and new_file_content_checked == 0:
            print("    PASS  未发现恶意内容模式")
        elif not content_hits:
            print(f"    PASS  已检查 {new_file_content_checked} 个新增文件, 未发现恶意内容")

        # ━━ 维度 15: 关键二进制完整性 ━━
        sub("[D15] 关键系统二进制完整性")
        if pre_bins.strip() == post_bins.strip():
            print("    PASS  /bin/bash, su, sudo, passwd, sshd 等均未被篡改")
        else:
            engine.add("CRITICAL", "二进制完整性", "关键系统二进制被篡改",
                      45, ["T1554"],
                      f"Before:\n{pre_bins[:200]}\nAfter:\n{post_bins[:200]}")
            print("    !! FAIL  关键系统二进制文件 hash 变更!")
            pre_bin_set = set(pre_bins.strip().splitlines())
            post_bin_set = set(post_bins.strip().splitlines())
            for line in (post_bin_set - pre_bin_set):
                print(f"      !! 变更: {line}")
            for line in (pre_bin_set - post_bin_set):
                print(f"      <- 原始: {line}")

        # ━━ 维度 16: 新增符号链接检测 ━━
        sub("[D16] 符号链接变更")
        new_symlinks = post_symlinks - pre_symlinks
        if new_symlinks:
            # 检查新链接是否指向敏感文件
            dangerous_links = [l for l in new_symlinks
                              if any(s in l for s in ["/etc/shadow", "/etc/passwd",
                                                       "/proc/", "/dev/null",
                                                       "authorized_keys", ".bash_history"])]
            if dangerous_links:
                engine.add("WARN", "符号链接", f"新增指向敏感目标的符号链接",
                          20, ["T1036"], "\n".join(list(dangerous_links)[:5]))
                for l in dangerous_links[:5]:
                    print(f"    !! {l}")
            else:
                print(f"    [INFO] 新增 {len(new_symlinks)} 个符号链接 (非敏感目标)")
                for l in list(new_symlinks)[:5]:
                    print(f"      + {l}")
        else:
            print("    PASS  无新增符号链接")

        # ━━ 维度 17: 文件能力 (getcap) 变更 ━━
        sub("[D17] 文件能力 (Linux Capabilities)")
        new_caps = post_file_caps - pre_file_caps
        if new_caps:
            engine.add("CRITICAL", "文件能力", f"新增文件能力: {len(new_caps)}",
                      35, ["T1548.001"], "\n".join(list(new_caps)[:10]))
            print(f"    !! 新增 {len(new_caps)} 个文件能力:")
            for c in list(new_caps)[:10]:
                print(f"      + {c}")
        else:
            print("    PASS  无新增文件能力")

        # ━━ 维度 18: 输出内容分析 (stdout/stderr 侦察检测) ━━
        sub("[D18] 输出内容分析")
        output_text = stdout + "\n" + stderr
        output_suspicious = []
        # 检测输出中的侦察结果
        output_patterns = [
            (r"root:.*:0:0:", "passwd file contents in output", "T1048", 15),
            (r"\$[0-9]+\$[A-Za-z0-9./]+\$", "password hash in output", "T1048", 30),
            (r"ssh-rsa\s+AAAA", "SSH public key in output", "T1082", 10),
            (r"BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY", "private key in output!", "T1048", 40),
        ]
        for pattern, desc, mitre_id, score in output_patterns:
            if re.search(pattern, output_text, re.IGNORECASE):
                output_suspicious.append(desc)
                engine.add("WARN", "输出分析", desc, score, [mitre_id])
                print(f"    !! {desc}")
        if not output_suspicious:
            print("    PASS  输出内容无敏感信息泄露")

        # ━━ 维度 19: 新增文件熵分析 (高熵 = 加密/压缩载荷) ━━
        sub("[D19] 新增文件熵分析")
        high_entropy_files = []
        # 检查 /tmp 等目录新增的非文本文件
        for path in new_paths[:20]:
            if any(path.startswith(d) for d in ["/tmp/", "/var/tmp/", "/dev/shm/"]):
                # 读取文件头部字节计算熵
                fc, _ = await run_cmd(sandbox,
                    f"head -c 1024 '{path}' 2>/dev/null | base64", 5)
                if fc.strip():
                    try:
                        import base64
                        raw = base64.b64decode(fc.strip())
                        ent = calculate_entropy(raw)
                        if ent > ENTROPY_THRESHOLD:  # 高熵阈值 (可在 scoring.conf 配置)
                            high_entropy_files.append((path, ent))
                    except Exception:
                        pass

        if high_entropy_files:
            engine.add("WARN", "熵分析",
                      f"高熵文件 (可能为加密/压缩载荷): {[f[0] for f in high_entropy_files]}",
                      20, ["T1027"], str(high_entropy_files))
            for path, ent in high_entropy_files:
                print(f"    !! {path} (entropy: {ent}/8.0)")
        else:
            print("    PASS  无异常高熵文件")

        evidence["exit_code"] = exit_code
        evidence["critical_bins_changed"] = pre_bins.strip() != post_bins.strip()
        evidence["new_symlinks"] = len(new_symlinks) if new_symlinks else 0
        evidence["new_file_caps"] = len(new_caps) if new_caps else 0

        # ━━ 维度 20: 计划任务详细差异 ━━
        sub("[D20] 计划任务详细差异")
        # 使用 pre_persist 和 post_persist 的差值来检测真正的变化
        if pre_persist.strip() != post_persist.strip():
            print("    !! 计划任务发生变化")
            # 解析 cron.d 内容(从 persist 快照中提取)
            def extract_cron_d(content):
                """从 persist 快照中提取 cron.d 部分的内容"""
                lines = content.splitlines()
                in_cron_d = False
                cron_d_content = []
                for line in lines:
                    if '=== cron.d ===' in line:
                        in_cron_d = True
                        continue
                    if in_cron_d:
                        if line.startswith('===') and 'cron.d' not in line:
                            break
                        cron_d_content.append(line)
                return '\n'.join(cron_d_content)

            pre_cron_d = extract_cron_d(pre_persist)
            post_cron_d = extract_cron_d(post_persist)

            # 检测 cron.d 的变化(新增或修改)
            if post_cron_d.strip() != pre_cron_d.strip():
                # 只分析"新增"的内容(执行后才出现的)
                cron_d_diff = post_cron_d.replace(pre_cron_d, '').strip()
                if cron_d_diff:
                    # 扫描 cron.d 新增内容中的恶意模式
                    cron_malicious_patterns = [
                        (r"curl\s+.*\|.*bash", "cron.d with curl|bash payload", "T1053.003", 35),
                        (r"wget\s+.*\|.*bash", "cron.d with wget|bash payload", "T1053.003", 35),
                        (r"(curl|wget).*http.*\|", "cron.d with download and pipe", "T1053.003", 30),
                        (r"bash\s+-i\s+>&\s+/dev/tcp/", "cron.d with reverse shell", "T1059.004", 45),
                        (r"nc\s+.*\-e\s+/bin/(ba)?sh", "cron.d with netcat backdoor", "T1059.004", 45),
                        (r"python[23]?\s+-c.*socket", "cron.d with python socket", "T1059.004", 35),
                        (r"exec\s+\d+<>/dev/tcp/", "cron.d with bash tcp redirect", "T1059.004", 45),
                        (r"(rm|del)\s+.*\-rf", "cron.d with destructive command", "T1485", 25),
                        (r"mkfifo.*nc.*sh", "cron.d with named pipe shell", "T1059.004", 40),
                        (r"base64\s+.*\|.*(bash|sh)", "cron.d with base64 encoded payload", "T1027", 35),
                    ]
                    malicious_found = False
                    for pattern, desc, mitre_id, score in cron_malicious_patterns:
                        if re.search(pattern, cron_d_diff, re.IGNORECASE):
                            engine.add("CRITICAL", "计划任务差异",
                                      f"cron.d 新增恶意内容: {desc}", score, [mitre_id],
                                      cron_d_diff[:200])
                            print(f"    !! cron.d 新增恶意内容: {desc}")
                            malicious_found = True
                    if not malicious_found:
                        # cron.d 有变化但没有恶意模式,给予较低分数
                        engine.add("WARN", "计划任务差异",
                                  "cron.d 文件发生变化", 10, ["T1053.003"],
                                  cron_d_diff[:200])
                        print(f"    ! cron.d 文件发生变化(无恶意内容)")
            else:
                print("    PASS  cron.d 无变化")
        else:
            print("    PASS  计划任务无变化")

        # ━━ 维度 21: 隐藏进程检测 ━━
        sub("[D21] 隐藏进程检测")
        proc_pids, _ = await run_cmd(sandbox,
            "ls -d /proc/[0-9]* 2>/dev/null | sed 's|/proc/||' | sort -n", 10)
        ps_pids, _ = await run_cmd(sandbox,
            "ps -eo pid --no-headers 2>/dev/null | tr -d ' ' | sort -n", 10)
        proc_set = set(proc_pids.strip().splitlines()) if proc_pids.strip() else set()
        ps_set = set(ps_pids.strip().splitlines()) if ps_pids.strip() else set()
        hidden_pids = proc_set - ps_set
        # Filter out kernel threads and self
        hidden_pids = {p for p in hidden_pids if p.strip() and p.strip().isdigit()}
        if len(hidden_pids) > HIDDEN_PROC_TOLERANCE:  # 容差可在 scoring.conf 配置
            engine.add("WARN", "隐藏进程",
                      f"检测到 {len(hidden_pids)} 个 /proc 中存在但 ps 不可见的进程",
                      20, ["T1564.001"], str(sorted(hidden_pids)[:20]))
            print(f"    !! {len(hidden_pids)} 个潜在隐藏进程")
        else:
            print("    PASS  未发现隐藏进程")

        # ━━ 维度 22: 信号处理与 trap 分析 ━━
        sub("[D22] 信号处理 / trap 分析")
        # 检查命令中是否包含 trap 劫持
        trap_patterns = [
            (r"trap\s+['\"].*['\"].*EXIT", "trap on EXIT signal", 15),
            (r"trap\s+['\"].*['\"].*INT", "trap on INT signal (Ctrl+C evasion)", 20),
            (r"trap\s+['\"].*['\"].*TERM", "trap on TERM signal (kill evasion)", 25),
            (r"trap\s+['\"].*['\"].*HUP", "trap on HUP signal (persistence)", 15),
            (r"trap\s+''", "ignoring signals (anti-kill)", 25),
        ]
        trap_found = False
        combined_text = COMMAND + "\n" + stdout + "\n" + stderr
        for pattern, desc, score in trap_patterns:
            if re.search(pattern, combined_text, re.IGNORECASE):
                trap_found = True
                engine.add("WARN", "信号处理", desc, score, ["T1059.004"], desc)
                print(f"    !! {desc}")
        if not trap_found:
            print("    PASS  未发现恶意信号处理")

        # ━━ 维度 23: 攻击链关联分析 ━━
        sub("[D23] 攻击链关联分析")
        # 分析多个维度发现之间的关联, 识别组合攻击
        attack_chains = []
        finding_dims = set(f.dimension for f in engine.findings)

        # 链 1: 下载 + 执行 + 持久化 = 典型恶意软件部署
        if ("文件变更" in finding_dims or "可疑二进制" in finding_dims) and \
           "持久化" in finding_dims:
            attack_chains.append("恶意软件部署链 (文件落地 + 持久化)")
            engine.add("CRITICAL", "攻击链", "检测到恶意软件部署链: 文件落地 + 持久化",
                      15, ["T1105", "T1053.003"])

        # 链 2: 用户创建/权限变更 + SSH key = 后门账户
        if "用户/权限" in finding_dims and any("authorized_keys" in f.description
                                              for f in engine.findings):
            attack_chains.append("后门账户链 (用户变更 + SSH key 注入)")
            engine.add("CRITICAL", "攻击链", "检测到后门账户链: 用户变更 + SSH key 注入",
                      15, ["T1098", "T1021.004"])

        # 链 3: 反取证 + 恶意行为 = 高级攻击
        anti_forensics_dims = {"静态分析"}
        anti_forensics_keywords = {"history", "HISTFILE", "反取证", "anti-forensics"}
        has_anti_forensics = any(
            any(kw in f.description.lower() for kw in anti_forensics_keywords)
            for f in engine.findings
        )
        if has_anti_forensics and len(engine.findings) > 2:
            attack_chains.append("高级攻击链 (反取证 + 多维度恶意行为)")
            engine.add("WARN", "攻击链", "检测到反取证措施配合其他恶意行为",
                      10, ["T1070.003"])

        # 链 4: DNS 变更 + 网络连接 = C2 通信
        if "DNS" in finding_dims and external:
            attack_chains.append("C2 通信链 (DNS 劫持 + 外部连接)")
            engine.add("CRITICAL", "攻击链", "检测到 C2 通信链: DNS 劫持 + 外部网络连接",
                      20, ["T1071.004", "T1016"])

        # 链 5: LD_PRELOAD + 关键二进制修改 = Rootkit
        if "环境变量" in finding_dims and "二进制完整性" in finding_dims:
            attack_chains.append("Rootkit 链 (LD_PRELOAD + 二进制篡改)")
            engine.add("CRITICAL", "攻击链", "检测到 Rootkit 链: LD_PRELOAD + 二进制篡改",
                      20, ["T1014", "T1574.006"])

        if attack_chains:
            for chain in attack_chains:
                print(f"    !! 攻击链: {chain}")
            evidence["attack_chains"] = attack_chains
        else:
            print("    PASS  未检测到攻击链组合")

        # ━━ 维度 24: 文件权限变更追踪 ━━
        sub("[D24] 敏感文件权限变更")
        perm_check, _ = await run_cmd(sandbox,
            "stat -c '%a %n' /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config "
            "/etc/crontab /usr/bin/sudo /bin/su /usr/bin/passwd 2>/dev/null | sort || true", 10)
        perm_changes = []
        # 检查常见危险权限
        for line in perm_check.splitlines():
            parts = line.strip().split(" ", 1)
            if len(parts) == 2:
                perm, path = parts
                # shadow 应该是 640 或更严格
                if "shadow" in path and int(perm, 8) > 0o640:
                    perm_changes.append(f"{path} 权限过宽: {perm}")
                # sudoers 应该是 440
                if "sudoers" in path and perm != "440":
                    perm_changes.append(f"{path} 权限异常: {perm} (应为 440)")
                # passwd 可读但不应可写
                if "passwd" in path and int(perm, 8) & 0o022:
                    perm_changes.append(f"{path} 全局可写: {perm}")

        # 检查新增文件中的 world-writable
        world_writable, _ = await run_cmd(sandbox,
            "find /etc /usr/local/bin -xdev -perm -o+w -type f 2>/dev/null | head -20 || true", 10)
        if world_writable.strip():
            for ww in world_writable.strip().splitlines()[:10]:
                perm_changes.append(f"全局可写文件: {ww}")

        if perm_changes:
            engine.add("WARN", "文件权限", f"发现 {len(perm_changes)} 个权限异常",
                      15, ["T1222.002"], "\n".join(perm_changes[:10]))
            for pc in perm_changes[:10]:
                print(f"    !! {pc}")
        else:
            print("    PASS  敏感文件权限正常")

        evidence["permission_issues"] = perm_changes[:20] if perm_changes else []

        # ── 8/9 MITRE ATT&CK 映射 ──
        section("8/9  MITRE ATT&CK 技术映射")
        mitre_map = engine.mitre_summary()
        if mitre_map:
            for tid, info_data in sorted(mitre_map.items()):
                print(f"    [{tid}] {info_data['name']}")
                for f_desc in info_data["findings"][:3]:
                    print(f"      └─ {f_desc}")
        else:
            print("    未映射到任何 ATT&CK 技术")

        evidence["mitre_techniques"] = list(mitre_map.keys())

        # ── 9/9 综合判定 ──
        section("9/9  综合判定")
        verdict = engine.verdict()
        score = engine.total_score()
        confidence = engine.confidence()
        criticals = [f for f in engine.findings if f.severity == "CRITICAL"]
        warns = [f for f in engine.findings if f.severity == "WARN"]
        infos = [f for f in engine.findings if f.severity == "INFO"]
        tactic_map = engine.tactic_summary()

        sym_map = {"DANGEROUS": "!!", "SUSPICIOUS": "??", "LOW_RISK": "~~", "LIKELY_SAFE": "OK"}
        sym = sym_map.get(verdict, "??")

        # 评分条
        bar_len = 40
        filled = int(score / 100 * bar_len)
        bar = "█" * filled + "░" * (bar_len - filled)

        print(f"""
  +{'─'*(W-2)}+
  |  [{sym}] 判定: {verdict:20s}  风险评分: {score:3d}/100            |
  |  [{bar}]                              |
  |  置信度: {confidence:6s}  维度覆盖: {len(set(f.dimension for f in engine.findings)):2d}/24              |
  +{'─'*(W-2)}+
""")
        print(f"  命令           : {COMMAND}")
        print(f"  合法命令模式   : {'是' if engine.is_legitimate else '否'}")
        print(f"  退出码         : {exit_code}")
        print(f"  文件 +/-       : +{len(new_paths)} / -{len(del_paths)}")
        print(f"  inotify 事件   : {len(sys_events)} 系统 + {len(tmp_events)} 临时")
        print(f"  外部连接       : {len(external)} 个")
        print(f"  SUID/SGID 变更 : +{len(new_suid)}")
        print(f"  二进制完整性   : {'FAIL' if pre_bins.strip() != post_bins.strip() else 'PASS'}")
        print(f"  新增符号链接   : {len(new_symlinks) if new_symlinks else 0}")
        print(f"  新增文件能力   : {len(new_caps) if new_caps else 0}")
        print(f"  执行耗时       : {dur:.1f}s")
        print(f"  MITRE 技术     : {len(mitre_map)} 个")
        print(f"  ATT&CK 战术    : {', '.join(sorted(tactic_map.keys())) if tactic_map else '无'}")
        print(f"  发现           : {len(criticals)} critical, {len(warns)} warnings, {len(infos)} info")
        print(f"  置信度         : {confidence}")
        print()

        if engine.findings:
            print("  详细发现 (按严重程度排序):")
            for f in sorted(engine.findings, key=lambda x: {"CRITICAL": 0, "WARN": 1, "INFO": 2}[x.severity]):
                color = {"CRITICAL": "!!!", "WARN": " ! ", "INFO": " i "}[f.severity]
                mitre_str = f" [{','.join(f.mitre_ids)}]" if f.mitre_ids else ""
                print(f"    [{color}] [{f.dimension}] {f.description}{mitre_str} (score: {f.score})")
        else:
            print("  全部 24 维度检查通过:")
            checks = [
                "无敏感路径写入",
                "用户/权限未被修改",
                "无持久化后门 (cron/systemd/rc.local)",
                "Shell 环境未被篡改",
                "DNS 配置未被修改",
                "无可疑残留进程",
                "临时目录无可执行文件",
                "无新增 SUID/SGID 文件",
                "内核模块未变化",
                "挂载点未变化",
                "无 LD_PRELOAD 注入",
                "未发现恶意内容模式",
                "关键二进制完整性通过",
                "无危险符号链接",
                "无新增文件能力",
                "输出无敏感信息泄露",
                "无异常高熵文件",
                "计划任务无变化",
                "未发现隐藏进程",
                "无恶意信号处理",
                "未检测到攻击链",
                "敏感文件权限正常",
                f"外部连接 {len(external)} 个",
                f"MITRE ATT&CK 映射 0 个技术",
            ]
            for c in checks:
                print(f"    [PASS] {c}")

        # ── 安全建议 ──
        recommendations = generate_recommendations(verdict, engine.findings, confidence)
        print("\n  安全建议:")
        for rec in recommendations:
            print(f"    -> {rec}")

        # ── 执行时间线 ──
        timeline = [
            {"phase": "baseline", "time": f"{t0:.0f}", "desc": "基线采集完成"},
            {"phase": "probes_start", "time": f"{t1:.0f}", "desc": "探针启动 + 命令执行开始"},
            {"phase": "exec_end", "time": f"{t1+dur:.0f}", "desc": f"命令执行结束 (耗时 {dur:.1f}s, 退出码 {exit_code})"},
            {"phase": "post_snapshot", "time": f"{time.time():.0f}", "desc": "后置快照 + 分析完成"},
        ]

        # ── 生成报告 ──
        report = {
            "version": "4.1",
            "command": COMMAND,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "verdict": verdict,
            "risk_score": score,
            "confidence": confidence,
            "recommendations": recommendations,
            "is_legitimate_pattern": engine.is_legitimate,
            "findings_summary": {
                "total": len(engine.findings),
                "critical": len(criticals),
                "warn": len(warns),
                "info": len(infos),
                "dimensions_hit": len(set(f.dimension for f in engine.findings)),
            },
            "findings": [f.to_dict() for f in engine.findings],
            "evidence": evidence,
            "dimensions": {
                "files_added": new_paths[:300],
                "files_deleted": del_paths[:50],
                "inotify_sys_events": sys_events[:300],
                "inotify_tmp_events": tmp_events[:100],
                "external_connections": [f"{ip}:{p}" for ip, p in sorted(external)],
                "suid_new": list(new_suid)[:50],
                "suid_removed": list(removed_suid)[:50],
                "new_symlinks": list(new_symlinks)[:50] if new_symlinks else [],
                "new_file_caps": list(new_caps)[:50] if new_caps else [],
                "critical_bins_tampered": pre_bins.strip() != post_bins.strip(),
                "high_entropy_files": [(p, e) for p, e in high_entropy_files] if high_entropy_files else [],
                "exit_code": exit_code,
                "attack_chains": evidence.get("attack_chains", []),
            },
            "mitre_attack": {
                tid: {"name": info_data["name"], "findings": info_data["findings"]}
                for tid, info_data in mitre_map.items()
            },
            "mitre_tactics": {
                tactic: sorted(set(tids))
                for tactic, tids in tactic_map.items()
            },
            "deobfuscation": {
                "original": COMMAND,
                "deobfuscated": deobfuscated if deobfuscated != COMMAND else None,
                "layers": [{"type": t, "decoded": d[:200]} for t, _, d in deob_layers] if deob_layers else [],
            },
            "timeline": timeline,
            "stdout": stdout_lines[:100],
            "stderr": stderr_lines[:50],
        }
        # 生成人类可读摘要并加入报告
        text_summary = generate_text_summary(report)
        report["text_summary"] = text_summary

        # 加入快速预判结果 (对比沙箱深度分析 vs 静态预判)
        triage = fast_triage(COMMAND)
        report["fast_triage"] = triage

        report_file = os.path.join(REPORT_DIR, f"safety_report_{int(time.time())}.json")
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

        # 同时保存纯文本摘要
        txt_file = report_file.replace(".json", ".txt")
        with open(txt_file, "w") as f:
            f.write(text_summary)

        # 保存 SARIF 格式报告 (CI/CD 集成)
        sarif_file = report_file.replace(".json", ".sarif.json")
        sarif_report = generate_sarif(report)
        with open(sarif_file, "w") as f:
            json.dump(sarif_report, f, indent=2, ensure_ascii=False, default=str)

        print(f"\n  报告 (JSON) : {report_file}")
        print(f"  报告 (文本) : {txt_file}")
        print(f"  报告 (SARIF): {sarif_file}")
        print(f"\n  快速预判: {triage['level']} (静态分: {triage['static_score']}, "
              f"模式匹配: {triage['patterns_matched']})")
        if triage['level'] != "PASS" and verdict in ("LIKELY_SAFE", "LOW_RISK"):
            print(f"  [INFO] 快速预判与深度分析不一致 — 静态分析可能过于敏感")
        elif triage['level'] == "PASS" and verdict in ("DANGEROUS", "SUSPICIOUS"):
            print(f"  [WARN] 快速预判未能识别 — 此攻击需要沙箱动态分析才能发现")

        print(f"\n{'='*W}")
        print("  人类可读摘要:")
        print(f"{'='*W}")
        for line in text_summary.splitlines():
            print(f"  {line}")
        print()

        await sandbox.kill()
        print("  沙箱已销毁。\n")

if __name__ == "__main__":
    # 支持快速预判模式 (不启动沙箱)
    if os.environ.get("FAST_TRIAGE") == "1":
        result = fast_triage(COMMAND)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        asyncio.run(main())
PYTHON_SCRIPT

# 支持base64编码的命令传递
if [ -n "${COMMAND_B64:-}" ]; then
    export COMMAND_B64
    export CHECK_COMMAND=""
else
    export CHECK_COMMAND="$COMMAND"
fi
export SANDBOX_IMAGE REPORT_DIR

# 支持快速预判模式 (跳过沙箱, 纯静态分析)
if [ "${FAST_TRIAGE:-0}" = "1" ]; then
    info "快速预判模式 (不启动沙箱)"
    FAST_TRIAGE=1 python3 "${WORK_DIR}/checker.py"
    exit $?
fi

python3 "${WORK_DIR}/checker.py"

# ── Step 7: 完成 ──
echo ""
info "[Step 7/7] 完成!"
REPORT=$(ls -t "${REPORT_DIR}"/safety_report_*.json 2>/dev/null | head -1)
if [ -n "$REPORT" ]; then
    ok "报告 (JSON): ${REPORT}"
    TXT_REPORT="${REPORT%.json}.txt"
    [ -f "$TXT_REPORT" ] && ok "报告 (文本): ${TXT_REPORT}"
    echo "  查看: python3 -m json.tool ${REPORT}"
    echo "  快速预判: FAST_TRIAGE=1 COMMAND='...' ./checker.sh"
    echo ""
fi
