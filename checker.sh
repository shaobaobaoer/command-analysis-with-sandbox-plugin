#!/usr/bin/env bash
# ============================================================================
#  OpenSandbox Behavioral Analysis Engine — v5 (Python Refactored)
#
#  核心: 通过执行前/后快照对比发现行为差异
#        任何单独的"执行后状态"必须与基线对比才有意义
#
#  用法:
#    COMMAND="some command" ./checker.sh
#
#  环境变量:
#    COMMAND        — 待检测命令
#    COMMAND_B64    — base64 编码的命令（多行命令使用）
#    SANDBOX_PORT   — 服务端口 (默认: 8080)
#    SANDBOX_IMAGE  — 沙箱镜像
#    EXECD_IMAGE    — execd 镜像
#    REGISTRY_MIRROR — 镜像仓库前缀（国内加速）
#    REPORT_DIR     — 报告输出目录
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

# ── 镜像配置 ──────────────────────────────────────────────────────────────
REGISTRY_MIRROR="${REGISTRY_MIRROR:-}"
if [ -n "$REGISTRY_MIRROR" ]; then
    DEFAULT_SANDBOX_IMAGE="${REGISTRY_MIRROR}/code-interpreter:v1.0.2"
    DEFAULT_EXECD_IMAGE="${REGISTRY_MIRROR}/execd:v1.0.7"
else
    DEFAULT_SANDBOX_IMAGE="opensandbox/code-interpreter:v1.0.2"
    DEFAULT_EXECD_IMAGE="opensandbox/execd:v1.0.7"
fi

# ── 命令解析（支持 base64 编码）────────────────────────────────────────────
if [ -n "${COMMAND_B64:-}" ]; then
    COMMAND=$(echo "$COMMAND_B64" | base64 -d)
else
    COMMAND="${COMMAND:-curl -fsSL https://claude.ai/install.sh | bash}"
fi
SANDBOX_PORT="${SANDBOX_PORT:-8080}"
SANDBOX_IMAGE="${SANDBOX_IMAGE:-$DEFAULT_SANDBOX_IMAGE}"
EXECD_IMAGE="${EXECD_IMAGE:-$DEFAULT_EXECD_IMAGE}"
REPORT_DIR="${REPORT_DIR:-$(pwd)}"

WORK_DIR="$(mktemp -d)"
VENV_DIR="${WORK_DIR}/.venv"
CONFIG_FILE="${WORK_DIR}/sandbox.toml"
SERVER_PID=""

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

echo ""
echo -e "${BOLD}========================================================"
echo "  OpenSandbox Behavioral Analysis Engine v5"
echo "  核心: Before/After 快照对比 = 命令真实行为"
echo -e "========================================================${NC}"
echo ""
info "待检测命令: ${COMMAND}"
echo ""

# ── Step 1: 环境检查 ──────────────────────────────────────────────────────
info "[Step 1/6] 检查环境..."
command -v docker &>/dev/null || fail "Docker 未安装"
# Docker 需要 sudo
if ! sudo docker info &>/dev/null 2>&1; then
    fail "Docker daemon 未运行或无权限 (需要 sudo)"
fi
ok "Docker: $(docker --version | head -1)"
command -v python3 &>/dev/null || fail "Python3 未安装"
ok "Python: $(python3 --version)"

# 安装 uv（快速 Python 包管理器）
if ! command -v uv &>/dev/null; then
    info "安装 uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
    command -v uv &>/dev/null || fail "uv 安装失败"
fi
ok "uv: $(uv --version)"

# ── Step 2: 预拉取 Docker 镜像 ────────────────────────────────────────────
info "[Step 2/6] 预拉取 Docker 镜像..."
pull_image() {
    local image="$1" label="$2"
    if sudo docker image inspect "$image" &>/dev/null; then
        ok "${label}: ${image} (已存在)"
    else
        info "${label}: 拉取 ${image} ..."
        sudo docker pull "$image" || fail "${label}: 拉取失败. 国内试: REGISTRY_MIRROR=... ./checker.sh"
        ok "${label}: 完成"
    fi
}
pull_image "$SANDBOX_IMAGE" "沙箱镜像"
pull_image "$EXECD_IMAGE"   "Execd镜像"

# ── Step 3: 安装 Python 依赖（使用 uv 加速）─────────────────────────────
info "[Step 3/6] 安装 Python 依赖 (uv)..."
cd "$WORK_DIR"
uv venv "$VENV_DIR" --python python3 -q
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
# 并发安装 opensandbox-server 和 opensandbox SDK
uv pip install -q opensandbox-server opensandbox 2>&1 | tail -3
ok "opensandbox-server + SDK 已安装"

# ── Step 4: 服务端配置 ────────────────────────────────────────────────────
info "[Step 4/6] 生成服务端配置..."
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

# ── Step 5: 启动服务端 ────────────────────────────────────────────────────
info "[Step 5/6] 启动 OpenSandbox Server..."
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

# ── Step 6: 运行 Python 分析引擎 ──────────────────────────────────────────
info "[Step 6/6] 运行分析引擎..."
echo ""

# 导出环境变量给 checker.py
if [ -n "${COMMAND_B64:-}" ]; then
    export COMMAND_B64
    export CHECK_COMMAND=""
else
    export CHECK_COMMAND="$COMMAND"
fi
export SANDBOX_PORT SANDBOX_IMAGE REPORT_DIR

python3 "${SCRIPT_DIR}/checker.py"

# ── 完成 ──────────────────────────────────────────────────────────────────
echo ""
REPORT=$(ls -t "${REPORT_DIR}"/safety_report_*.json 2>/dev/null | grep -v sarif | head -1 || true)
if [ -n "$REPORT" ] && [ -f "$REPORT" ]; then
    ok "报告 (JSON): ${REPORT}"
    TXT_REPORT="${REPORT%.json}.txt"
    [ -f "$TXT_REPORT" ] && ok "报告 (文本): ${TXT_REPORT}"
fi
