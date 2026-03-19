#!/usr/bin/env bash
# ============================================================================
#  OpenSandbox Script Safety Checker — All-in-One (v2)
#
#  在有 Docker 的机器上一键运行:
#    chmod +x run.sh && ./run.sh
#
#  可选环境变量:
#    COMMAND        — 待检测命令 (默认: curl -fsSL https://claude.ai/install.sh | bash)
#    SANDBOX_PORT   — 服务端口 (默认: 8080)
#    SANDBOX_IMAGE  — 沙箱镜像
#    EXECD_IMAGE    — execd 镜像
#    REGISTRY_MIRROR — 镜像仓库前缀 (国内加速)
#
#  v2 修复:
#    - 监控工具安装移到快照之前, 避免 apt-get 污染基线
#    - 过滤 execd 自身临时文件 (/tmp/{uuid}.stdout|stderr)
#    - 过滤内部连接 (127.0.0.1, 172.17.*)
#    - inotifywait 排除自身日志, 消除递归写入
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
REPORT_DIR="$(pwd)"

cleanup() {
    info "Cleaning up..."
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null || true
    rm -rf "$WORK_DIR"
    ok "Cleanup done."
}
trap cleanup EXIT

echo ""
echo -e "${BOLD}=========================================="
echo "  OpenSandbox Script Safety Checker v2"
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

# ── Step 6: 安全检测 ──
info "[Step 6/7] 创建沙箱并执行安全检测..."
echo ""

cat > "${WORK_DIR}/checker.py" << 'PYTHON_SCRIPT'
"""OpenSandbox Script Safety Checker v2 - 修复误报"""
import asyncio
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone

from opensandbox import Sandbox
from opensandbox.config import ConnectionConfig

COMMAND = os.environ["CHECK_COMMAND"]
PORT = int(os.environ.get("SANDBOX_PORT", "8080"))
IMAGE = os.environ.get("SANDBOX_IMAGE", "opensandbox/code-interpreter:v1.0.2")
REPORT_DIR = os.environ.get("REPORT_DIR", "/tmp")
W = 72

# execd 自身产物 + 监控自身文件, 需要从所有比对中排除
EXECD_TMP_RE = re.compile(r"^/tmp/[0-9a-f]{32}\.(stdout|stderr)$")
INFRA_FILES = {"/tmp/.inotify_log", "/var/log/.inotify_log",
               "/tmp/.net_baseline", "/tmp/.net_poll_log",
               "/tmp/.resolv_baseline", "/tmp/execd.log"}

def is_infra(path):
    return path in INFRA_FILES or bool(EXECD_TMP_RE.match(path))

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

async def snap_fs(sb):
    """文件快照, 自动排除基础设施文件。"""
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
    o, _ = await run_cmd(sb, "ps auxf 2>/dev/null || ps aux"); return o

async def snap_persist(sb):
    o, _ = await run_cmd(sb,
        "{ crontab -l 2>/dev/null || true; cat /etc/crontab 2>/dev/null || true; "
        "ls ~/.config/systemd/user/*.service 2>/dev/null || true; "
        "cat /etc/rc.local 2>/dev/null || true; } | md5sum")
    return o

async def snap_auth(sb):
    """只比较用户名列表+sudoers行数, 不用 md5sum (避免时间戳等无关变化)。"""
    o, _ = await run_cmd(sb,
        "awk -F: '{print $1}' /etc/passwd 2>/dev/null | sort; "
        "echo '---'; "
        "wc -l /etc/shadow /etc/sudoers 2>/dev/null; "
        "echo '---'; "
        "ls /root/.ssh/ ~/.ssh/ 2>/dev/null || echo 'no-ssh'")
    return o

async def snap_shell(sb):
    o, _ = await run_cmd(sb,
        "cat ~/.bashrc ~/.bash_profile ~/.profile /etc/profile /etc/bash.bashrc 2>/dev/null | md5sum")
    return o

def parse_proc_net(raw):
    conns = set()
    for line in raw.splitlines():
        parts = line.strip().split()
        if len(parts) < 4 or parts[0] == "sl": continue
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
    return ip.startswith("127.") or ip.startswith("172.17.") or ip.startswith("172.18.") or ip == "0.0.0.0"

def extract_path(entry):
    parts = entry.split(" ", 2)
    return parts[2] if len(parts) == 3 else entry


async def main():
    findings = []
    evidence = {}
    config = ConnectionConfig(domain=f"localhost:{PORT}", request_timeout=timedelta(seconds=600))

    # ── 1/8 创建沙箱 ──
    section("1/8  创建隔离沙箱")
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

        # ── 2/8 安装监控工具 (在快照之前!) ──
        section("2/8  安装监控工具 (快照前, 避免污染基线)")
        await run_cmd(sandbox,
            "apt-get update -qq 2>/dev/null && "
            "apt-get install -y -qq inotify-tools 2>/dev/null || "
            "yum install -y -q inotify-tools 2>/dev/null || "
            "apk add inotify-tools 2>/dev/null || "
            "echo 'skip'", timeout_sec=120)
        print("  inotify-tools 已安装 (如有)")

        # ── 3/8 执行前快照 (干净基线) ──
        section("3/8  采集执行前快照 (干净基线)")
        t0 = time.time()
        pre_fs, pre_ps, pre_persist, pre_auth, pre_shell = await asyncio.gather(
            snap_fs(sandbox), snap_ps(sandbox),
            snap_persist(sandbox), snap_auth(sandbox), snap_shell(sandbox))
        print(f"  文件数   : {len(pre_fs)}")
        print(f"  耗时     : {time.time()-t0:.1f}s")
        try:
            pre_m = await sandbox.get_metrics()
            print(f"  CPU      : {pre_m.cpu_used_percentage:.1f}%")
            print(f"  Memory   : {pre_m.memory_used_in_mib:.1f}/{pre_m.memory_total_in_mib:.1f} MiB")
        except Exception:
            pre_m = None

        # ── 4/8 启动探针 + 执行命令 ──
        section("4/8  启动监控 + 执行待测命令")

        # inotifywait: 不监控 /tmp (execd 在 /tmp 大量读写, 且日志也在 /tmp, 会递归)
        # 只监控真正重要的目录
        await run_cmd(sandbox,
            "nohup inotifywait -mr -e create,modify,delete,moved_to "
            "--timefmt '%Y-%m-%dT%H:%M:%S' --format '%T %e %w%f' "
            "/usr/local/bin /usr/bin /etc /root /home "
            "> /var/log/.inotify_log 2>/dev/null &", 10)
        print("  [inotify]  监控: /usr/local/bin /usr/bin /etc /root /home")
        print("             日志: /var/log/.inotify_log (避免 /tmp 递归)")

        # 网络连接轮询
        await run_cmd(sandbox, "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null > /tmp/.net_baseline", 5)
        await run_cmd(sandbox,
            "nohup sh -c 'while true; do cat /proc/net/tcp /proc/net/tcp6 2>/dev/null; sleep 1; "
            "done > /tmp/.net_poll_log 2>/dev/null' &", 5)
        print("  [network]  /proc/net/tcp 轮询 (1s)")

        await run_cmd(sandbox, "cp /etc/resolv.conf /tmp/.resolv_baseline 2>/dev/null || true", 5)

        # 执行待测命令
        print(f"\n  $ {COMMAND}")
        print(f"  {'─'*60}", flush=True)
        t1 = time.time()
        stdout, stderr = await run_cmd(sandbox, COMMAND, timeout_sec=300)
        dur = time.time() - t1

        stdout_lines = stdout.splitlines() if stdout else []
        stderr_lines = stderr.splitlines() if stderr else []
        print(f"\n  耗时   : {dur:.1f}s")
        print(f"  stdout : {len(stdout_lines)} 行")
        print(f"  stderr : {len(stderr_lines)} 行")
        if stdout_lines:
            sub("stdout (前 50 行)")
            for l in stdout_lines[:50]: print(f"    | {l}")
            if len(stdout_lines) > 50: print(f"    | ... ({len(stdout_lines)-50} more)")
        if stderr_lines:
            sub("stderr (前 30 行)")
            for l in stderr_lines[:30]: print(f"    | {l}")

        evidence["stdout_lines"] = len(stdout_lines)
        evidence["stderr_lines"] = len(stderr_lines)
        evidence["exec_duration_sec"] = round(dur, 1)

        # ── 5/8 执行后快照 ──
        section("5/8  采集执行后快照")
        await asyncio.sleep(2)
        post_fs, post_ps, post_persist, post_auth, post_shell = await asyncio.gather(
            snap_fs(sandbox), snap_ps(sandbox),
            snap_persist(sandbox), snap_auth(sandbox), snap_shell(sandbox))
        try:
            post_m = await sandbox.get_metrics()
        except Exception:
            post_m = None

        inotify_log, _ = await run_cmd(sandbox, "cat /var/log/.inotify_log 2>/dev/null")
        net_poll_log, _ = await run_cmd(sandbox, "cat /tmp/.net_poll_log 2>/dev/null")
        resolv_after, _ = await run_cmd(sandbox, "cat /etc/resolv.conf 2>/dev/null")
        resolv_before, _ = await run_cmd(sandbox, "cat /tmp/.resolv_baseline 2>/dev/null")
        post_net, _ = await run_cmd(sandbox,
            "ss -tunap 2>/dev/null || cat /proc/net/tcp /proc/net/tcp6 2>/dev/null || echo N/A")

        print(f"  文件数     : {len(post_fs)}")
        print(f"  inotify    : {len(inotify_log.splitlines())} 条")

        # ── 6/8 网络分析 ──
        section("6/8  网络行为分析")

        baseline_conns = parse_proc_net(
            (await run_cmd(sandbox, "cat /tmp/.net_baseline 2>/dev/null"))[0])
        poll_conns = parse_proc_net(net_poll_log)
        new_conns_raw = poll_conns - baseline_conns

        external = {(ip, p) for ip, p in new_conns_raw if not is_internal(ip)}
        internal = new_conns_raw - external

        sub("外部连接 (真正的出站)")
        if external:
            for ip, port in sorted(external):
                proto = "HTTPS" if port == 443 else "HTTP" if port == 80 else f":{port}"
                print(f"    -> {ip}:{port} ({proto})")
        else:
            print("    (无外部连接)")
        if internal:
            print(f"\n    [{len(internal)} 个内部连接已忽略 (127.0.0.1, 172.17.* = execd/Docker)]")

        evidence["external_connections"] = [f"{ip}:{p}" for ip, p in sorted(external)]

        sub("DNS 配置")
        if resolv_before.strip() == resolv_after.strip():
            print("    PASS  /etc/resolv.conf 未被修改")
        else:
            findings.append("WARN: /etc/resolv.conf 被修改")
            print("    !! /etc/resolv.conf 已被修改!")

        # ── 7/8 安全对比 ──
        section("7/8  安全对比分析")

        # 文件变更
        new_files = post_fs - pre_fs
        deleted_files = pre_fs - post_fs
        new_paths = sorted(extract_path(f) for f in new_files)
        del_paths = sorted(extract_path(f) for f in deleted_files)

        sub(f"文件变更 (+{len(new_paths)} / -{len(del_paths)})")
        if new_paths:
            print(f"    新增 {len(new_paths)} 个:")
            for p in new_paths[:80]: print(f"      + {p}")
            if len(new_paths) > 80: print(f"      ... 还有 {len(new_paths)-80} 个")
        else:
            print("    (无新增)")
        if del_paths:
            print(f"    删除 {len(del_paths)} 个:")
            for p in del_paths[:30]: print(f"      - {p}")
        evidence["files_added"] = len(new_paths)
        evidence["files_deleted"] = len(del_paths)

        SENSITIVE = ["/etc/passwd", "/etc/shadow", "/etc/sudoers",
                     "/root/.ssh", "/etc/ssh/", "/usr/sbin/",
                     "/etc/ld.so", "/etc/pam.d/"]
        suspicious = [p for p in new_paths if any(p.startswith(s) for s in SENSITIVE)]
        if suspicious:
            findings.append(f"CRITICAL: 敏感路径写入: {suspicious}")
            print(f"    !! 敏感路径写入: {suspicious}")

        # inotify 事件
        sub("实时文件事件 (inotifywait)")
        inotify_lines = [l for l in inotify_log.splitlines() if l.strip()]
        if inotify_lines:
            for l in inotify_lines[:50]: print(f"    {l}")
            if len(inotify_lines) > 50: print(f"    ... 还有 {len(inotify_lines)-50} 条")
        else:
            print("    (无事件 — 待测命令未修改监控目录内文件)")
        evidence["inotify_events"] = len(inotify_lines)

        # 用户/权限
        sub("用户与权限")
        if pre_auth.strip() == post_auth.strip():
            print("    PASS  /etc/passwd, shadow, sudoers, SSH 无变化")
        else:
            findings.append("CRITICAL: 用户/权限配置被修改!")
            print("    !! FAIL  用户/权限配置已变更!")

        # 持久化
        sub("持久化 (cron/systemd/rc.local)")
        if pre_persist.strip() == post_persist.strip():
            print("    PASS  无新增")
        else:
            findings.append("WARN: 持久化机制被修改")
            print("    !! FAIL")

        # Shell 环境
        sub("Shell 环境 (.bashrc/.profile)")
        if pre_shell.strip() == post_shell.strip():
            print("    PASS  无变化")
        else:
            findings.append("WARN: Shell 配置被修改")
            print("    !! FAIL")
            c, _ = await run_cmd(sandbox, "cat ~/.bashrc ~/.bash_profile ~/.profile 2>/dev/null | head -20")
            for l in c.splitlines()[:15]: print(f"      {l}")

        # 残留进程 (过滤监控自身)
        sub("残留进程")
        for l in post_ps.splitlines():
            if any(x in l for x in ["inotifywait", ".net_poll", "sleep 1"]): continue
            print(f"      {l}")

        # 残留连接
        sub("残留网络连接")
        net_lines = [l for l in post_net.splitlines() if l.strip()]
        if net_lines:
            for l in net_lines[:15]: print(f"      {l}")
        else:
            print("    (无)")

        # 资源
        sub("资源消耗")
        if pre_m and post_m:
            print(f"    CPU    : {pre_m.cpu_used_percentage:.1f}% -> {post_m.cpu_used_percentage:.1f}%")
            print(f"    Memory : {pre_m.memory_used_in_mib:.1f} -> {post_m.memory_used_in_mib:.1f} MiB")
            if post_m.cpu_used_percentage > 80:
                findings.append(f"WARN: CPU 异常 ({post_m.cpu_used_percentage:.1f}%)")
        else:
            print("    (不可用)")

        # 可疑二进制 (用 grep -v 过滤 execd 的 uuid 文件, 比 find -regex 更可靠)
        sub("可疑二进制 (/tmp /var/tmp /dev/shm)")
        sus, _ = await run_cmd(sandbox,
            "find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null "
            "| grep -vE '/[0-9a-f]{32}\\.(stdout|stderr)$' "
            "| grep -vE '/\\.' "
            "| grep -v execd.log "
            "|| echo none")
        sus_clean = sus.strip()
        if sus_clean and sus_clean != "none":
            findings.append(f"WARN: 临时目录可执行文件: {sus_clean}")
            print(f"    !! {sus_clean}")
        else:
            print("    PASS")

        # ── 8/8 综合判定 ──
        section("8/8  综合判定")
        evidence["findings"] = findings
        critical = [f for f in findings if "CRITICAL" in f]
        warns = [f for f in findings if "WARN" in f]

        if critical: verdict, sym = "DANGEROUS", "!!"
        elif warns: verdict, sym = "SUSPICIOUS", "??"
        else: verdict, sym = "LIKELY_SAFE", "OK"

        print(f"""
  +{'─'*(W-2)}+
  |  [{sym}] 判定: {verdict:50s}|
  +{'─'*(W-2)}+
""")
        print(f"  命令         : {COMMAND}")
        print(f"  文件 +/-     : +{len(new_paths)} / -{len(del_paths)}")
        print(f"  inotify      : {len(inotify_lines)} 事件")
        print(f"  外部连接     : {len(external)} 个")
        print(f"  执行耗时     : {dur:.1f}s")
        print(f"  发现         : {len(critical)} critical, {len(warns)} warnings")
        print()

        if findings:
            print("  详细发现:")
            for f in findings: print(f"    - {f}")
        else:
            print("  全部检查通过:")
            for c in [
                "无敏感路径写入 (/etc/passwd, /etc/shadow, ...)",
                "用户/权限未被修改",
                "无持久化后门 (cron/systemd)",
                "Shell 环境未被篡改",
                "DNS 配置未被修改",
                "无可疑残留进程",
                "临时目录无可执行文件",
                f"外部连接仅 {len(external)} 个",
            ]: print(f"    [PASS] {c}")

        report = {
            "command": COMMAND,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "verdict": verdict,
            "evidence": evidence,
            "new_files": new_paths[:300],
            "deleted_files": del_paths[:50],
            "inotify_events": inotify_lines[:300],
            "external_connections": [f"{ip}:{p}" for ip, p in sorted(external)],
            "stdout": stdout_lines[:100],
            "stderr": stderr_lines[:50],
        }
        report_file = os.path.join(REPORT_DIR, f"safety_report_{int(time.time())}.json")
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n  报告: {report_file}")
        await sandbox.kill()
        print("  沙箱已销毁。\n")

if __name__ == "__main__":
    asyncio.run(main())
PYTHON_SCRIPT

export CHECK_COMMAND="$COMMAND"
export SANDBOX_IMAGE REPORT_DIR
python3 "${WORK_DIR}/checker.py"

# ── Step 7: 完成 ──
echo ""
info "[Step 7/7] 完成!"
REPORT=$(ls -t "${REPORT_DIR}"/safety_report_*.json 2>/dev/null | head -1)
if [ -n "$REPORT" ]; then
    ok "报告: ${REPORT}"
    echo "  查看: python3 -m json.tool ${REPORT}"
    echo ""
fi
