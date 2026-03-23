"""
sandbox_ops.py — 沙箱操作封装

核心: 所有 snapshot (快照) 函数都采用并发执行 (asyncio.gather)，
显著减少等待时间。

关键设计原则: 必须采集 before/after 快照，对比才有意义。
任何单独的 after 状态不能代表"命令的行为"。
"""
from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass  # Sandbox type hint only

# ═══════════════════════════════════════════════════════════════════════════
#  基础设施文件过滤（避免把监控探针自身的文件当作恶意发现）
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


def is_infra_file(path: str) -> bool:
    return path in INFRA_FILES or bool(EXECD_TMP_RE.match(path))


# ═══════════════════════════════════════════════════════════════════════════
#  核心命令执行包装
# ═══════════════════════════════════════════════════════════════════════════

async def run_cmd(sandbox, cmd: str, timeout_sec: int = 120) -> tuple[str, str]:
    """在沙箱内运行命令，返回 (stdout, stderr)"""
    try:
        r = await asyncio.wait_for(sandbox.commands.run(cmd), timeout=timeout_sec)
        out = "\n".join(m.text for m in r.logs.stdout) if r.logs.stdout else ""
        err = "\n".join(m.text for m in r.logs.stderr) if r.logs.stderr else ""
        return out, err
    except asyncio.TimeoutError:
        return "", f"[TIMEOUT {timeout_sec}s]"
    except Exception as e:
        return "", f"[ERROR] {e}"


# ═══════════════════════════════════════════════════════════════════════════
#  快照函数 — 每个函数只负责采集一类数据
# ═══════════════════════════════════════════════════════════════════════════

async def snap_fs(sandbox) -> set[str]:
    """文件系统快照，排除基础设施文件"""
    o, _ = await run_cmd(sandbox,
        "find / -xdev -not -path '/proc/*' -not -path '/sys/*' "
        "-not -path '/dev/*' -not -path '/run/*' "
        "-type f -printf '%s %T@ %p\\n' 2>/dev/null | sort", 60)
    result: set[str] = set()
    for line in (o.strip().splitlines() if o.strip() else []):
        parts = line.split(" ", 2)
        path = parts[2] if len(parts) == 3 else line
        if not is_infra_file(path):
            result.add(line)
    return result


async def snap_ps(sandbox) -> str:
    """进程列表快照"""
    o, _ = await run_cmd(sandbox, "ps auxf 2>/dev/null || ps aux")
    return o


async def snap_persist(sandbox) -> str:
    """持久化机制全面快照: cron + systemd + rc.local + init.d + at + timer
    返回完整内容以便做精确差值分析
    """
    o, _ = await run_cmd(sandbox,
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


async def snap_auth(sandbox) -> str:
    """用户/权限全面快照"""
    o, _ = await run_cmd(sandbox,
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


async def snap_shell(sandbox) -> str:
    """Shell 配置快照"""
    o, _ = await run_cmd(sandbox,
        "echo '=== bashrc ==='; cat ~/.bashrc 2>/dev/null || true; "
        "echo '=== bash_profile ==='; cat ~/.bash_profile 2>/dev/null || true; "
        "echo '=== profile ==='; cat ~/.profile 2>/dev/null || true; "
        "echo '=== bash_logout ==='; cat ~/.bash_logout 2>/dev/null || true; "
        "echo '=== etc_profile ==='; cat /etc/profile 2>/dev/null || true; "
        "echo '=== etc_bashrc ==='; cat /etc/bash.bashrc 2>/dev/null || true; "
        "echo '=== etc_environment ==='; cat /etc/environment 2>/dev/null || true; "
        "echo '=== profile.d ==='; cat /etc/profile.d/*.sh 2>/dev/null || true")
    return o


async def snap_suid(sandbox) -> set[str]:
    """SUID/SGID 文件快照 - 使用稳定格式避免时间戳差异"""
    o, _ = await run_cmd(sandbox,
        "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f "
        "-printf '%m %u %g %p\\n' 2>/dev/null | sort", 30)
    return set(o.strip().splitlines()) if o.strip() else set()


async def snap_mounts(sandbox) -> str:
    """挂载点快照"""
    o, _ = await run_cmd(sandbox, "mount 2>/dev/null | sort")
    return o


async def snap_modules(sandbox) -> str:
    """内核模块快照"""
    o, _ = await run_cmd(sandbox,
        "lsmod 2>/dev/null | sort || "
        "cat /proc/modules 2>/dev/null | sort || echo 'N/A'")
    return o


async def snap_env(sandbox) -> str:
    """安全相关环境变量快照"""
    o, _ = await run_cmd(sandbox,
        "env 2>/dev/null | grep -E "
        "'(LD_PRELOAD|LD_LIBRARY_PATH|PATH|HOME|SHELL|USER|SUDO|HTTP_PROXY|HTTPS_PROXY)' "
        "| sort || true")
    return o


async def snap_critical_bins(sandbox) -> str:
    """关键系统二进制文件 hash 快照"""
    o, _ = await run_cmd(sandbox,
        "md5sum /bin/bash /bin/sh /bin/su /usr/bin/sudo /usr/bin/passwd "
        "/usr/bin/crontab /usr/sbin/sshd /bin/login "
        "/usr/bin/ssh /usr/bin/newgrp 2>/dev/null | sort || true", 15)
    return o


async def snap_symlinks(sandbox) -> set[str]:
    """关键目录中的符号链接快照"""
    o, _ = await run_cmd(sandbox,
        "find /etc /root /home /tmp /usr/local/bin -maxdepth 3 -type l "
        "-exec ls -la {} \\; 2>/dev/null | sort || true", 20)
    return set(o.strip().splitlines()) if o.strip() else set()


async def snap_file_caps(sandbox) -> set[str]:
    """文件能力 (getcap) 快照"""
    o, _ = await run_cmd(sandbox, "getcap -r / 2>/dev/null | sort || true", 20)
    return set(o.strip().splitlines()) if o.strip() else set()


# ═══════════════════════════════════════════════════════════════════════════
#  并发基线采集 — 核心性能优化点
#
#  使用 asyncio.gather 并发运行所有快照函数，比串行快 5-8x。
#  这是 before 和 after 都要调用的函数。
# ═══════════════════════════════════════════════════════════════════════════

async def collect_all_snapshots(sandbox) -> dict:
    """并发采集所有维度的快照，返回 dict。
    
    这是 before/after 对比的核心数据结构。
    任何单独调用 after 快照都没有意义，必须与 before 对比。
    """
    (fs, ps, persist, auth, shell_cfg,
     suid, mounts, modules, env,
     bins, symlinks, file_caps) = await asyncio.gather(
        snap_fs(sandbox),
        snap_ps(sandbox),
        snap_persist(sandbox),
        snap_auth(sandbox),
        snap_shell(sandbox),
        snap_suid(sandbox),
        snap_mounts(sandbox),
        snap_modules(sandbox),
        snap_env(sandbox),
        snap_critical_bins(sandbox),
        snap_symlinks(sandbox),
        snap_file_caps(sandbox),
    )
    return {
        "fs": fs,
        "ps": ps,
        "persist": persist,
        "auth": auth,
        "shell": shell_cfg,
        "suid": suid,
        "mounts": mounts,
        "modules": modules,
        "env": env,
        "bins": bins,
        "symlinks": symlinks,
        "file_caps": file_caps,
    }


# ═══════════════════════════════════════════════════════════════════════════
#  探针管理 — 实时监控（在命令执行期间运行）
# ═══════════════════════════════════════════════════════════════════════════

async def start_probes(sandbox) -> str:
    """启动所有实时监控探针，采集网络基线，返回 resolv.conf 基线"""

    # 安装监控工具（优先使用 apt，失败则 yum/apk）
    await run_cmd(sandbox,
        "apt-get update -qq 2>/dev/null && "
        "apt-get install -y -qq inotify-tools procps 2>/dev/null || "
        "yum install -y -q inotify-tools procps-ng 2>/dev/null || "
        "apk add inotify-tools procps 2>/dev/null || "
        "echo 'skip'", timeout_sec=120)

    # 探针1: inotify 监控关键系统目录
    await run_cmd(sandbox,
        "nohup inotifywait -mr -e create,modify,delete,moved_to,attrib "
        "--timefmt '%Y-%m-%dT%H:%M:%S' --format '%T %e %w%f' "
        "/usr/local/bin /usr/bin /usr/sbin /etc /root /home "
        "> /var/log/.inotify_log 2>/dev/null &", 10)

    # 探针2: inotify 独立监控 /tmp（避免递归）
    await run_cmd(sandbox,
        "nohup inotifywait -mr -e create,modify,delete,moved_to,attrib "
        "--timefmt '%Y-%m-%dT%H:%M:%S' --format '%T %e %w%f' "
        "--exclude '\\.(stdout|stderr|inotify|net_|resolv_|proc_|audit_|suid_|mount_|modules_|env_|caps_|conntrack_)' "
        "/tmp /var/tmp /dev/shm "
        "> /tmp/.inotify_tmp_log 2>/dev/null &", 10)

    # 探针3: 网络连接高频轮询
    await run_cmd(sandbox,
        "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null > /tmp/.net_baseline", 5)
    await run_cmd(sandbox,
        "nohup sh -c 'while true; do "
        "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null; "
        "sleep 0.5; done > /tmp/.net_poll_log 2>/dev/null' &", 5)

    # 探针4: DNS 基线
    resolv_before, _ = await run_cmd(sandbox,
        "cat /etc/resolv.conf 2>/dev/null; "
        "cp /etc/resolv.conf /tmp/.resolv_baseline 2>/dev/null || true", 5)

    # 探针5: 进程树轮询
    await run_cmd(sandbox,
        "nohup sh -c 'while true; do "
        "ps auxf 2>/dev/null || ps aux 2>/dev/null; "
        "echo \"=== $(date +%s) ===\"; "
        "sleep 1; done > /tmp/.proc_tree_log 2>/dev/null' &", 5)

    return resolv_before


async def collect_probe_results(sandbox) -> dict:
    """收集所有探针的运行结果"""
    (inotify_sys, inotify_tmp, net_poll,
     resolv_after, post_net, proc_tree) = await asyncio.gather(
        run_cmd(sandbox, "cat /var/log/.inotify_log 2>/dev/null"),
        run_cmd(sandbox, "cat /tmp/.inotify_tmp_log 2>/dev/null"),
        run_cmd(sandbox, "cat /tmp/.net_poll_log 2>/dev/null"),
        run_cmd(sandbox, "cat /etc/resolv.conf 2>/dev/null"),
        run_cmd(sandbox,
            "ss -tunap 2>/dev/null || "
            "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null || echo N/A"),
        run_cmd(sandbox, "cat /tmp/.proc_tree_log 2>/dev/null"),
    )

    net_baseline_raw, _ = await run_cmd(sandbox, "cat /tmp/.net_baseline 2>/dev/null")

    # 过滤 /tmp 事件中的基础设施文件
    infra_keywords = [".inotify", ".net_", ".resolv_", ".proc_", ".audit_",
                      ".suid_", ".mount_", ".modules_", ".env_", ".caps_",
                      ".conntrack_", "execd"]
    inotify_tmp_clean = [
        l for l in inotify_tmp[0].splitlines()
        if l.strip() and not any(k in l for k in infra_keywords)
    ]

    return {
        "inotify_sys": inotify_sys[0],
        "inotify_tmp": "\n".join(inotify_tmp_clean),
        "net_poll": net_poll[0],
        "net_baseline": net_baseline_raw,
        "resolv_after": resolv_after[0],
        "post_net": post_net[0],
        "proc_tree": proc_tree[0],
    }


# ═══════════════════════════════════════════════════════════════════════════
#  网络分析工具函数
# ═══════════════════════════════════════════════════════════════════════════

def parse_proc_net(raw: str) -> set[tuple[str, int]]:
    """解析 /proc/net/tcp 原始文本，返回 (ip, port) 集合"""
    conns: set[tuple[str, int]] = set()
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


def is_internal_ip(ip: str) -> bool:
    return (ip.startswith("127.") or ip.startswith("172.17.")
            or ip.startswith("172.18.") or ip.startswith("10.")
            or ip.startswith("169.254.") or ip == "0.0.0.0")
