"""
diff_analysis.py — Before/After 差值分析核心

这是整个项目的核心模块。
所有分析都基于沙箱执行前后快照的对比：
  before_snap  — 命令执行前采集的系统状态基线
  after_snap   — 命令执行后采集的系统状态
  diff         — before vs after = 命令实际产生的行为变化

不做任何命令字符串的静态分析，仅观察行为事实。
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import defaultdict
from typing import TYPE_CHECKING

from .patterns import ARTIFACT_PATTERNS, CRON_ARTIFACT_PATTERNS, OUTPUT_PATTERNS
from .scoring import ScoringEngine
from .sandbox_ops import run_cmd, parse_proc_net, is_internal_ip

if TYPE_CHECKING:
    pass

# C2 常见端口
C2_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337,
            12345, 4443, 8443, 1337, 6667, 6697}

# 敏感路径前缀（写入这些路径视为可疑）
# 注意: /etc/ld.so.cache 是 ldconfig 正常更新的文件，不在此列表中
# /etc/ld.so.preload 才是恶意的 LD_PRELOAD 劫持目标
SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/root/.ssh", "/etc/ssh/",
    "/etc/ld.so.preload",  # LD_PRELOAD 劫持（不包括 .cache，那是 ldconfig 正常更新的）
    "/etc/pam.d/", "/etc/security/",
    "/etc/systemd/system/", "/etc/init.d/",
    "/etc/cron", "/etc/profile",
    "/usr/sbin/", "/usr/bin/sudo", "/bin/su",
]


def extract_path(entry: str) -> str:
    parts = entry.split(" ", 2)
    return parts[2] if len(parts) == 3 else entry


def calculate_entropy(data: bytes) -> float:
    """计算字节串的 Shannon 熵 (0-8)"""
    if not data:
        return 0.0
    freq: defaultdict = defaultdict(int)
    for c in data:
        freq[c] += 1
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values() if count > 0
    )
    return round(entropy, 2)


def extract_persist_section(content: str, marker: str) -> str:
    """从 persist 快照内容中提取特定 section"""
    lines = content.splitlines()
    in_section = False
    section_lines = []
    for line in lines:
        if marker in line:
            in_section = True
            continue
        if in_section:
            if line.startswith("===") and marker not in line:
                break
            section_lines.append(line)
    return "\n".join(section_lines)


class DiffAnalyzer:
    """
    Before/After 对比分析器

    每个 analyze_* 方法接收 before 和 after 两个快照，
    只报告两者之间的差异，不评估任何静态属性。
    """

    def __init__(self, engine: ScoringEngine, before: dict, after: dict,
                 probes: dict, stdout: str, stderr: str):
        self.engine = engine
        self.before = before
        self.after = after
        self.probes = probes
        self.stdout = stdout
        self.stderr = stderr
        self.evidence: dict = {}

        # 预计算的差异结果（precompute_diffs 后填充）
        self._new_paths: list[str] = []
        self._del_paths: list[str] = []
        self._new_suid: set[str] = set()
        self._removed_suid: set[str] = set()
        self._new_symlinks: set[str] = set()
        self._new_caps: set[str] = set()
        self._external_conns: set[tuple[str, int]] = set()

    def precompute_diffs(self) -> None:
        """预计算所有 before/after 差异，避免重复计算"""
        pre_fs = self.before["fs"]
        post_fs = self.after["fs"]
        new_files = post_fs - pre_fs
        deleted_files = pre_fs - post_fs
        self._new_paths = sorted(extract_path(f) for f in new_files)
        self._del_paths = sorted(extract_path(f) for f in deleted_files)

        self._new_suid = self.after["suid"] - self.before["suid"]
        self._removed_suid = self.before["suid"] - self.after["suid"]
        self._new_symlinks = self.after["symlinks"] - self.before["symlinks"]
        self._new_caps = self.after["file_caps"] - self.before["file_caps"]

        # 网络连接差异：执行期间出现但执行前不存在的外部连接
        baseline_conns = parse_proc_net(self.probes["net_baseline"])
        poll_conns = parse_proc_net(self.probes["net_poll"])
        new_conns = poll_conns - baseline_conns
        self._external_conns = {
            (ip, p) for ip, p in new_conns if not is_internal_ip(ip)
        }

    # ── D1: 文件变更 ──────────────────────────────────────────────────────

    def analyze_file_changes(self) -> dict:
        """D1: 文件系统变更 — before 快照 vs after 快照"""
        new_paths = self._new_paths
        del_paths = self._del_paths
        self.evidence["files_added"] = len(new_paths)
        self.evidence["files_deleted"] = len(del_paths)

        # 写入敏感路径
        suspicious = [
            p for p in new_paths
            if any(p.startswith(s) for s in SENSITIVE_PATHS)
        ]
        if suspicious:
            self.engine.add(
                "CRITICAL", "文件变更",
                f"敏感路径写入: {suspicious[:5]}",
                35, ["T1222.002"], str(suspicious[:10]),
            )

        return {"new": new_paths, "deleted": del_paths, "suspicious": suspicious}

    # ── D2: 实时文件事件 ────────────────────────────────────────────────────

    def analyze_inotify(self) -> dict:
        """D2: inotifywait 实时事件 — 命令执行期间捕获"""
        sys_events = [l for l in self.probes["inotify_sys"].splitlines() if l.strip()]
        tmp_events = [l for l in self.probes["inotify_tmp"].splitlines() if l.strip()]
        self.evidence["inotify_sys_events"] = len(sys_events)
        self.evidence["inotify_tmp_events"] = len(tmp_events)
        return {"sys": sys_events, "tmp": tmp_events}

    # ── D3: 用户/权限 ───────────────────────────────────────────────────────

    def analyze_auth(self) -> bool:
        """D3: 用户/权限配置 — before vs after"""
        pre = self.before["auth"]
        post = self.after["auth"]
        if pre.strip() == post.strip():
            return False
        self.engine.add(
            "CRITICAL", "用户/权限",
            "用户/权限配置被修改",
            40, ["T1136.001", "T1098"],
            f"Before hash: {hashlib.md5(pre.encode()).hexdigest()}\n"
            f"After hash: {hashlib.md5(post.encode()).hexdigest()}",
        )
        return True

    # ── D4: 持久化 ─────────────────────────────────────────────────────────

    def analyze_persistence(self) -> dict:
        """D4: 持久化机制 — before vs after（cron/systemd/rc.local 等）"""
        pre = self.before["persist"]
        post = self.after["persist"]
        if pre.strip() == post.strip():
            return {"changed": False}

        sections = ["CRONTAB", "/etc/crontab", "cron.d", "systemd system",
                    "rc.local", "init.d", "at queue", "systemd timers"]
        changed_sections = [
            sec for sec in sections
            if extract_persist_section(pre, sec).strip() !=
               extract_persist_section(post, sec).strip()
        ]

        self.engine.add(
            "CRITICAL", "持久化",
            f"持久化机制被修改: {changed_sections}",
            35, ["T1053.003", "T1543.002", "T1037.004"],
        )

        # 对 cron.d 新增内容扫描行为产物
        cron_d_findings = []
        if "cron.d" in changed_sections:
            pre_cron_d = extract_persist_section(pre, "cron.d")
            post_cron_d = extract_persist_section(post, "cron.d")
            new_content = post_cron_d.replace(pre_cron_d, "").strip()
            if new_content:
                for pattern, desc, mitre_id, score in CRON_ARTIFACT_PATTERNS:
                    if re.search(pattern, new_content, re.IGNORECASE):
                        self.engine.add(
                            "CRITICAL", "持久化内容",
                            f"cron.d 新增恶意内容: {desc}",
                            score, [mitre_id], new_content[:200],
                        )
                        cron_d_findings.append(desc)

        return {"changed": True, "sections": changed_sections, "cron_d": cron_d_findings}

    # ── D5: Shell 环境 ─────────────────────────────────────────────────────

    def analyze_shell_env(self) -> bool:
        """D5: Shell 配置文件 — before vs after"""
        pre = self.before["shell"]
        post = self.after["shell"]
        if pre.strip() == post.strip():
            return False
        self.engine.add(
            "CRITICAL", "Shell环境",
            "Shell 配置文件被修改 (.bashrc/.profile 等)",
            30, ["T1546.004"],
        )
        return True

    # ── D6: 网络行为 ───────────────────────────────────────────────────────

    def analyze_network(self) -> dict:
        """D6: 网络连接 — 执行前基线 vs 执行期间捕获的新增连接"""
        external = self._external_conns
        self.evidence["external_connections"] = [
            f"{ip}:{p}" for ip, p in sorted(external)
        ]

        if not external:
            self.evidence["c2_port_hits"] = []
            return {"external": set(), "c2": []}

        # 非标准端口
        suspicious_ports = [(ip, p) for ip, p in external
                            if p not in (80, 443, 53, 8080, 8443)]
        if suspicious_ports:
            self.engine.add(
                "WARN", "网络",
                f"外部非标准端口连接: {suspicious_ports[:5]}",
                20, ["T1071.001"], str(suspicious_ports[:5]),
            )

        # C2 端口
        c2_conns = [(ip, p) for ip, p in external if p in C2_PORTS]
        if c2_conns:
            self.engine.add(
                "CRITICAL", "网络",
                f"C2 常见端口连接: {c2_conns}",
                35, ["T1071.001"], str(c2_conns),
            )

        # 多目标扫描
        unique_ips = {ip for ip, _ in external}
        if len(unique_ips) >= 5:
            self.engine.add(
                "WARN", "网络",
                f"连接到 {len(unique_ips)} 个不同 IP (扫描行为)",
                15, ["T1016"], str(sorted(unique_ips)[:20]),
            )

        self.evidence["c2_port_hits"] = [
            f"{ip}:{p}" for ip, p in sorted(external) if p in C2_PORTS
        ]
        return {"external": external, "c2": c2_conns}

    # ── D7: DNS ────────────────────────────────────────────────────────────

    def analyze_dns(self) -> bool:
        """D7: /etc/resolv.conf — before vs after"""
        before_resolv = self.probes.get("resolv_before", "")
        after_resolv = self.probes["resolv_after"]
        if before_resolv.strip() == after_resolv.strip():
            return False
        self.engine.add(
            "CRITICAL", "DNS",
            "/etc/resolv.conf 被修改 (DNS 劫持)",
            30, ["T1016"], after_resolv[:200],
        )
        return True

    # ── D8: SUID/SGID ──────────────────────────────────────────────────────

    def analyze_suid(self) -> dict:
        """D8: SUID/SGID 文件 — before vs after"""
        new_suid = self._new_suid
        if new_suid:
            self.engine.add(
                "CRITICAL", "SUID/SGID",
                f"新增 SUID/SGID 文件: {len(new_suid)} 个",
                40, ["T1548.001"], "\n".join(list(new_suid)[:10]),
            )
        self.evidence["suid_added"] = len(new_suid)
        return {"added": new_suid, "removed": self._removed_suid}

    # ── D9: 内核模块 ───────────────────────────────────────────────────────

    def analyze_modules(self) -> bool:
        """D9: 内核模块列表 — before vs after"""
        if self.before["modules"].strip() == self.after["modules"].strip():
            return False
        self.engine.add(
            "CRITICAL", "内核模块",
            "内核模块列表变更",
            45, ["T1014"], self.after["modules"][:200],
        )
        return True

    # ── D10: 挂载点 ────────────────────────────────────────────────────────

    def analyze_mounts(self) -> bool:
        """D10: 挂载点 — before vs after"""
        if self.before["mounts"].strip() == self.after["mounts"].strip():
            return False
        self.engine.add(
            "WARN", "挂载点",
            "挂载点配置变更",
            20, ["T1611"], self.after["mounts"][:200],
        )
        return True

    # ── D11: 环境变量 ──────────────────────────────────────────────────────

    def analyze_env_vars(self) -> list[str]:
        """D11: 安全相关环境变量 — before vs after"""
        pre_set = set(self.before["env"].strip().splitlines())
        post_set = set(self.after["env"].strip().splitlines())
        new_envs = list(post_set - pre_set)
        for env_line in new_envs:
            if "LD_PRELOAD" in env_line:
                self.engine.add(
                    "CRITICAL", "环境变量",
                    f"LD_PRELOAD 被设置: {env_line}",
                    40, ["T1574.006"], env_line,
                )
            elif "LD_LIBRARY_PATH" in env_line:
                self.engine.add(
                    "WARN", "环境变量",
                    f"LD_LIBRARY_PATH 变更: {env_line}",
                    15, ["T1574.001"], env_line,
                )
        return new_envs

    # ── D12: 关键二进制完整性 ──────────────────────────────────────────────

    def analyze_binary_integrity(self) -> bool:
        """D12: 关键系统二进制 hash — before vs after"""
        pre = self.before["bins"]
        post = self.after["bins"]
        if pre.strip() == post.strip():
            return False
        self.engine.add(
            "CRITICAL", "二进制完整性",
            "关键系统二进制被篡改",
            45, ["T1554"],
            f"Before:\n{pre[:200]}\nAfter:\n{post[:200]}",
        )
        self.evidence["critical_bins_changed"] = True
        return True

    # ── D13: 符号链接 ──────────────────────────────────────────────────────

    def analyze_symlinks(self) -> dict:
        """D13: 符号链接 — before vs after"""
        new_symlinks = self._new_symlinks
        dangerous = [
            l for l in new_symlinks
            if any(s in l for s in [
                "/etc/shadow", "/etc/passwd", "/proc/", "/dev/null",
                "authorized_keys", ".bash_history",
            ])
        ]
        if dangerous:
            self.engine.add(
                "WARN", "符号链接",
                "新增指向敏感目标的符号链接",
                20, ["T1036"], "\n".join(list(dangerous)[:5]),
            )
        self.evidence["new_symlinks"] = len(new_symlinks)
        return {"new": new_symlinks, "dangerous": dangerous}

    # ── D14: 文件能力 ──────────────────────────────────────────────────────

    def analyze_file_caps(self) -> set[str]:
        """D14: 文件能力 (getcap) — before vs after"""
        new_caps = self._new_caps
        if new_caps:
            self.engine.add(
                "CRITICAL", "文件能力",
                f"新增文件能力: {len(new_caps)} 个",
                35, ["T1548.001"], "\n".join(list(new_caps)[:10]),
            )
        self.evidence["new_file_caps"] = len(new_caps)
        return new_caps

    # ── D15: 新增文件/shell 配置内容扫描 ──────────────────────────────────

    def analyze_artifacts(self, shell_changed: bool, new_file_contents: dict) -> list[str]:
        """D15: 扫描执行后新增/变更文件的内容（行为产物）

        参数:
          shell_changed: D5 是否检测到 shell 配置变更
          new_file_contents: {path: content} 从沙箱读取的新增文件内容
        只扫描 before→after 确认新增或变更的文件，不扫描执行前已有内容。
        """
        hits = []

        # 扫描 shell 配置变更内容
        if shell_changed and "shell_after" in new_file_contents:
            content = new_file_contents["shell_after"]
            for pattern, desc, mitre_id, score in ARTIFACT_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    self.engine.add(
                        "CRITICAL", "文件内容",
                        f"Shell 配置含恶意内容: {desc}",
                        score, [mitre_id], desc,
                    )
                    hits.append(f"shell: {desc}")

        # 扫描新增文件内容
        for path, content in new_file_contents.items():
            if path == "shell_after":
                continue
            for pattern, desc, mitre_id, score in ARTIFACT_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    sev = "CRITICAL" if score >= 35 else "WARN"
                    self.engine.add(
                        sev, "文件内容",
                        f"新增文件 {path} 含恶意内容: {desc}",
                        score, [mitre_id], content[:200],
                    )
                    hits.append(f"{path}: {desc}")

        return hits

    # ── D16: 输出内容分析 ──────────────────────────────────────────────────

    def analyze_output(self) -> list[str]:
        """D16: 命令 stdout/stderr 中的敏感信息泄露"""
        output_text = self.stdout + "\n" + self.stderr
        found = []
        for pattern, desc, mitre_id, score in OUTPUT_PATTERNS:
            if re.search(pattern, output_text, re.IGNORECASE):
                found.append(desc)
                self.engine.add("WARN", "输出分析", desc, score, [mitre_id])
        return found

    # ── D17: 高熵文件 ──────────────────────────────────────────────────────

    async def analyze_entropy(self, sandbox, entropy_threshold: float = 6.5) -> list[tuple[str, float]]:
        """D17: 新增文件熵分析

        仅分析 D1 中 before→after 确认新增的文件，不扫描执行前已有文件。
        """
        import base64 as b64
        high_entropy = []
        for path in self._new_paths[:20]:
            if not any(path.startswith(d) for d in ["/tmp/", "/var/tmp/", "/dev/shm/"]):
                continue
            fc, _ = await run_cmd(sandbox, f"head -c 1024 '{path}' 2>/dev/null | base64", 5)
            if not fc.strip():
                continue
            try:
                raw = b64.b64decode(fc.strip())
                ent = calculate_entropy(raw)
                if ent > entropy_threshold:
                    high_entropy.append((path, ent))
            except Exception:
                pass
        if high_entropy:
            self.engine.add(
                "WARN", "熵分析",
                f"高熵文件 (可能为加密/混淆载荷): {[f[0] for f in high_entropy]}",
                20, ["T1027"], str(high_entropy),
            )
        return high_entropy

    # ── D18: 攻击链关联 ────────────────────────────────────────────────────

    def analyze_attack_chains(self) -> list[str]:
        """D18: 跨维度攻击链关联分析"""
        chains = []
        finding_dims = set(f.dimension for f in self.engine.findings)
        finding_descs = " ".join(f.description for f in self.engine.findings).lower()

        # 文件落地 + 持久化
        if ("文件变更" in finding_dims or "文件内容" in finding_dims) \
                and "持久化" in finding_dims:
            chains.append("恶意软件部署链 (文件落地 + 持久化)")
            self.engine.add(
                "CRITICAL", "攻击链",
                "检测到恶意软件部署链: 文件落地 + 持久化",
                15, ["T1105", "T1053.003"],
            )

        # 用户变更 + SSH key
        if "用户/权限" in finding_dims and "authorized_keys" in finding_descs:
            chains.append("后门账户链 (用户变更 + SSH key 注入)")
            self.engine.add(
                "CRITICAL", "攻击链",
                "检测到后门账户链: 用户变更 + SSH key 注入",
                15, ["T1098", "T1021.004"],
            )

        # 反取证 + 多维度
        anti_forensics = any(
            any(kw in f.description.lower() for kw in
                ["history", "histfile", "histsize"])
            for f in self.engine.findings
        )
        if anti_forensics and len(self.engine.findings) > 2:
            chains.append("高级攻击链 (反取证 + 多维度恶意行为)")
            self.engine.add(
                "WARN", "攻击链",
                "检测到反取证措施配合其他恶意行为",
                10, ["T1070.003"],
            )

        # DNS 劫持 + 外部连接 = C2
        if "DNS" in finding_dims and self._external_conns:
            chains.append("C2 通信链 (DNS 劫持 + 外部连接)")
            self.engine.add(
                "CRITICAL", "攻击链",
                "检测到 C2 通信链: DNS 劫持 + 外部网络连接",
                20, ["T1071.004", "T1016"],
            )

        # LD_PRELOAD + 二进制篡改 = Rootkit
        if "环境变量" in finding_dims and "二进制完整性" in finding_dims:
            chains.append("Rootkit 链 (LD_PRELOAD + 二进制篡改)")
            self.engine.add(
                "CRITICAL", "攻击链",
                "检测到 Rootkit 链: LD_PRELOAD + 二进制篡改",
                20, ["T1014", "T1574.006"],
            )

        if chains:
            self.evidence["attack_chains"] = chains
        return chains
