"""
engine.py — 主分析引擎

沙箱行为分析流程（纯动态，无静态分析）:

  1. 创建隔离沙箱
  2. 并发采集执行前基线 (before snapshots) + 安装监控工具
  3. 启动多层实时探针（inotify / net / proc）
  4. 执行待测命令（带超时）
  5. 并发采集执行后快照 (after snapshots) + 探针数据
  6. Before/After 差值分析（所有维度）
  7. 生成报告

判定依据: 完全基于执行前后的状态变化，不做任何命令字符串的静态分析。
"""
from __future__ import annotations

import asyncio
import os
import re
import time
from datetime import timedelta

from opensandbox import Sandbox
from opensandbox.config import ConnectionConfig

from .diff_analysis import DiffAnalyzer
from .patterns import ARTIFACT_PATTERNS
from .report import build_report, save_reports, generate_text_summary, generate_recommendations
from .sandbox_ops import (
    collect_all_snapshots, start_probes, collect_probe_results, run_cmd,
)
from .scoring import ScoringEngine, ScoringConfig

W = 76


def _section(title: str) -> None:
    print(f"\n{'='*W}\n  {title}\n{'='*W}", flush=True)


def _sub(title: str) -> None:
    print(f"\n  --- {title} ---", flush=True)


async def run_analysis(
    command: str,
    port: int,
    image: str,
    report_dir: str,
    config: ScoringConfig,
) -> dict:
    """
    完整行为分析主流程。

    判定依据完全来自 before_snap 与 after_snap 的差异，
    以及探针在执行期间捕获的实时事件。
    """
    conn_config = ConnectionConfig(
        domain=f"localhost:{port}",
        request_timeout=timedelta(seconds=600),
    )
    engine = ScoringEngine(config)

    # ── 1. 创建沙箱 ──────────────────────────────────────────────────────
    _section("1/6  创建隔离沙箱")
    print(f"  镜像: {image}", flush=True)
    try:
        sandbox = await asyncio.wait_for(
            Sandbox.create(image, connection_config=conn_config,
                           timeout=timedelta(minutes=10)),
            timeout=120,
        )
    except asyncio.TimeoutError:
        print("  !! 创建超时 (120s).")
        raise SystemExit(1)
    except Exception as e:
        print(f"  !! 创建失败: {e}")
        raise SystemExit(1)
    print(f"  Sandbox ID: {sandbox.id}")

    async with sandbox:
        # ── 2. 安装工具 + 并发采集前置基线 ──────────────────────────────
        _section("2/6  安装监控工具 + 并发采集执行前基线")
        t0 = time.time()

        # 安装工具与采集基线并发执行（安装过程中基线数据不受影响）
        install_task = asyncio.create_task(
            run_cmd(sandbox,
                "apt-get update -qq 2>/dev/null && "
                "apt-get install -y -qq inotify-tools procps 2>/dev/null || "
                "yum install -y -q inotify-tools procps-ng 2>/dev/null || "
                "apk add inotify-tools procps 2>/dev/null || "
                "echo 'skip'", timeout_sec=120)
        )
        before_snap_task = asyncio.create_task(collect_all_snapshots(sandbox))

        await install_task
        before_snap = await before_snap_task

        print(f"  文件数       : {len(before_snap['fs'])}")
        print(f"  SUID/SGID    : {len(before_snap['suid'])}")
        print(f"  符号链接     : {len(before_snap['symlinks'])}")
        print(f"  文件能力     : {len(before_snap['file_caps'])}")
        print(f"  基线采集耗时 : {time.time()-t0:.1f}s")

        try:
            pre_m = await sandbox.get_metrics()
            print(f"  CPU          : {pre_m.cpu_used_percentage:.1f}%")
            print(f"  Memory       : {pre_m.memory_used_in_mib:.1f}/"
                  f"{pre_m.memory_total_in_mib:.1f} MiB")
        except Exception:
            pre_m = None

        # ── 3. 启动探针 + 执行命令 ────────────────────────────────────────
        _section("3/6  启动多层实时探针 + 执行待测命令")

        resolv_before = await start_probes(sandbox)
        print("  [探针1] inotify: 系统目录 (/usr /etc /root /home)")
        print("  [探针2] inotify: 临时目录 (/tmp /var/tmp /dev/shm)")
        print("  [探针3] network: /proc/net/tcp 轮询 (0.5s 间隔)")
        print("  [探针4] DNS    : /etc/resolv.conf 基线快照")
        print("  [探针5] process: 进程树轮询 (1s 间隔)")

        print(f"\n  $ {command}")
        print(f"  {'─'*60}", flush=True)
        t1 = time.time()
        wrapped_cmd = f"{{ {command} ; }}; echo \"__EXIT_CODE__$?\""
        stdout_raw, stderr = await run_cmd(sandbox, wrapped_cmd, timeout_sec=300)
        dur = time.time() - t1

        # 提取退出码
        exit_code = -1
        stdout = stdout_raw
        if "__EXIT_CODE__" in stdout_raw:
            lines_ = stdout_raw.splitlines()
            for i, line_ in enumerate(lines_):
                if line_.startswith("__EXIT_CODE__"):
                    try:
                        exit_code = int(line_.replace("__EXIT_CODE__", ""))
                    except ValueError:
                        pass
                    stdout = "\n".join(lines_[:i])
                    break

        stdout_lines = stdout.splitlines() if stdout else []
        stderr_lines = stderr.splitlines() if stderr else []
        print(f"\n  耗时   : {dur:.1f}s")
        print(f"  退出码 : {exit_code}")
        if stdout_lines:
            _sub("stdout (前 50 行)")
            for l in stdout_lines[:50]:
                print(f"    | {l}")
            if len(stdout_lines) > 50:
                print(f"    | ... ({len(stdout_lines)-50} more)")
        if stderr_lines:
            _sub("stderr (前 20 行)")
            for l in stderr_lines[:20]:
                print(f"    | {l}")

        # ── 4. 采集执行后快照 ─────────────────────────────────────────────
        _section("4/6  采集执行后快照 + 探针数据 (并发)")
        await asyncio.sleep(2)  # 等待短命进程退出

        after_snap, probes_data = await asyncio.gather(
            collect_all_snapshots(sandbox),
            collect_probe_results(sandbox),
        )
        probes_data["resolv_before"] = resolv_before

        try:
            post_m = await sandbox.get_metrics()
        except Exception:
            post_m = None

        print(f"  文件数       : {len(after_snap['fs'])}")
        if pre_m and post_m:
            cpu_delta = post_m.cpu_used_percentage - pre_m.cpu_used_percentage
            mem_delta = post_m.memory_used_in_mib - pre_m.memory_used_in_mib
            print(f"  CPU delta    : {cpu_delta:+.1f}%")
            print(f"  Memory delta : {mem_delta:+.1f} MiB")
            if post_m.cpu_used_percentage > 80:
                engine.add("WARN", "资源",
                    f"CPU 异常高 ({post_m.cpu_used_percentage:.1f}%)",
                    15, [], f"CPU: {post_m.cpu_used_percentage:.1f}%")
            if mem_delta > 200:
                engine.add("WARN", "资源",
                    f"内存异常增长 (+{mem_delta:.0f} MiB)",
                    10, [], f"Memory delta: {mem_delta:.0f} MiB")

        # ── 5. Before/After 差值分析 ──────────────────────────────────────
        _section("5/6  Before/After 差值分析")

        diff = DiffAnalyzer(
            engine=engine,
            before=before_snap,
            after=after_snap,
            probes=probes_data,
            stdout=stdout,
            stderr=stderr,
        )
        diff.precompute_diffs()

        # D1: 文件变更
        _sub("[D1] 文件变更 (before vs after)")
        file_result = diff.analyze_file_changes()
        new_paths = file_result["new"]
        del_paths = file_result["deleted"]
        print(f"    新增 {len(new_paths)} 个 / 删除 {len(del_paths)} 个")
        for p in new_paths[:20]:
            print(f"      + {p}")
        if len(new_paths) > 20:
            print(f"      ... 还有 {len(new_paths)-20} 个")
        if file_result["suspicious"]:
            print(f"    !! 敏感路径写入: {file_result['suspicious'][:5]}")
        else:
            print("    PASS  无敏感路径写入" if not new_paths else "")

        # D2: 实时事件
        _sub("[D2] 实时文件事件 (执行期间捕获)")
        inotify_result = diff.analyze_inotify()
        sys_events = inotify_result["sys"]
        tmp_events = inotify_result["tmp"]
        if sys_events:
            print(f"    系统目录事件 ({len(sys_events)} 条):")
            for l in sys_events[:30]:
                print(f"      {l}")
        else:
            print("    系统目录: (无事件)")
        if tmp_events:
            print(f"    临时目录事件 ({len(tmp_events)} 条):")
            for l in tmp_events[:15]:
                print(f"      {l}")

        # D3: 用户/权限
        _sub("[D3] 用户与权限 (before vs after)")
        auth_changed = diff.analyze_auth()
        if auth_changed:
            # 显示具体变更行
            pre_lines = set(before_snap["auth"].strip().splitlines())
            post_lines = set(after_snap["auth"].strip().splitlines())
            added = post_lines - pre_lines
            removed = pre_lines - post_lines
            for line in list(added)[:5]:
                print(f"      + {line}")
            for line in list(removed)[:5]:
                print(f"      - {line}")
        else:
            print("    PASS  无变化")

        # D4: 持久化
        _sub("[D4] 持久化机制 (before vs after)")
        persist_result = diff.analyze_persistence()
        if persist_result["changed"]:
            print(f"    !! 变更: {', '.join(persist_result['sections'])}")
            if persist_result["cron_d"]:
                print(f"    !! cron.d 恶意内容: {', '.join(persist_result['cron_d'])}")
        else:
            print("    PASS  无变化")

        # D5: Shell 环境
        _sub("[D5] Shell 配置 (before vs after)")
        shell_changed = diff.analyze_shell_env()
        if shell_changed:
            print("    !! Shell 配置被修改")
            shell_after, _ = await run_cmd(sandbox,
                "cat ~/.bashrc ~/.bash_profile ~/.profile 2>/dev/null | tail -15")
            for l in shell_after.splitlines()[:15]:
                print(f"      {l}")
        else:
            print("    PASS  无变化")

        # D6: 网络行为
        _sub("[D6] 网络行为 (执行前基线 vs 执行期间新增连接)")
        net_result = diff.analyze_network()
        if net_result["external"]:
            for ip, port in sorted(net_result["external"]):
                label = "HTTPS" if port == 443 else "HTTP" if port == 80 else f":{port}"
                c2_flag = " !! C2端口" if port in {4444, 5555, 6666, 7777, 8888, 9999,
                                                     1234, 31337, 12345, 4443, 8443} else ""
                print(f"    -> {ip}:{port} ({label}){c2_flag}")
        else:
            print("    (无外部连接)")

        # D7: DNS
        _sub("[D7] DNS 配置 (before vs after)")
        dns_changed = diff.analyze_dns()
        if dns_changed:
            print("    !! /etc/resolv.conf 被修改")
            print(f"      before: {probes_data.get('resolv_before', '')[:80]}")
            print(f"      after:  {probes_data['resolv_after'][:80]}")
        else:
            print("    PASS  未被修改")

        # D8: 可疑二进制（临时目录可执行文件）
        _sub("[D8] 临时目录可执行文件 (after 快照)")
        sus, _ = await run_cmd(sandbox,
            "find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null "
            "| grep -vE '/[0-9a-f]{32}\\.(stdout|stderr)$' "
            "| grep -vE '/(\\.|execd)' "
            "|| echo none")
        sus_clean = sus.strip()
        if sus_clean and sus_clean != "none":
            sus_files = [f for f in sus_clean.splitlines() if f.strip()]
            if sus_files:
                engine.add("WARN", "可疑二进制",
                    f"临时目录可执行文件: {sus_files}",
                    25, ["T1105"], sus_clean[:300])
                for f in sus_files[:5]:
                    print(f"    !! {f}")
                    meta, _ = await run_cmd(sandbox, f"file '{f}' 2>/dev/null", 5)
                    if meta.strip():
                        print(f"       {meta.strip()}")
            else:
                print("    PASS")
        else:
            print("    PASS")

        # D9: SUID/SGID
        _sub("[D9] SUID/SGID 变更 (before vs after)")
        suid_result = diff.analyze_suid()
        new_suid = suid_result["added"]
        removed_suid = suid_result["removed"]
        if new_suid:
            for f in list(new_suid)[:5]:
                print(f"    !! + {f}")
        else:
            print("    PASS  无新增 SUID/SGID 文件")

        # D10: 内核模块
        _sub("[D10] 内核模块 (before vs after)")
        modules_changed = diff.analyze_modules()
        print("    PASS  无变化" if not modules_changed else "    !! 内核模块已变更!")

        # D11: 挂载点
        _sub("[D11] 挂载点 (before vs after)")
        mounts_changed = diff.analyze_mounts()
        print("    PASS  无变化" if not mounts_changed else "    !! 挂载点已变更!")

        # D12: 环境变量
        _sub("[D12] 安全相关环境变量 (before vs after)")
        new_envs = diff.analyze_env_vars()
        if new_envs:
            for e in new_envs[:5]:
                prefix = "!!" if "LD_PRELOAD" in e else "  "
                print(f"    {prefix} {e}")
        else:
            print("    PASS  无变化")

        # D13: 关键二进制完整性
        _sub("[D13] 关键系统二进制完整性 (before vs after)")
        bins_changed = diff.analyze_binary_integrity()
        if bins_changed:
            pre_bin_set = set(before_snap["bins"].strip().splitlines())
            post_bin_set = set(after_snap["bins"].strip().splitlines())
            for line in (post_bin_set - pre_bin_set)[:5]:
                print(f"    !! 变更: {line}")
        else:
            print("    PASS  关键二进制均未被篡改")

        # D14: 符号链接
        _sub("[D14] 符号链接变更 (before vs after)")
        symlink_result = diff.analyze_symlinks()
        new_symlinks = symlink_result["new"]
        if symlink_result["dangerous"]:
            for l in list(symlink_result["dangerous"])[:5]:
                print(f"    !! {l}")
        elif new_symlinks:
            print(f"    [INFO] 新增 {len(new_symlinks)} 个符号链接 (非敏感目标)")
        else:
            print("    PASS  无新增符号链接")

        # D15: 文件能力
        _sub("[D15] 文件能力 (before vs after)")
        new_caps = diff.analyze_file_caps()
        if new_caps:
            for c in list(new_caps)[:5]:
                print(f"    !! + {c}")
        else:
            print("    PASS  无新增文件能力")

        # D16: 新增/变更文件内容扫描（行为产物）
        _sub("[D16] 新增文件内容扫描 (before→after 确认的新增文件)")
        new_file_contents: dict[str, str] = {}
        # 读取 shell 配置变更后内容
        if shell_changed:
            shell_content, _ = await run_cmd(sandbox,
                "cat ~/.bashrc ~/.bash_profile ~/.profile /etc/profile "
                "/etc/bash.bashrc /etc/environment 2>/dev/null || true")
            new_file_contents["shell_after"] = shell_content
        # 读取新增的脚本/配置文件
        for path in new_paths[:20]:
            if any(path.endswith(ext) for ext in [
                ".sh", ".py", ".pl", ".rb", ".php",
                ".service", ".conf", ".cfg", ".txt",
            ]):
                fc, _ = await run_cmd(sandbox, f"head -50 '{path}' 2>/dev/null || true", 5)
                if fc.strip():
                    new_file_contents[path] = fc

        artifact_hits = diff.analyze_artifacts(shell_changed, new_file_contents)
        if artifact_hits:
            for hit in artifact_hits[:5]:
                print(f"    !! {hit}")
        else:
            print("    PASS  未发现恶意内容")

        # D17: 输出内容分析
        _sub("[D17] 命令输出分析 (敏感数据泄露)")
        output_issues = diff.analyze_output()
        if output_issues:
            for issue in output_issues:
                print(f"    !! {issue}")
        else:
            print("    PASS  输出无敏感信息")

        # D18: 高熵文件（仅新增文件）
        _sub("[D18] 新增文件熵分析 (before→after 确认的新增文件)")
        high_entropy = await diff.analyze_entropy(sandbox, config.entropy_threshold)
        if high_entropy:
            for path, ent in high_entropy:
                print(f"    !! {path} (entropy: {ent}/8.0)")
        else:
            print("    PASS  无异常高熵文件")

        # D19: 进程树（执行期间）
        _sub("[D19] 进程树 (执行期间探针捕获)")
        proc_tree = probes_data["proc_tree"]
        observed_cmds: set[str] = set()
        for l in proc_tree.splitlines():
            if l.startswith("=== ") or not l.strip():
                continue
            parts = l.split(None, 10)
            if len(parts) >= 11:
                cmd_str = parts[10]
                if not any(x in cmd_str for x in [
                    "inotifywait", ".net_poll", ".proc_tree",
                    "sleep 0.5", "sleep 1", "ps aux",
                ]):
                    observed_cmds.add(cmd_str[:120])
        if observed_cmds:
            print(f"    执行期间观察到 {len(observed_cmds)} 个独立进程:")
            for c in sorted(observed_cmds)[:10]:
                print(f"      > {c}")
        else:
            print("    (无额外进程)")

        # D20: 隐藏进程
        _sub("[D20] 隐藏进程检测 (/proc vs ps 差异)")
        proc_pids, _ = await run_cmd(sandbox,
            "ls -d /proc/[0-9]* 2>/dev/null | sed 's|/proc/||' | sort -n", 10)
        ps_pids, _ = await run_cmd(sandbox,
            "ps -eo pid --no-headers 2>/dev/null | tr -d ' ' | sort -n", 10)
        proc_set = set(proc_pids.strip().splitlines()) if proc_pids.strip() else set()
        ps_set = set(ps_pids.strip().splitlines()) if ps_pids.strip() else set()
        hidden = {p for p in (proc_set - ps_set) if p.strip() and p.strip().isdigit()}
        if len(hidden) > config.hidden_proc_tolerance:
            engine.add("WARN", "隐藏进程",
                f"检测到 {len(hidden)} 个 /proc 存在但 ps 不可见的进程",
                20, ["T1564.001"], str(sorted(hidden)[:20]))
            print(f"    !! {len(hidden)} 个潜在隐藏进程")
        else:
            print("    PASS  未发现隐藏进程")

        # D21: 敏感文件权限
        _sub("[D21] 敏感文件权限 (after 快照)")
        perm_check, _ = await run_cmd(sandbox,
            "stat -c '%a %n' /etc/passwd /etc/shadow /etc/sudoers "
            "/etc/ssh/sshd_config /usr/bin/sudo /bin/su "
            "/usr/bin/passwd 2>/dev/null | sort || true", 10)
        perm_issues = []
        for line in perm_check.splitlines():
            parts = line.strip().split(" ", 1)
            if len(parts) != 2:
                continue
            perm, path = parts
            try:
                if "shadow" in path and int(perm, 8) > 0o640:
                    perm_issues.append(f"{path} 权限过宽: {perm}")
                if "sudoers" in path and perm not in ("440", "0440"):
                    perm_issues.append(f"{path} 权限异常: {perm} (应为 440)")
                if path.endswith("/passwd") and int(perm, 8) & 0o022:
                    perm_issues.append(f"{path} 全局可写: {perm}")
            except ValueError:
                pass
        if perm_issues:
            engine.add("WARN", "文件权限",
                f"发现 {len(perm_issues)} 个权限异常",
                15, ["T1222.002"], "\n".join(perm_issues))
            for pc in perm_issues[:5]:
                print(f"    !! {pc}")
        else:
            print("    PASS  敏感文件权限正常")

        # D22: 攻击链关联（汇总所有维度的发现）
        _sub("[D22] 攻击链关联分析")
        attack_chains = diff.analyze_attack_chains()
        if attack_chains:
            for chain in attack_chains:
                print(f"    !! {chain}")
        else:
            print("    PASS  未检测到攻击链组合")

        # ── 6. 综合判定 ───────────────────────────────────────────────────
        _section("6/6  综合判定")
        mitre_map = engine.mitre_summary()
        tactic_map = engine.tactic_summary()
        verdict = engine.verdict()
        score = engine.total_score()
        confidence = engine.confidence()
        criticals = [f for f in engine.findings if f.severity == "CRITICAL"]
        warns = [f for f in engine.findings if f.severity == "WARN"]
        infos = [f for f in engine.findings if f.severity == "INFO"]

        if mitre_map:
            print("  MITRE ATT&CK 映射:")
            for tid, info_data in sorted(mitre_map.items()):
                print(f"    [{tid}] {info_data['name']}")
                for f_desc in info_data["findings"][:2]:
                    print(f"      └─ {f_desc}")

        sym_map = {"DANGEROUS": "!!", "SUSPICIOUS": "??",
                   "LOW_RISK": "~~", "LIKELY_SAFE": "OK"}
        sym = sym_map.get(verdict, "??")
        bar_len = 40
        filled = int(score / 100 * bar_len)
        bar = "█" * filled + "░" * (bar_len - filled)

        print(f"""
  +{'─'*(W-2)}+
  |  [{sym}] 判定: {verdict:20s}  风险评分: {score:3d}/100            |
  |  [{bar}]                              |
  |  置信度: {confidence:6s}  发现: {len(criticals)} critical / {len(warns)} warn / {len(infos)} info  |
  +{'─'*(W-2)}+
""")
        print(f"  命令         : {command}")
        print(f"  退出码       : {exit_code}")
        print(f"  文件 +/-     : +{len(new_paths)} / -{len(del_paths)}")
        print(f"  外部连接     : {len(diff._external_conns)} 个")
        print(f"  SUID 新增    : {len(new_suid)}")
        print(f"  执行耗时     : {dur:.1f}s")
        print(f"  ATT&CK 战术  : {', '.join(sorted(tactic_map.keys())) or '无'}")

        if engine.findings:
            print("\n  详细发现 (按严重程度):")
            for f in sorted(engine.findings,
                           key=lambda x: {"CRITICAL": 0, "WARN": 1, "INFO": 2}[x.severity]):
                icons = {"CRITICAL": "!!!", "WARN": " ! ", "INFO": " i "}[f.severity]
                mitre_str = f" [{','.join(f.mitre_ids)}]" if f.mitre_ids else ""
                print(f"    [{icons}] [{f.dimension}] {f.description}{mitre_str} (+{f.score})")
        else:
            print("\n  全部维度检查通过，命令行为安全。")

        recommendations = generate_recommendations(verdict, engine)
        print("\n  安全建议:")
        for rec in recommendations:
            print(f"    -> {rec}")

        # ── 构建并保存报告 ────────────────────────────────────────────────
        exec_info = {
            "t_start": t1,
            "duration": dur,
            "exit_code": exit_code,
            "stdout_lines": stdout_lines,
            "stderr_lines": stderr_lines,
        }

        report = build_report(
            command=command,
            engine=engine,
            diff_analyzer=diff,
            probes=probes_data,
            exec_info=exec_info,
            new_paths=new_paths,
            del_paths=del_paths,
            new_suid=new_suid,
            removed_suid=removed_suid,
            new_symlinks=new_symlinks,
            new_caps=new_caps,
            external_conns=diff._external_conns,
            high_entropy_files=high_entropy,
            sys_events=sys_events,
            tmp_events=tmp_events,
            attack_chains=attack_chains,
        )

        json_path, txt_path, sarif_path = save_reports(report, report_dir)
        print(f"\n  报告 (JSON) : {json_path}")
        print(f"  报告 (文本) : {txt_path}")
        print(f"  报告 (SARIF): {sarif_path}")

        summary = generate_text_summary(report)
        print(f"\n{'='*W}")
        print("  分析摘要:")
        print(f"{'='*W}")
        for line in summary.splitlines():
            print(f"  {line}")
        print()

        await sandbox.kill()
        print("  沙箱已销毁。\n")

        return report
