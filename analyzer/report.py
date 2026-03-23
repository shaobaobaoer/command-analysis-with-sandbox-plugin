"""
report.py — 报告生成模块

支持格式:
  - JSON (完整报告)
  - TXT (人类可读摘要)
  - SARIF v2.1.0 (CI/CD 集成)
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .patterns import MITRE
from .scoring import ScoringEngine

if TYPE_CHECKING:
    pass


def generate_text_summary(report: dict) -> str:
    """生成人类可读的分析摘要"""
    v = report["verdict"]
    score = report["risk_score"]
    conf = report.get("confidence", "N/A")
    cmd = report["command"]
    findings = report.get("findings", [])
    recs = report.get("recommendations", [])
    tactics = report.get("mitre_tactics", {})

    icon_map = {
        "DANGEROUS":   "[!!]",
        "SUSPICIOUS":  "[??]",
        "LOW_RISK":    "[~~]",
        "LIKELY_SAFE": "[OK]",
    }
    icon = icon_map.get(v, "[?]")

    lines = []
    lines.append(f"{icon} 判定: {v} (风险分: {score}/100, 置信度: {conf})")
    lines.append(f"命令: {cmd[:120]}")
    lines.append("")

    if findings:
        criticals = [f for f in findings if f.get("severity") == "CRITICAL"]
        warns = [f for f in findings if f.get("severity") == "WARN"]
        lines.append(f"发现 {len(findings)} 个问题 ({len(criticals)} 严重, {len(warns)} 警告):")
        for f in sorted(findings,
                        key=lambda x: {"CRITICAL": 0, "WARN": 1, "INFO": 2}.get(
                            x.get("severity", "INFO"), 3))[:8]:
            sev = f.get("severity", "?")
            dim = f.get("dimension", "?")
            desc = f.get("description", "?")
            mitre = ", ".join(m["id"] for m in f.get("mitre_attack", []))
            mitre_str = f" [{mitre}]" if mitre else ""
            lines.append(f"  [{sev}] {dim}: {desc}{mitre_str}")
        if len(findings) > 8:
            lines.append(f"  ... 还有 {len(findings)-8} 个发现")
    else:
        lines.append("全部维度检查通过，命令行为安全。")

    if tactics:
        lines.append("")
        lines.append(f"涉及 ATT&CK 战术: {', '.join(sorted(tactics.keys()))}")

    if recs:
        lines.append("")
        lines.append("建议:")
        for rec in recs[:3]:
            lines.append(f"  * {rec}")

    return "\n".join(lines)


def generate_recommendations(verdict: str, engine: ScoringEngine) -> list[str]:
    """根据动态分析结果生成可操作的安全建议"""
    findings = engine.findings
    confidence = engine.confidence()
    recs = []
    finding_dims = set(f.dimension for f in findings)
    finding_descs = " ".join(f.description for f in findings).lower()

    if verdict == "DANGEROUS":
        recs.append("BLOCK: 强烈建议阻止此命令执行")
        if "持久化" in finding_dims or "持久化内容" in finding_dims:
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
            recs.append("多维度攻击已确认，建议全面安全审计")
    elif verdict == "SUSPICIOUS":
        recs.append("REVIEW: 建议人工审核此命令后再决定是否放行")
        if confidence == "LOW":
            recs.append("置信度较低，请结合上下文判断")
    elif verdict == "LOW_RISK":
        recs.append("ALLOW: 风险较低，可考虑放行但建议记录审计日志")
    else:
        recs.append("ALLOW: 命令行为安全，可放行")

    return recs


def generate_sarif(report: dict) -> dict:
    """转换为 SARIF v2.1.0 格式"""
    severity_map = {"CRITICAL": "error", "WARN": "warning", "INFO": "note"}
    rules = []
    results = []
    rule_ids: set[str] = set()

    for i, finding in enumerate(report.get("findings", [])):
        mitre_ids = [m["id"] for m in finding.get("mitre_attack", [])]
        rule_id = mitre_ids[0] if mitre_ids else f"CMD-{i+1:03d}"
        if rule_id in rule_ids:
            rule_id = f"{rule_id}-{i}"
        rule_ids.add(rule_id)

        rule = {
            "id": rule_id,
            "name": finding.get("dimension", "Unknown"),
            "shortDescription": {"text": finding.get("description", "")[:256]},
            "helpUri": (
                f"https://attack.mitre.org/techniques/{mitre_ids[0].replace('.', '/')}"
                if mitre_ids else ""
            ),
            "properties": {
                "tags": ["security", "sandbox-behavioral-analysis"]
                        + [f"mitre/{m}" for m in mitre_ids],
            },
        }
        if mitre_ids:
            rule["help"] = {
                "text": "MITRE ATT&CK: " + ", ".join(
                    f"{m} ({MITRE.get(m, '')})" for m in mitre_ids
                )
            }
        rules.append(rule)

        result = {
            "ruleId": rule_id,
            "level": severity_map.get(finding.get("severity", "INFO"), "note"),
            "message": {"text": finding.get("description", "")},
            "properties": {
                "risk_score": finding.get("risk_score", 0),
                "dimension": finding.get("dimension", ""),
            },
        }
        if finding.get("evidence"):
            result["properties"]["evidence"] = finding["evidence"][:500]
        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Command Safety Analyzer",
                    "version": report.get("version", "5.0"),
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


def save_reports(report: dict, report_dir: str) -> tuple[str, str, str]:
    """保存 JSON + TXT + SARIF 三份报告"""
    ts = int(time.time())
    base = os.path.join(report_dir, f"safety_report_{ts}")

    json_path = f"{base}.json"
    txt_path = f"{base}.txt"
    sarif_path = f"{base}.sarif.json"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(generate_text_summary(report))

    with open(sarif_path, "w", encoding="utf-8") as f:
        json.dump(generate_sarif(report), f, indent=2, ensure_ascii=False, default=str)

    return json_path, txt_path, sarif_path


def build_report(
    command: str,
    engine: ScoringEngine,
    diff_analyzer,
    probes: dict,
    exec_info: dict,
    new_paths: list,
    del_paths: list,
    new_suid: set,
    removed_suid: set,
    new_symlinks: set,
    new_caps: set,
    external_conns: set,
    high_entropy_files: list,
    sys_events: list,
    tmp_events: list,
    attack_chains: list,
) -> dict:
    """构建完整的分析报告"""
    verdict = engine.verdict()
    score = engine.total_score()
    confidence = engine.confidence()
    mitre_map = engine.mitre_summary()
    tactic_map = engine.tactic_summary()
    recommendations = generate_recommendations(verdict, engine)
    criticals = [f for f in engine.findings if f.severity == "CRITICAL"]
    warns = [f for f in engine.findings if f.severity == "WARN"]
    infos = [f for f in engine.findings if f.severity == "INFO"]
    dur = exec_info.get("duration", 0)
    exit_code = exec_info.get("exit_code", -1)

    report = {
        "version": "5.0",
        "command": command,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "risk_score": score,
        "confidence": confidence,
        "recommendations": recommendations,
        "findings_summary": {
            "total": len(engine.findings),
            "critical": len(criticals),
            "warn": len(warns),
            "info": len(infos),
            "dimensions_hit": len(set(f.dimension for f in engine.findings)),
        },
        "findings": [f.to_dict() for f in engine.findings],
        "evidence": diff_analyzer.evidence,
        "dimensions": {
            "files_added": new_paths[:300],
            "files_deleted": del_paths[:50],
            "inotify_sys_events": sys_events[:300],
            "inotify_tmp_events": tmp_events[:100],
            "external_connections": [f"{ip}:{p}" for ip, p in sorted(external_conns)],
            "suid_new": list(new_suid)[:50],
            "suid_removed": list(removed_suid)[:50],
            "new_symlinks": list(new_symlinks)[:50] if new_symlinks else [],
            "new_file_caps": list(new_caps)[:50] if new_caps else [],
            "critical_bins_tampered": diff_analyzer.evidence.get("critical_bins_changed", False),
            "high_entropy_files": high_entropy_files,
            "exit_code": exit_code,
            "attack_chains": attack_chains,
        },
        "mitre_attack": {
            tid: {"name": info_data["name"], "findings": info_data["findings"]}
            for tid, info_data in mitre_map.items()
        },
        "mitre_tactics": {
            tactic: sorted(set(tids))
            for tactic, tids in tactic_map.items()
        },
        "timeline": [
            {"phase": "baseline",      "desc": "执行前基线采集完成"},
            {"phase": "probes_start",  "desc": "探针启动 + 命令开始执行"},
            {"phase": "exec_end",      "desc": f"命令执行结束 (耗时 {dur:.1f}s, 退出码 {exit_code})"},
            {"phase": "post_snapshot", "desc": "执行后快照 + 差值分析完成"},
        ],
        "stdout": exec_info.get("stdout_lines", [])[:100],
        "stderr": exec_info.get("stderr_lines", [])[:50],
    }

    report["text_summary"] = generate_text_summary(report)
    return report
