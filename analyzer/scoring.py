"""
scoring.py — 评分引擎、Finding 数据类、判定逻辑

核心设计:
  - Finding: 单条发现，包含严重度、维度、描述、分数、MITRE ID、证据
  - ScoringEngine: 加权评分 + 置信度 + 判定
  所有发现均来自沙箱执行前后的快照对比，没有静态评分。
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from .patterns import MITRE, TACTIC_MAP


@dataclass
class Finding:
    """单条行为发现"""
    severity: str           # CRITICAL / WARN / INFO
    dimension: str          # 检测维度（如"文件变更"、"持久化"等）
    description: str        # 发现描述
    score: int              # 风险分 (0-50)
    mitre_ids: list[str] = field(default_factory=list)
    evidence: str = ""

    def to_dict(self) -> dict:
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


class ScoringConfig:
    """评分阈值配置，可从 scoring.conf 加载"""
    def __init__(
        self,
        dangerous_threshold: int = 60,
        dangerous_criticals: int = 2,
        suspicious_threshold: int = 25,
        low_risk_threshold: int = 10,
        entropy_threshold: float = 6.5,
        hidden_proc_tolerance: int = 8,
    ):
        self.dangerous_threshold = dangerous_threshold
        self.dangerous_criticals = dangerous_criticals
        self.suspicious_threshold = suspicious_threshold
        self.low_risk_threshold = low_risk_threshold
        self.entropy_threshold = entropy_threshold
        self.hidden_proc_tolerance = hidden_proc_tolerance

    @classmethod
    def from_file(cls, path: str) -> "ScoringConfig":
        """从 scoring.conf 文件加载配置"""
        import os
        conf: dict[str, str] = {}
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, val = line.split("=", 1)
                        val = val.split("#")[0].strip()
                        conf[key.strip()] = val
        return cls(
            dangerous_threshold=int(conf.get("DANGEROUS_THRESHOLD", 60)),
            dangerous_criticals=int(conf.get("DANGEROUS_CRITICALS", 2)),
            suspicious_threshold=int(conf.get("SUSPICIOUS_THRESHOLD", 25)),
            low_risk_threshold=int(conf.get("LOW_RISK_THRESHOLD", 10)),
            entropy_threshold=float(conf.get("ENTROPY_THRESHOLD", 6.5)),
            hidden_proc_tolerance=int(conf.get("HIDDEN_PROC_TOLERANCE", 8)),
        )


class ScoringEngine:
    """加权风险评分引擎 — 所有发现来自沙箱行为对比"""

    def __init__(self, config: Optional[ScoringConfig] = None):
        self.config = config or ScoringConfig()
        self.findings: list[Finding] = []

    def add(
        self,
        severity: str,
        dimension: str,
        description: str,
        score: int,
        mitre_ids: Optional[list[str]] = None,
        evidence: str = "",
    ) -> None:
        self.findings.append(Finding(
            severity=severity,
            dimension=dimension,
            description=description,
            score=score,
            mitre_ids=mitre_ids or [],
            evidence=evidence,
        ))

    def total_score(self) -> int:
        return min(100, sum(f.score for f in self.findings))

    def verdict(self) -> str:
        score = self.total_score()
        criticals = [f for f in self.findings if f.severity == "CRITICAL"]
        chain_findings = [f for f in self.findings if f.dimension == "攻击链"]
        cfg = self.config
        if (score >= cfg.dangerous_threshold
                or len(criticals) >= cfg.dangerous_criticals
                or (chain_findings and criticals)):
            return "DANGEROUS"
        elif score >= cfg.suspicious_threshold or criticals:
            return "SUSPICIOUS"
        elif score >= cfg.low_risk_threshold:
            return "LOW_RISK"
        else:
            return "LIKELY_SAFE"

    def confidence(self) -> str:
        """评估判定的置信度 (HIGH/MEDIUM/LOW)"""
        criticals = len([f for f in self.findings if f.severity == "CRITICAL"])
        unique_dims = len(set(f.dimension for f in self.findings))
        chain_findings = len([f for f in self.findings if f.dimension == "攻击链"])
        verd = self.verdict()

        if verd == "DANGEROUS":
            if criticals >= 3 or (criticals >= 2 and unique_dims >= 3) or chain_findings >= 2:
                return "HIGH"
            elif criticals >= 1 and unique_dims >= 2:
                return "MEDIUM"
            else:
                return "LOW"
        elif verd == "SUSPICIOUS":
            return "HIGH" if unique_dims >= 3 else "MEDIUM" if unique_dims >= 2 else "LOW"
        elif verd == "LIKELY_SAFE":
            return "HIGH" if self.total_score() == 0 else "MEDIUM"
        else:  # LOW_RISK
            return "MEDIUM"

    def mitre_summary(self) -> dict:
        """汇总所有涉及的 MITRE ATT&CK 技术"""
        techniques: dict = {}
        for f in self.findings:
            for mid in f.mitre_ids:
                if mid not in techniques:
                    techniques[mid] = {"name": MITRE.get(mid, "Unknown"), "findings": []}
                techniques[mid]["findings"].append(f.description)
        return techniques

    def tactic_summary(self) -> dict:
        """按 ATT&CK 战术分组"""
        tactics: dict = defaultdict(list)
        for f in self.findings:
            for mid in f.mitre_ids:
                prefix = mid.split(".")[0]
                tactic = TACTIC_MAP.get(prefix, "Unknown")
                tactics[tactic].append(mid)
        return dict(tactics)
