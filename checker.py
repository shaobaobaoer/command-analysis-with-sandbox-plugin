#!/usr/bin/env python3
"""
checker.py — Command Safety Analyzer 主入口

基于沙箱执行前后快照对比的纯动态行为分析，不做任何静态分析。

用法:
    COMMAND="some command" python3 checker.py

环境变量:
    COMMAND        — 待检测命令
    COMMAND_B64    — base64 编码的命令（优先，解决多行命令问题）
    SANDBOX_PORT   — OpenSandbox 服务端口 (默认: 8080)
    SANDBOX_IMAGE  — 沙箱 Docker 镜像
    REPORT_DIR     — 报告输出目录
"""
from __future__ import annotations

import asyncio
import base64
import os
import sys


def _load_command() -> str:
    """从环境变量读取命令，支持 base64 编码传递"""
    if os.environ.get("COMMAND_B64"):
        try:
            return base64.b64decode(os.environ["COMMAND_B64"]).decode("utf-8")
        except Exception:
            pass
    cmd = os.environ.get("COMMAND") or os.environ.get("CHECK_COMMAND", "")
    if not cmd:
        print("[ERROR] 请设置 COMMAND 环境变量", file=sys.stderr)
        sys.exit(1)
    return cmd


def _patch_opensandbox_sdk() -> None:
    """修复 opensandbox SDK 在 metadata=null 时的 TypeError。

    服务端有时返回 "metadata": null，SDK 的 CreateSandboxResponseMetadata.from_dict()
    调用 dict(None) 导致 TypeError。直接补丁该方法使其将 None 视为空 dict。
    """
    try:
        from opensandbox.api.lifecycle.models.create_sandbox_response_metadata import (
            CreateSandboxResponseMetadata,
        )
        _orig = CreateSandboxResponseMetadata.from_dict.__func__  # type: ignore[attr-defined]

        @classmethod  # type: ignore[misc]
        def _safe_from_dict(cls, src_dict):
            if src_dict is None:
                src_dict = {}
            return _orig(cls, src_dict)

        CreateSandboxResponseMetadata.from_dict = _safe_from_dict  # type: ignore[method-assign]
    except Exception:
        pass  # SDK 版本不同时静默跳过


def main() -> None:
    _patch_opensandbox_sdk()
    command = _load_command()
    port = int(os.environ.get("SANDBOX_PORT", "8080"))
    image = os.environ.get("SANDBOX_IMAGE", "opensandbox/code-interpreter:v1.0.2")
    report_dir = os.environ.get("REPORT_DIR", os.getcwd())

    from analyzer.scoring import ScoringConfig
    conf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scoring.conf")
    config = ScoringConfig.from_file(conf_path)

    print("")
    print("=" * 78)
    print("  OpenSandbox Behavioral Analysis Engine v5")
    print("  判定依据: 沙箱执行前/后快照对比 (纯动态行为分析)")
    print("=" * 78)
    print(f"\n  待检测命令: {command}\n")

    from analyzer.engine import run_analysis
    asyncio.run(run_analysis(command, port, image, report_dir, config))


if __name__ == "__main__":
    main()
