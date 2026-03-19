# Command Safety Analyzer with OpenSandbox — v4

在 OpenSandbox 隔离沙箱中运行命令，通过 **23 维度深度行为分析** + **MITRE ATT&CK 映射 (40+ 技术)** + **加权评分 + 攻击链关联** 判断命令安全性。

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
├── checker.sh          # 单命令深度检测器 (OpenSandbox 沙箱 + 23 维度分析)
├── run_all.sh          # 批量运行 + Git 自动提交 + 性能分析 + 重试
├── samples/
│   ├── white.jsonl     # 白样本 30 条 (安全命令)
│   └── black.jsonl     # 黑样本 30 条 (恶意命令)
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

## 23 维度检测体系

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

## 报告格式 (v4)

```json
{
  "version": "4.0",
  "command": "...",
  "verdict": "DANGEROUS",
  "risk_score": 75,
  "confidence": "HIGH",
  "is_legitimate_pattern": false,
  "findings_summary": {
    "total": 5,
    "critical": 3,
    "warn": 2,
    "info": 0,
    "dimensions_hit": 4
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "dimension": "攻击链",
      "description": "检测到恶意软件部署链",
      "risk_score": 15,
      "mitre_attack": [{"id": "T1105", "name": "..."}],
      "evidence": "..."
    }
  ],
  "mitre_attack": {"T1546.004": {"name": "...", "findings": ["..."]}},
  "mitre_tactics": {
    "Persistence": ["T1053.003", "T1546.004"],
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

## v3 -> v4 变更

- 检测维度: 19 -> 23 (新增: 计划任务差异/隐藏进程/信号处理/攻击链关联)
- 恶意模式: 50+ -> 70+ (新增: LotL/进程伪装/时间戳篡改/编译后门/网络隧道)
- 合法白名单: 12 -> 30+ (新增: docker/go/make/terraform/ansible 等)
- MITRE 映射: 30+ -> 40+ 技术
- 评分引擎: 新增置信度评估 + 攻击链加成
- 报告格式: v3.1 -> v4.0 (新增 confidence/findings_summary/mitre_tactics)
- 批量运行: 新增 --retry 重试参数
- 样本集: 20+20 -> 30+30 (新增边界案例/高级攻击/LotL)
