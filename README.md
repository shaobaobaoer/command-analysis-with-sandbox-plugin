# Command Safety Analyzer with OpenSandbox

在 OpenSandbox 隔离沙箱中运行命令，通过多维度行为对比判断命令是否安全。

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

# 国内镜像加速
REGISTRY_MIRROR="sandbox-registry.cn-zhangjiakou.cr.aliyuncs.com/opensandbox" ./run_all.sh
```

## 项目结构

```
├── checker.sh          # 单命令检测器 (OpenSandbox 沙箱)
├── run_all.sh          # 批量运行 + Git 自动提交
├── samples/
│   ├── white.jsonl     # 白样本 (安全命令)
│   └── black.jsonl     # 黑样本 (恶意命令)
├── reports/
│   ├── white/          # 白样本报告 (JSON + log)
│   ├── black/          # 黑样本报告
│   └── summary.jsonl   # 汇总结果
└── README.md
```

## 样本格式

`samples/*.jsonl` 每行一个 JSON:

```json
{"id": "w01", "label": "safe", "desc": "echo hello", "command": "echo 'hello world'"}
{"id": "b01", "label": "malicious", "desc": "reverse shell", "command": "echo 'bash -i >& ...' >> ~/.bashrc"}
```

- `id`: 唯一标识
- `label`: `safe` 或 `malicious` (期望判定)
- `desc`: 简短描述
- `command`: 待检测的命令

## 检测维度

| # | 维度 | 方法 |
|---|------|------|
| 1 | 文件变更 | 执行前后文件系统快照对比 |
| 2 | 实时文件事件 | inotifywait 监控关键目录 |
| 3 | 用户/权限 | /etc/passwd 用户列表对比 |
| 4 | 持久化 | cron/systemd/rc.local 对比 |
| 5 | Shell 环境 | .bashrc/.profile hash 对比 |
| 6 | 网络连接 | /proc/net/tcp 轮询捕获外部 IP |
| 7 | DNS 配置 | /etc/resolv.conf 变更检测 |
| 8 | 可疑二进制 | /tmp 等路径可执行文件扫描 |
| 9 | 资源消耗 | CPU / 内存指标 |

## 判定逻辑

- `LIKELY_SAFE` — 所有检查通过
- `SUSPICIOUS` — 存在 WARN 级发现
- `DANGEROUS` — 存在 CRITICAL 级发现

## 添加新样本

编辑 `samples/white.jsonl` 或 `samples/black.jsonl`，追加一行 JSON 即可。
