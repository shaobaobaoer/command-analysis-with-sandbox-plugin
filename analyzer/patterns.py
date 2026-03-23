"""
patterns.py — MITRE ATT&CK 映射表 + 沙箱行为检测模式

注意: 这里的模式用于分析沙箱执行后的**行为产物**（新增文件内容、cron 变更内容、
输出内容等），不用于静态分析命令本身。
"""
from __future__ import annotations

# ═══════════════════════════════════════════════════════════════════════════
#  MITRE ATT&CK 技术映射表
# ═══════════════════════════════════════════════════════════════════════════
MITRE: dict[str, str] = {
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1053.003": "Scheduled Task/Job: Cron",
    "T1053.001": "Scheduled Task/Job: At",
    "T1053.005": "Scheduled Task/Job: Systemd Timers",
    "T1136.001": "Create Account: Local Account",
    "T1098":     "Account Manipulation",
    "T1543.002": "Create/Modify System Process: Systemd Service",
    "T1037.004": "Boot/Logon Init Scripts: RC Scripts",
    "T1546.004": "Event Triggered Execution: .bash_profile/.bashrc",
    "T1574.006": "Hijack Execution Flow: LD_PRELOAD",
    "T1574.001": "Hijack Execution Flow: DLL Search Order",
    "T1048":     "Exfiltration Over Alternative Protocol",
    "T1071.001": "Application Layer Protocol: Web",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1105":     "Ingress Tool Transfer",
    "T1070.003": "Indicator Removal: Clear Command History",
    "T1070.006": "Indicator Removal: Timestomp",
    "T1222.002": "File/Dir Permissions Modification: Linux",
    "T1548.001": "Abuse Elevation Control: Setuid/Setgid",
    "T1548.003": "Abuse Elevation: Sudo and Sudo Caching",
    "T1556":     "Modify Authentication Process",
    "T1554":     "Compromise Client Software Binary",
    "T1611":     "Escape to Host",
    "T1014":     "Rootkit",
    "T1082":     "System Information Discovery",
    "T1016":     "System Network Configuration Discovery",
    "T1496":     "Resource Hijacking (Cryptomining)",
    "T1027":     "Obfuscated Files or Information",
    "T1036":     "Masquerading",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1562.004": "Impair Defenses: Disable or Modify System Firewall",
    "T1021.004": "Remote Services: SSH",
    "T1140":     "Deobfuscate/Decode Files or Information",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1552.005": "Unsecured Credentials: Cloud Instance Metadata API",
    "T1564.001": "Hide Artifacts: Hidden Files and Directories",
    "T1055":     "Process Injection",
    "T1485":     "Data Destruction",
    "T1195":     "Supply Chain Compromise",
}

# MITRE 技术前缀 -> 战术映射
TACTIC_MAP: dict[str, str] = {
    "T1059": "Execution", "T1053": "Persistence", "T1543": "Persistence",
    "T1037": "Persistence", "T1546": "Persistence", "T1136": "Persistence",
    "T1098": "Persistence",
    "T1548": "Privilege Escalation", "T1574": "Privilege Escalation",
    "T1055": "Privilege Escalation",
    "T1070": "Defense Evasion", "T1027": "Defense Evasion",
    "T1036": "Defense Evasion", "T1014": "Defense Evasion",
    "T1562": "Defense Evasion", "T1564": "Defense Evasion",
    "T1140": "Defense Evasion",
    "T1556": "Credential Access", "T1552": "Credential Access",
    "T1082": "Discovery", "T1016": "Discovery",
    "T1048": "Exfiltration",
    "T1105": "Command and Control", "T1071": "Command and Control",
    "T1021": "Lateral Movement",
    "T1496": "Impact", "T1611": "Execution", "T1485": "Impact",
    "T1195": "Initial Access",
}

# ═══════════════════════════════════════════════════════════════════════════
#  沙箱行为产物检测模式
#
#  用途: 分析执行后捕获到的内容（新增文件内容、cron 变更、shell 配置变更等）
#  这些模式作用于沙箱内读取的文件/命令输出，而非命令字符串本身。
# ═══════════════════════════════════════════════════════════════════════════

# 新增文件/shell配置内容中的恶意行为模式
ARTIFACT_PATTERNS: list[tuple[str, str, str, int]] = [
    # 反弹 Shell 痕迹
    (r"/dev/tcp/\S+/\d+",              "reverse shell via /dev/tcp",           "T1059.004", 40),
    (r"bash\s+-i\s+>&",                "interactive bash reverse shell",        "T1059.004", 45),
    (r"nc\s+.*\s+/bin/(ba)?sh",        "netcat shell",                          "T1059.004", 45),
    (r"mkfifo.*\|.*/bin/sh",           "named pipe shell",                      "T1059.004", 40),
    (r"socat\s+exec:",                 "socat exec shell",                      "T1059.004", 40),
    # 下载执行
    (r"curl\s+.*\|\s*(ba)?sh",         "download and execute (curl|sh)",        "T1105",     35),
    (r"wget\s+.*\|\s*(ba)?sh",         "download and execute (wget|sh)",        "T1105",     35),
    # 凭据外泄
    (r"/etc/shadow",                   "shadow file reference",                 "T1048",     30),
    (r"base64.*\|\s*curl",             "base64 exfil via curl",                 "T1048",     35),
    # 持久化机制
    (r"authorized_keys",               "SSH authorized_keys manipulation",      "T1098",     30),
    (r"/etc/ld\.so\.preload",          "LD_PRELOAD hijack file",               "T1574.006", 40),
    (r"LD_PRELOAD=",                   "LD_PRELOAD injection",                  "T1574.006", 35),
    # 反取证
    (r"HISTFILE=/dev/null",            "disabling bash history",                "T1070.003", 20),
    (r"HISTSIZE=0",                    "zeroing history size",                  "T1070.003", 15),
    (r"ln\s+-sf?\s+/dev/null.*history","nulling history file",                  "T1070.003", 25),
    # 挖矿
    (r"(xmrig|stratum\+tcp|cryptonight|monero)", "cryptocurrency mining",       "T1496",     35),
    # PAM 后门
    (r"pam_permit",                    "PAM permit (auth bypass)",              "T1556",     40),
    # C2 回连
    (r"curl\s+.*http.*\|\s*(ba)?sh",  "curl C2 callback",                      "T1105",     35),
    (r"169\.254\.169\.254",            "cloud metadata access",                 "T1552.005", 35),
]

# cron.d 新增内容检测模式
CRON_ARTIFACT_PATTERNS: list[tuple[str, str, str, int]] = [
    (r"curl\s+.*\|\s*(ba)?sh",         "cron: curl|bash payload",               "T1053.003", 35),
    (r"wget\s+.*\|\s*(ba)?sh",         "cron: wget|bash payload",               "T1053.003", 35),
    (r"/dev/tcp/",                     "cron: reverse shell",                   "T1059.004", 45),
    (r"nc\s+.*-e\s+/bin/(ba)?sh",     "cron: netcat backdoor",                 "T1059.004", 45),
    (r"python[23]?\s+-c.*socket",      "cron: python socket",                   "T1059.004", 35),
    (r"mkfifo.*nc.*sh",                "cron: named pipe shell",                "T1059.004", 40),
    (r"base64\s+.*\|\s*(ba)?sh",       "cron: base64 payload",                  "T1027",     35),
]

# 命令输出内容检测模式（敏感数据泄露）
OUTPUT_PATTERNS: list[tuple[str, str, str, int]] = [
    (r"root:.*:0:0:",                               "passwd contents in output",  "T1048", 15),
    (r"\$[0-9]+\$[A-Za-z0-9./]+\$",                "password hash in output",    "T1048", 30),
    (r"ssh-rsa\s+AAAA",                             "SSH public key in output",   "T1082", 10),
    (r"BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY", "private key in output",      "T1048", 40),
]
