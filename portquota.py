#!/usr/bin/python3
import os, sys, time, subprocess, json, argparse, re, datetime
try:
    import tomllib  # py3.11+
except Exception as e:
    print("Python 3.11+ with tomllib is required.", file=sys.stderr)
    sys.exit(1)

FAMILY = "inet"
TABLE = "traffic"
INGRESS = "ingress"
EGRESS = "egress"

def run(cmd, input_text=None):
    return subprocess.run(cmd, input=input_text, text=True, capture_output=True)

def nft_f(rules_text):
    return run(["nft","-f","-"], input_text=rules_text)

def sync_rules(cfg: dict):
    """
    幂等：清空我们自建链，再按配置精确下发一次规则。
    避免重复规则导致的多次计数。
    """
    g = cfg.get("general", {})
    exclude_ifaces = g.get("exclude_ifaces", ["lo", "docker0"])
    protocols = g.get("protocols", ["tcp", "udp"])

    # 确保表/链存在
    ensure_infra()

    # 清空我们自己的链（不影响计数器）
    nft_f(f"flush chain {FAMILY} {TABLE} {INGRESS}")
    nft_f(f"flush chain {FAMILY} {TABLE} {EGRESS}")

    def add_one(direction, proto, port, counter_name):
        # 给规则加上 comment，便于诊断
        line = rule_line(exclude_ifaces, proto, direction, port, counter_name) + \
               f' comment "pq:{port}:{direction}:{proto}"'
        nft_f(line)

    # 逐端口下发
    for p in cfg.get("ports", []):
        port = int(p["port"])
        direction = p.get("direction", "both")
        protocols_here = protocols
        cname = f"port{port}_total"
        ensure_counter(cname)

        dirs = [INGRESS, EGRESS] if direction == "both" else [direction]
        for d in dirs:
            for proto in protocols_here:
                add_one(d, proto, port, cname)


def ensure_infra():
    if run(["nft","list","table",FAMILY,TABLE]).returncode != 0:
        nft_f(f"add table {FAMILY} {TABLE}")
    if run(["nft","list","chain",FAMILY,TABLE,INGRESS]).returncode != 0:
        nft_f(f"add chain {FAMILY} {TABLE} {INGRESS} {{ type filter hook input priority 10; policy accept; }}")
    if run(["nft","list","chain",FAMILY,TABLE,EGRESS]).returncode != 0:
        nft_f(f"add chain {FAMILY} {TABLE} {EGRESS} {{ type filter hook output priority 10; policy accept; }}")

def ensure_counter(counter_name):
    if run(["nft","list","counter",FAMILY,TABLE,counter_name]).returncode != 0:
        nft_f(f"add counter {FAMILY} {TABLE} {counter_name}")

def rule_line(exclude_ifaces, proto, direction, port, counter_name):
    # direction: "ingress" uses dport, "egress" uses sport
    iface = ""
    if exclude_ifaces:
        names = ", ".join(f'"{i}"' for i in exclude_ifaces)
        iface = f"iifname != {{ {names} }} " if direction==INGRESS else f"oifname != {{ {names} }} "
    port_expr = f"{proto} dport {port}" if direction==INGRESS else f"{proto} sport {port}"
    return f"add rule {FAMILY} {TABLE} {direction} {iface}{port_expr} counter name {counter_name}"

def nft_counter_bytes(counter_name):
    res = run(["nft","-j","list","counter",FAMILY,TABLE,counter_name])
    if res.returncode != 0:
        return 0
    data = json.loads(res.stdout or "{}")
    for obj in data.get("nftables", []):
        if "counter" in obj:
            return int(obj["counter"].get("bytes",0))
    return 0

def ufw_status_text(numbered=False):
    cmd = ["ufw", "status", "numbered"] if numbered else ["ufw", "status"]
    return run(cmd).stdout

def ufw_delete_rules_matching(regex: re.Pattern):
    """
    删除所有与 regex 匹配的规则（用 numbered 模式，从大到小删）。
    """
    out = ufw_status_text(numbered=True)
    to_delete = []
    for line in out.splitlines():
        m = re.match(r"\[\s*(\d+)\]\s+(.*)", line)
        if not m: 
            continue
        idx, body = int(m.group(1)), m.group(2)
        if regex.search(body):
            to_delete.append(idx)
    for idx in sorted(to_delete, reverse=True):
        run(["ufw", "delete", str(idx)])

def block_port_tcp_by_removing_allow(port:int):
    """
    超额时：直接删除该端口的 ALLOW（v4+v6 一起删），不插入 DENY。
    这里使用 `ufw delete allow <port>/tcp`，在你的环境不需要确认。
    """
    # 如果本来就没有 ALLOW，这条命令会提示找不到规则，返回码可能非0——无所谓，直接忽略。
    run(["ufw", "delete", "allow", f"{port}/tcp"])

def ensure_port_allowed_tcp(port:int):
    """
    reset 后：确保存在 ALLOW（通常会生成 v4+v6 两条）。
    已存在时 `ufw allow` 会提示已存在或再加一条，同样是幂等可接受。
    """
    run(["ufw", "allow", f"{port}/tcp"])


def is_port_allowed_tcp(port:int):
    pat = re.compile(rf"\b{port}/tcp\b.*\bALLOW\b", re.I)
    return any(pat.search(l) for l in ufw_status_text().splitlines())

def is_port_denied_tcp(port:int):
    pat = re.compile(rf"\b{port}/tcp\b.*\bDENY\b", re.I)
    return any(pat.search(l) for l in ufw_status_text().splitlines())

def deny_port_tcp(port:int):
    """
    1) 删除所有该端口的 ALLOW（v4/v6 都会匹配）
    2) 把 DENY 插到第 1 条，确保优先级最高
    """
    ufw_delete_rules_matching(re.compile(rf"\b{port}/tcp\b.*\bALLOW\b", re.I))
    if not is_port_denied_tcp(port):
        run(["ufw","insert","1","deny",f"{port}/tcp"])

def allow_port_tcp(port:int):
    """
    1) 删除所有该端口的 DENY
    2) 如无 ALLOW，则添加 ALLOW
    """
    ufw_delete_rules_matching(re.compile(rf"\b{port}/tcp\b.*\bDENY\b", re.I))
    if not is_port_allowed_tcp(port):
        run(["ufw","allow",f"{port}/tcp"])

def reset_counter(counter_name:str):
    run(["nft","reset","counter",FAMILY,TABLE,counter_name])

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

def load_config(path):
    with open(path,"rb") as f:
        return tomllib.load(f)

def write_json_atomic(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp,"w") as f:
        json.dump(data,f,indent=2,ensure_ascii=False)
    os.replace(tmp,path)

def loop(cfg:dict):
    g = cfg.get("general",{})
    unit = (g.get("unit","GB")).upper()
    unit_size = 1_000_000_000 if unit=="GB" else 1_073_741_824
    exclude_ifaces = g.get("exclude_ifaces", ["lo","docker0"])
    protocols = g.get("protocols", ["tcp","udp"])  # 仅用于统计；封禁按需求只封 tcp
    usage_file = g.get("usage_file","/root/portquota/usage.json")
    interval = int(g.get("interval_sec",5))

    ensure_infra()
    sync_rules(cfg)


    # 预创建每个端口的计数器与规则
    items = []
    for p in cfg.get("ports",[]):
        port = int(p["port"])
        limit_gb = float(p["limit_gb"])
        direction = p.get("direction","both")  # both/ingress/egress
        cname = f"port{port}_total"
        ensure_counter(cname)
        items.append((port, limit_gb, direction, cname))

    while True:
        out = {"timestamp": now_iso(), "unit": unit, "ports": {}}
        for (port, limit_gb, direction, cname) in items:
            used_bytes = nft_counter_bytes(cname)
            limit_bytes = int(limit_gb * unit_size)
            exceeded = used_bytes >= limit_bytes
            if exceeded:
                block_port_tcp_by_removing_allow(port) # 按需求只关 tcp
            out["ports"][str(port)] = {
                "bytes": used_bytes,
                f"used_{unit.lower()}": round(used_bytes/unit_size, 4),
                f"limit_{unit.lower()}": limit_gb,
                "direction": direction,
                "status": "blocked" if exceeded else "open",
            }
        write_json_atomic(usage_file, out)
        time.sleep(interval)

def main():
    parser = argparse.ArgumentParser(description="Per-port traffic quota enforcer (nftables counters + UFW)")
    parser.add_argument("-c","--config", default="/root/portquota/config.toml")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon")
    sub = parser.add_subparsers(dest="cmd")

    r = sub.add_parser("reset", help="Reset a port's usage and reopen via UFW")
    r.add_argument("port", type=int)

    s = sub.add_parser("status", help="Print current snapshot from nft (and ensure rules exist)")
    s.add_argument("--json", action="store_true")

    args = parser.parse_args()
    if os.geteuid() != 0:
        print("Run as root.", file=sys.stderr); sys.exit(1)

    cfg = load_config(args.config)

    if args.cmd == "reset":
        port = int(args.port)
        reset_counter(f"port{port}_total")
        ensure_port_allowed_tcp(port)
        print(f"[reset] port {port}: counter cleared and ufw allowed.")
        return

    if args.cmd == "status":
        g = cfg.get("general",{})
        unit = (g.get("unit","GB")).upper()
        unit_size = 1_000_000_000 if unit=="GB" else 1_073_741_824
        ensure_infra()
        rows=[]
        for p in cfg.get("ports",[]):
            port=int(p["port"]); lim=float(p["limit_gb"])
            direction=p.get("direction","both")
            cname=f"port{port}_total"
            ensure_counter(cname)
            b=nft_counter_bytes(cname); status = "blocked" if b>=lim*unit_size else "open"
            if args.json:
                rows.append({"port":port, f"used_{unit.lower()}":round(b/unit_size,4), f"limit_{unit.lower()}":lim, "direction":direction, "status":status})
            else:
                print(f"{port}: {b/unit_size:.4f}/{lim} {unit} [{direction}]  -> {status}")
        if args.json:
            print(json.dumps({"unit":unit,"ports":rows},ensure_ascii=False,indent=2))
        return

    if args.daemon:
        loop(cfg)
    else:
        parser.print_help()

if __name__=="__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

