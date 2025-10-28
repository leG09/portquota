#!/usr/bin/python3
import os, sys, time, subprocess, json, argparse, re, datetime
import curses
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

def write_text_atomic(path: str, text: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)

def perform_init(args):
    # 默认值
    cfg_path = args.config
    unit = (args.unit or "GB").upper()
    unit = "GB" if unit in ("GB",) else "GiB"
    interval = args.interval or 5
    usage_file = args.usage_file or "/root/portquota/usage.json"
    exclude_ifaces = [i.strip() for i in (args.exclude_ifaces or "lo,docker0").split(",") if i.strip()]
    protocols = [p.strip() for p in (args.protocols or "tcp,udp").split(",") if p.strip()]

    def parse_ports(s: str):
        result = []
        if not s:
            return result
        for entry in s.split(","):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split(":")
            try:
                port = int(parts[0])
                limit_gb = float(parts[1]) if len(parts) > 1 else 50.0
                direction = parts[2] if len(parts) > 2 else "both"
                if direction not in ("both","ingress","egress"):
                    direction = "both"
                result.append({"port": port, "limit_gb": limit_gb, "direction": direction})
            except Exception:
                continue
        return result

    ports = parse_ports(args.ports or "")

    if not ports and not args.yes:
        # 交互式采集基础端口
        print("将引导生成 config.toml，留空使用默认值。")
        try:
            unit_in = input(f"单位 [GB/GiB] (默认 {unit}): ").strip()
            if unit_in:
                unit = unit_in.upper() if unit_in.upper() in ("GB","GIB","GIB") else unit
            interval_in = input(f"采样间隔秒 (默认 {interval}): ").strip()
            if interval_in:
                interval = int(interval_in)
            usage_in = input(f"用量输出 JSON 路径 (默认 {usage_file}): ").strip()
            if usage_in:
                usage_file = usage_in
            excl_in = input(f"排除网卡 (逗号分隔, 默认 {','.join(exclude_ifaces)}): ").strip()
            if excl_in:
                exclude_ifaces = [i.strip() for i in excl_in.split(',') if i.strip()]
            proto_in = input(f"统计协议 (逗号分隔, 默认 {','.join(protocols)}): ").strip()
            if proto_in:
                protocols = [p.strip() for p in proto_in.split(',') if p.strip()]

            print("添加需要限额的端口，格式: 端口:限额GB[:方向]，例如 52135:1:both 或 51235:50")
            print("逐条输入，留空结束")
            while True:
                line = input("端口条目: ").strip()
                if not line:
                    break
                ports.extend(parse_ports(line))
        except KeyboardInterrupt:
            print("\n已取消。")
            return

    if not ports:
        # 给出一个最小示例
        ports = [{"port": 52135, "limit_gb": 1, "direction": "both"}]

    # 渲染 TOML 文本
    def to_toml_list(items):
        lines = []
        for it in items:
            lines.append("[[ports]]")
            lines.append(f"port = {int(it['port'])}")
            # limit_gb 尽量保留小数
            lim = ("%s" % it['limit_gb']).rstrip('0').rstrip('.') if isinstance(it['limit_gb'], float) else str(it['limit_gb'])
            lines.append(f"limit_gb = {lim}")
            lines.append(f"direction = \"{it.get('direction','both')}\"")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    header = [
        "[general]",
        f"interval_sec = {int(interval)}",
        f"usage_file   = \"{usage_file}\"",
        f"exclude_ifaces = [{', '.join(f'\"{i}\"' for i in exclude_ifaces)}]",
        f"unit = \"{unit}\"",
        f"protocols = [{', '.join(f'\"{p}\"' for p in protocols)}]",
        "",
    ]
    toml_text = "\n".join(header) + to_toml_list(ports)

    if args.write or args.force or args.yes:
        # 如存在且未 force，进行确认
        if os.path.exists(cfg_path) and not (args.force or args.yes):
            ans = input(f"{cfg_path} 已存在，是否覆盖? [y/N] ").strip().lower()
            if ans != 'y':
                print("已取消写入，以下为生成内容预览:\n")
                print(toml_text)
                return
        write_text_atomic(cfg_path, toml_text)
        print(f"配置已写入: {cfg_path}")
        print("你可以运行: systemctl restart portquota 使其生效。")
    else:
        # 预览到 stdout
        print(toml_text)

def render_config_toml(general: dict, ports: list[dict]) -> str:
    unit = (general.get("unit","GB")).upper()
    interval = int(general.get("interval_sec",5))
    usage_file = general.get("usage_file","/root/portquota/usage.json")
    exclude_ifaces = general.get("exclude_ifaces", ["lo","docker0"]) or []
    protocols = general.get("protocols", ["tcp","udp"]) or []

    header = [
        "[general]",
        f"interval_sec = {interval}",
        f"usage_file   = \"{usage_file}\"",
        f"exclude_ifaces = [{', '.join(f'\"{i}\"' for i in exclude_ifaces)}]",
        f"unit = \"{unit}\"",
        f"protocols = [{', '.join(f'\"{p}\"' for p in protocols)}]",
        "",
    ]

    def to_ports(ps: list[dict]) -> str:
        lines: list[str] = []
        for it in ps:
            lines.append("[[ports]]")
            lines.append(f"port = {int(it['port'])}")
            lim = ("%s" % it['limit_gb']).rstrip('0').rstrip('.') if isinstance(it['limit_gb'], float) else str(it['limit_gb'])
            lines.append(f"limit_gb = {lim}")
            lines.append(f"direction = \"{it.get('direction','both')}\"")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    return "\n".join(header) + to_ports(ports)

def run_tui(config_path: str):
    if os.geteuid() != 0:
        print("需要 root 权限。请使用 sudo 运行，例如: sudo portquota", file=sys.stderr)
        return

    cfg = load_config(config_path)
    general = cfg.get("general", {})
    ports_cfg = cfg.get("ports", [])

    items = []  # (port, limit_gb, direction, counter_name)
    for p in ports_cfg:
        port = int(p["port"])
        limit_gb = float(p["limit_gb"])
        direction = p.get("direction","both")
        cname = f"port{port}_total"
        ensure_counter(cname)
        items.append((port, limit_gb, direction, cname))

    unit = (general.get("unit","GB")).upper()
    unit_size = 1_000_000_000 if unit=="GB" else 1_073_741_824

    state = {
        "selected": 0,
        "message": "",
        "last_refresh": None,
        "watch": False,
    }

    def snapshot():
        rows = []
        for (port, limit_gb, direction, cname) in items:
            b = nft_counter_bytes(cname)
            status = "blocked" if b >= int(limit_gb*unit_size) else "open"
            rows.append({
                "port": port,
                "used": round(b/unit_size, 4),
                "limit": limit_gb,
                "direction": direction,
                "status": status,
            })
        return rows

    def draw(stdscr, rows):
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        title = "PortQuota 交互界面  ↑/↓ 选择  Enter 重置  A 添加  D 删除  E 编辑  Space 刷新  S 保存  R 重启服务  W 监听  Q 退出"
        try:
            curses.start_color(); curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_CYAN, -1)    # header/title
            curses.init_pair(2, curses.COLOR_GREEN, -1)   # open
            curses.init_pair(3, curses.COLOR_RED, -1)     # blocked
            curses.init_pair(4, curses.COLOR_YELLOW, -1)  # message
        except Exception:
            pass

        stdscr.addnstr(0, 0, title, w-1, curses.color_pair(1))
        stdscr.hline(1, 0, ord('-'), w-1)
        header = f" Port    Used/{unit:<4}   Limit/{unit:<4}  Direction  Status"
        stdscr.addnstr(2, 0, header, w-1, curses.A_BOLD | curses.color_pair(1))
        stdscr.hline(3, 0, ord('='), w-1)
        start_line = 4
        for idx, r in enumerate(rows):
            selected = (idx == state["selected"]) 
            prefix = ">" if selected else " "
            line = f"{prefix} {r['port']:<7} {r['used']:<10.4f} {r['limit']:<10.4f} {r['direction']:<9} "
            attr = curses.A_NORMAL
            if r['status'] == 'open':
                attr |= curses.color_pair(2)
            else:
                attr |= curses.color_pair(3)
            if selected:
                attr |= curses.A_REVERSE
            stdscr.addnstr(start_line + idx, 0, line + r['status'], w-1, attr)
        stdscr.hline(start_line + len(rows), 0, ord('-'), w-1)
        if state["message"]:
            stdscr.addnstr(start_line + len(rows) + 1, 0, state["message"], w-1, curses.color_pair(4))
        if state["watch"]:
            stdscr.addnstr(start_line + len(rows) + 2, 0, "[WATCH 模式：自动刷新中]", w-1, curses.color_pair(1))
        stdscr.refresh()

    def prompt(stdscr, msg) -> str:
        curses.echo()
        h, w = stdscr.getmaxyx()
        stdscr.addnstr(h-1, 0, " " * (w-1), w-1)
        stdscr.addnstr(h-1, 0, msg, w-1)
        stdscr.refresh()
        s = stdscr.getstr(h-1, len(msg)).decode(errors='ignore')
        curses.noecho()
        return s.strip()

    def save_config():
        new_ports = []
        for (port, limit_gb, direction, _cname) in items:
            new_ports.append({"port": port, "limit_gb": limit_gb, "direction": direction})
        text = render_config_toml(general, new_ports)
        write_text_atomic(config_path, text)

    def restart_service():
        res = run(["systemctl","restart","portquota"]) 
        ok = (res.returncode == 0)
        return ok, (res.stderr or res.stdout or "").strip()

    def run_loop(stdscr):
        curses.curs_set(0)
        rows = snapshot()
        draw(stdscr, rows)
        stdscr.timeout(-1)
        while True:
            ch = stdscr.getch()
            if ch in (ord('q'), ord('Q')):
                break
            elif ch in (curses.KEY_UP, ord('k')):
                state["selected"] = max(0, state["selected"] - 1)
            elif ch in (curses.KEY_DOWN, ord('j')):
                state["selected"] = min(len(items)-1, state["selected"] + 1)
            elif ch in (ord(' '), ord('r')):  # 空格刷新；r 也刷新
                pass
            elif ch in (curses.KEY_ENTER, 10, 13):
                if items:
                    port = items[state["selected"]][0]
                    reset_counter(f"port{port}_total")
                    ensure_port_allowed_tcp(port)
                    state["message"] = f"已重置端口 {port} 并允许 UFW"
            elif ch in (ord('e'), ord('E')):
                if items:
                    port, limit_gb, direction, cname = items[state["selected"]]
                    new_lim = prompt(stdscr, f"端口 {port} 新的限额GB(当前 {limit_gb}): ")
                    if new_lim:
                        try:
                            limit_gb = float(new_lim)
                            items[state["selected"]] = (port, limit_gb, direction, cname)
                            state["message"] = f"已更新端口 {port} 限额为 {limit_gb} GB"
                        except Exception:
                            state["message"] = "输入无效，未修改"
                    new_dir = prompt(stdscr, f"方向 both/ingress/egress(当前 {direction}): ")
                    if new_dir in ("both","ingress","egress"):
                        items[state["selected"]] = (port, limit_gb, new_dir, cname)
                        state["message"] = f"已更新端口 {port} 方向为 {new_dir}"
            elif ch in (ord('a'), ord('A')):
                sp = prompt(stdscr, "新增端口: ")
                if sp:
                    try:
                        nport = int(sp)
                        slim = prompt(stdscr, "限额GB(默认 50): ")
                        nlim = float(slim) if slim else 50.0
                        sdir = prompt(stdscr, "方向 both/ingress/egress(默认 both): ") or "both"
                        if sdir not in ("both","ingress","egress"):
                            sdir = "both"
                        cname = f"port{nport}_total"
                        ensure_counter(cname)
                        items.append((nport, nlim, sdir, cname))
                        state["selected"] = len(items)-1
                        state["message"] = f"已添加端口 {nport}"
                    except Exception:
                        state["message"] = "输入无效，未添加"
            elif ch in (ord('d'), ord('D')):
                if items:
                    idx = state["selected"]
                    p = items[idx][0]
                    items.pop(idx)
                    state["selected"] = max(0, min(idx, len(items)-1))
                    state["message"] = f"已移除端口 {p}（未保存）"
            elif ch in (ord('s'), ord('S')):
                save_config()
                state["message"] = "配置已保存。若要使守护进程生效，请运行: systemctl restart portquota"
            elif ch in (ord('w'), ord('W')):
                state["watch"] = not state["watch"]
                state["message"] = "已开启 WATCH 自动刷新" if state["watch"] else "已关闭 WATCH 自动刷新"
                stdscr.timeout(1000 if state["watch"] else -1)
            elif ch in (ord('R')):
                ok, msg = restart_service()
                state["message"] = "服务已重启" if ok else f"重启失败: {msg}"

            rows = snapshot()
            draw(stdscr, rows)

    curses.wrapper(run_loop)

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

    i = sub.add_parser("init", help="Interactive/Non-interactive config generator")
    i.add_argument("--yes", action="store_true", help="Assume yes for prompts")
    i.add_argument("--force", action="store_true", help="Overwrite existing config without prompt")
    i.add_argument("--unit", choices=["GB","GiB","GIB","gb","gib"], help="Unit for traffic quota")
    i.add_argument("--interval", type=int, help="Sampling interval seconds")
    i.add_argument("--usage-file", dest="usage_file", help="Usage output JSON path")
    i.add_argument("--exclude-ifaces", dest="exclude_ifaces", help="Comma separated interfaces to exclude, e.g. lo,docker0")
    i.add_argument("--protocols", help="Comma separated protocols to count, e.g. tcp,udp")
    i.add_argument("--ports", help="Comma list of entries port:limit[:direction], e.g. 52135:1:both,51235:50")
    i.add_argument("--write", action="store_true", help="Write to --config instead of preview to stdout")

    args = parser.parse_args()

    # Root 权限要求：除 init 外的命令需要 root
    if args.cmd != "init" and os.geteuid() != 0:
        print("需要 root 权限。请使用 sudo 运行，例如: sudo portquota status", file=sys.stderr); sys.exit(1)

    if args.cmd == "init":
        perform_init(args)
        return

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
        # 无子命令、非 daemon：进入 TUI
        run_tui(args.config)

if __name__=="__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

