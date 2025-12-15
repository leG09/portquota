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
        f"exclude_ifaces = {json.dumps(exclude_ifaces)}",
        f"unit = \"{unit}\"",
        f"protocols = {json.dumps(protocols)}",
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
        f"exclude_ifaces = {json.dumps(exclude_ifaces)}",
        f"unit = \"{unit}\"",
        f"protocols = {json.dumps(protocols)}",
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

    # 确保基础设施和规则同步（关键：让流量能被计数）
    ensure_infra()
    sync_rules(cfg)

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
        "selected": 0,   # 选中项的全局索引
        "top": 0,        # 可视区域的起始索引（滚动）
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
        # 预留底部 3 行：消息行、watch 行、输入提示行
        max_rows_area = max(0, h - start_line - 3 - 1)  # 额外减1给分隔线
        # 滚动窗口计算
        total = len(rows)
        if state["selected"] < state["top"]:
            state["top"] = state["selected"]
        if state["selected"] >= state["top"] + max_rows_area:
            state["top"] = max(0, state["selected"] - max_rows_area + 1)
        visible = rows[state["top"]: state["top"] + max_rows_area]

        for idx, r in enumerate(visible):
            global_idx = state["top"] + idx
            selected = (global_idx == state["selected"]) 
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
        # 若有截断，显示提示
        if total > len(visible):
            more = total - len(visible)
            stdscr.addnstr(start_line + len(visible), 0, f"... 还有 {more} 行未显示，增大终端高度以查看更多", w-1, curses.color_pair(4))

        footer_sep_y = h - 4
        if footer_sep_y >= 0:
            stdscr.hline(footer_sep_y, 0, ord('-'), w-1)

        msg_y = h - 3
        watch_y = h - 2
        if msg_y >= 0 and state["message"]:
            # 清理消息与 watch 行
            try:
                stdscr.addnstr(msg_y, 0, " " * (w-1), w-1)
                stdscr.addnstr(msg_y, 0, state["message"], w-1, curses.color_pair(4))
            except Exception:
                pass
        if watch_y >= 0 and state["watch"]:
            try:
                stdscr.addnstr(watch_y, 0, " " * (w-1), w-1)
                stdscr.addnstr(watch_y, 0, "[WATCH 模式：自动刷新中]", w-1, curses.color_pair(1))
            except Exception:
                pass
        stdscr.refresh()

    def prompt(stdscr, msg) -> str:
        # 暂停自动刷新，进入输入模式
        prev_timeout = 1000 if state.get("watch") else -1
        stdscr.timeout(-1)
        curses.echo()
        try:
            curses.curs_set(1)
        except Exception:
            pass
        h, w = stdscr.getmaxyx()
        # 清理底部两行（提示行在倒数第二行，输入在最底行）
        if h-2 >= 0:
            stdscr.addnstr(h-2, 0, " " * (w-1), w-1)
        if h-1 >= 0:
            stdscr.addnstr(h-1, 0, " " * (w-1), w-1)
        # 提示文本显示在倒数第二行，截断以适配宽度
        if h-2 >= 0:
            # 取尾部以保留关键信息
            max_prompt = max(0, w-1)
            display_msg = msg[-max_prompt:]
            stdscr.addnstr(h-2, 0, display_msg, w-1)
        # 输入在最底行，固定前缀，避免与提示重合
        input_prefix = "> "
        start_col = min(len(input_prefix), max(0, w-1))
        if h-1 >= 0:
            stdscr.addnstr(h-1, 0, input_prefix, w-1)
        # 使用单独的输入窗口，避免与主窗口属性冲突
        try:
            win = curses.newwin(1, max(1, w-1 - start_col), max(0, h-1), start_col)
            win.addnstr(0, 0, " " * (w-1), w-1)
            win.refresh()
            s = win.getstr(0, 0).decode(errors='ignore')
        except Exception:
            # 回退方案直接用 stdscr
            stdscr.refresh()
            s = stdscr.getstr(h-1, start_col).decode(errors='ignore')
        finally:
            curses.noecho()
            try:
                curses.curs_set(0)
            except Exception:
                pass
            # 恢复刷新设定
            stdscr.timeout(prev_timeout)
        return s.strip()

    def save_config():
        new_ports = []
        for (port, limit_gb, direction, _cname) in items:
            new_ports.append({"port": port, "limit_gb": limit_gb, "direction": direction})
        text = render_config_toml(general, new_ports)
        write_text_atomic(config_path, text)
        # 保存后重新加载配置并同步规则
        nonlocal cfg
        cfg = load_config(config_path)
        ensure_infra()
        sync_rules(cfg)
        # 更新 items 列表以反映新配置
        items.clear()
        for p in cfg.get("ports", []):
            port = int(p["port"])
            limit_gb = float(p["limit_gb"])
            direction = p.get("direction","both")
            cname = f"port{port}_total"
            ensure_counter(cname)
            items.append((port, limit_gb, direction, cname))
        # 调整选中索引，避免越界
        if state["selected"] >= len(items):
            state["selected"] = max(0, len(items) - 1)

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
    parser = argparse.ArgumentParser(description="PortQuota - 终端交互界面与守护进程")
    parser.add_argument("-c","--config", default="/root/portquota/config.toml")
    parser.add_argument("--daemon", action="store_true", help="以守护进程模式运行（读取配置并执行配额管理）")
    args, _unknown = parser.parse_known_args()

    # 守护进程需要 root
    if args.daemon and os.geteuid() != 0:
        print("需要 root 权限。请使用 sudo 运行，例如: sudo portquota --daemon", file=sys.stderr); sys.exit(1)

    cfg = load_config(args.config)

    # 兼容遗留代码：不再支持 reset/status 子命令

    # 兼容遗留代码：不再支持 reset/status 子命令

    if args.daemon:
        loop(cfg)
    else:
        # 非 daemon：进入 TUI（唯一交互方式）
        run_tui(args.config)

if __name__=="__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

