# PortQuota

一个基于 `nftables` 和 `UFW` 的轻量级服务器端口流量限额工具。它利用 `nftables` 的高性能计数器进行流量统计，并在流量超限后，通过 `UFW` 自动封禁对应端口。



## 0. 介绍

本工具旨在为每个独立端口提供精确的流量限额管理。通过后台服务持续监控，一旦指定端口的总流量（入口+出口）超出 `config.toml` 中设定的阈值，程序会自动操作 UFW 防火墙，移除该端口的 `ALLOW` 规则，从而实现访问限制。



## 1. 提醒与依赖

 **兼容性警告**: 本程序目前仅在 **Debian 12** 环境下经过完整测试。在其他 Linux 发行版上可能因包管理器 (`apt`) 或默认配置不同而无法正常工作，请自行评估风险。

 **核心依赖**: 程序依赖 `ufw`, `nftables`, `python3` (版本需 >= 3.11)。安装脚本会自动尝试安装这些依赖。

 **安装路径**: 程序主目录及所有相关文件（配置、日志等）均位于 `/root/portquota`。



## 2. 一键安装

请使用 root 权限执行以下命令进行安装。脚本会自动完成环境检查、依赖安装、服务部署等所有步骤。

**使用 curl:**
```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/leG09/portquota/refs/heads/main/install.sh)" -- --yes
```

安装成功后，卸载脚本位于 `/root/portquota/uninstall.sh`。

**卸载**
```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/leG09/portquota/refs/heads/main/uninstall.sh)"
```

### 非交互安装参数

```bash
# 完全非交互（隐含 --yes 并跳过 UFW 配置提示）
install.sh --non-interactive

# 指定自定义仓库/分支与安装目录
install.sh --repo https://github.com/leG09/portquota.git --branch main \
           --install-dir /root/portquota --bin-dir /usr/local/bin

# 跳过 UFW 首次配置（保留现有 UFW 策略）
install.sh --skip-ufw-config
```

## 3. 快速开始

安装完成后，直接运行 `portquota` 进入交互界面（TUI）。在界面内添加/编辑端口并保存配置，随后在界面内按 `R` 可一键重启服务使之生效。

## 4. 配置文件

所有配置均在 `/root/portquota/config.toml` 文件中定义。修改配置后，**必须重启服务**才能生效：`systemctl restart portquota`。

```toml
# config.toml 示例

[general]
# 数据统计与写入文件的频率（秒）
interval_sec = 5
# 流量使用情况的输出文件路径
usage_file   = "/root/portquota/usage.json"
# 要排除统计的网卡接口
exclude_ifaces = ["lo", "docker0"]
# 流量单位：GB (10^9 字节) 或 GiB (2^30 字节)
unit = "GB"
# 需要统计的协议（注意：目前超额时仅封禁 TCP 端口）
protocols = ["tcp", "udp"]

# === 需要进行流量限额的端口列表 ===
# direction: "both" (默认, 入口+出口总和), "ingress" (仅入口), "egress" (仅出口)

[[ports]]
port = 52135
limit_gb = 1
direction = "both"

[[ports]]
port = 51235
limit_gb = 50

# ...可以继续添加更多端口...
```


## 5. 交互界面（TUI）

安装后，直接运行 `portquota`（不带参数）即可进入终端交互界面：

按键说明：
- ↑/↓ 或 j/k: 移动选择
- Space 或 r: 刷新用量
- Enter: 重置选中端口（清零并允许 UFW）
- A: 添加端口
- E: 编辑端口限额/方向
- D: 删除端口（需保存后生效）
- S: 保存配置到 `config.toml`（需手动重启服务生效）
- W: 开启/关闭自动刷新（每秒刷新一次）
- R: 一键重启守护服务（需要 root）
- Q: 退出

提示：保存后运行 `sudo systemctl restart portquota` 应用新配置。

## 6. 守护进程

如需仅运行后台配额管理（不进入界面），可以使用 systemd 服务或 `--daemon`：

```bash
sudo systemctl restart portquota
# 或
sudo portquota --daemon
```
