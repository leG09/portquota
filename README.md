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
bash -c "$(curl -fsSL https://raw.githubusercontent.com/tsingfenger/portquota/refs/heads/main/install.sh)"
```

安装成功后，卸载脚本位于 `/root/portquota/uninstall.sh`。

**卸载**
```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/tsingfenger/portquota/refs/heads/main/uninstall.sh)"
```

## 3. 配置文件

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


## 4. 程序命令

安装脚本会自动创建全局 `portquota` 命令。

### 查看状态

显示所有被监控端口的当前流量使用情况。

```bash
portquota status
```

**示例输出:**
```
52135: 1.1193/1.0 GB [both]  -> blocked
51235: 0.0355/50.0 GB [both]  -> open
```

使用 `json` 参数可获取 JSON 格式的输出。

### 重置流量

清空指定端口的流量计数器，并使用 UFW 重新允许该端口。

```bash
portquota reset 52135
```

### 服务管理

使用 `systemctl` 控制后台守护进程。

```bash
# 查看服务状态
systemctl status portquota

# 重启服务（修改配置后使用）
systemctl restart portquota

# 停止服务
systemctl stop portquota
```
