#!/bin/bash

#================================================================================
# PortQuota Installation Script
#================================================================================

# --- 配置项 ---
# !!! 请务必修改为你的 GitHub 仓库地址 !!!
REPO_URL="https://github.com/tsingfenger/portquota.git"
# 安装目录
INSTALL_DIR="/root/portquota"
# Service 文件名
SERVICE_FILE="portquota.service"
# Systemd 目录
SYSTEMD_DIR="/etc/systemd/system"
# 命令名称
EXEC_NAME="portquota"
# 命令安装路径
BIN_DIR="/usr/local/bin"


# --- 颜色定义 ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# --- 函数定义 ---

# 打印信息
info() {
    echo -e "${GREEN}[INFO] $1${NC}"
}

# 打印警告
warn() {
    echo -e "${YELLOW}[WARN] $1${NC}"
}

# 打印错误并退出
error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

# 1. 检测是否为 root 用户
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "此脚本必须以 root 用户身份运行。"
    fi
}

# 2. 检测并安装依赖
check_and_install_deps() {
    info "正在检查系统依赖..."
    # 假设为 Debian/Ubuntu 系统，使用 apt
    # 如果是 CentOS/RHEL，请将 'apt-get' 改为 'yum' 或 'dnf'
    PKG_MANAGER="apt-get"
    
    # 需要检查的包（命令）
    REQUIRED_CMDS=("python3" "nft" "ufw" "git")
    PACKAGES_TO_INSTALL=()
    UFW_NEEDS_INSTALL=false

    for cmd in "${REQUIRED_CMDS[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            case "$cmd" in
                "python3") PACKAGES_TO_INSTALL+=("python3") ;;
                "nft") PACKAGES_TO_INSTALL+=("nftables") ;;
                "ufw") 
                    PACKAGES_TO_INSTALL+=("ufw")
                    UFW_NEEDS_INSTALL=true
                    ;;
                "git") PACKAGES_TO_INSTALL+=("git") ;;
            esac
        fi
    done

    if [ ${#PACKAGES_TO_INSTALL[@]} -ne 0 ]; then
        info "以下依赖缺失，将尝试安装: ${PACKAGES_TO_INSTALL[*]}"
        $PKG_MANAGER update || error "更新包列表失败。"
        $PKG_MANAGER install -y "${PACKAGES_TO_INSTALL[@]}" || error "安装依赖失败。"
        info "依赖安装完成。"
    else
        info "所有依赖均已满足。"
    fi

    # 如果 UFW 是新安装的，则进行配置
    if [ "$UFW_NEEDS_INSTALL" = true ]; then
        configure_ufw
    fi
}

# UFW 的交互式配置
configure_ufw() {
    warn "检测到 UFW 是新安装的，需要进行基础配置。"
    read -p "是否同意将 UFW 默认策略设置为 [入站拒绝, 出站允许]? [Y/n] " confirm
    if [[ "$confirm" =~ ^[Yy]$|^$ ]]; then
        info "设置 UFW 默认策略..."
        ufw default deny incoming
        ufw default allow outgoing

        read -p "请输入在安装时需要立即放行的端口（例如 22,80,443），用逗号分隔: " ports
        if [ -n "$ports" ]; then
            # 将逗号替换为空格
            ports_to_allow=$(echo "$ports" | tr ',' ' ')
            for port in $ports_to_allow; do
                info "允许端口: $port"
                ufw allow "$port"
            done
        fi
        
        info "启用 UFW 防火墙..."
        # UFW enable 会有一次确认，这是安全的
        ufw enable
    else
        warn "您已跳过 UFW 自动配置。请稍后手动配置防火墙。"
    fi
}

# 下载项目文件
download_project() {
    info "正在从 GitHub 克隆项目到 $INSTALL_DIR..."
    if [ -d "$INSTALL_DIR" ]; then
        warn "安装目录 $INSTALL_DIR 已存在，将进行覆盖。"
        rm -rf "$INSTALL_DIR"
    fi
    git clone "$REPO_URL" "$INSTALL_DIR" || error "克隆仓库失败，请检查 URL 和网络连接。"
    # 确保脚本内的文件也存在
    if [ ! -f "$INSTALL_DIR/$SERVICE_FILE" ]; then
        error "在下载的项目中未找到 $SERVICE_FILE 文件。"
    fi
}

# 3. 启用 Service
setup_service() {
    info "正在安装和启用 systemd 服务..."
    cp "$INSTALL_DIR/$SERVICE_FILE" "$SYSTEMD_DIR/" || error "复制 service 文件失败。"
    systemctl daemon-reload
    systemctl enable "$SERVICE_FILE" || error "启用服务失败。"
    systemctl start "$SERVICE_FILE" || error "启动服务失败。"
    
    info "服务状态检查:"
    # 等待2秒让服务有时间启动
    sleep 2
    systemctl status "$SERVICE_FILE" --no-pager
    info "服务已成功启动并设置为开机自启。"
}

# 4. 创建全局命令
create_command_link() {
    info "正在创建全局命令 '$EXEC_NAME'..."
    local script_path="$INSTALL_DIR/portquota.py"
    if [ ! -f "$script_path" ]; then
        error "主程序 $script_path 不存在。"
    fi
    # 赋予执行权限
    chmod +x "$script_path"
    # 创建软链接
    ln -sf "$script_path" "$BIN_DIR/$EXEC_NAME" || error "创建软链接失败。"
    info "现在你可以直接在终端使用 'portquota' 命令了。"
}

# --- 主逻辑 ---
main() {
    check_root
    check_and_install_deps
    download_project
    setup_service
    create_command_link
    echo -e "\n${GREEN}🎉 PortQuota 安装成功！${NC}\n"
}

main