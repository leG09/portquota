#!/bin/bash

#================================================================================
# PortQuota Uninstallation Script
#================================================================================

# --- 配置项 (与 install.sh 保持一致) ---
INSTALL_DIR="/root/portquota"
SERVICE_FILE="portquota.service"
SYSTEMD_DIR="/etc/systemd/system"
EXEC_NAME="portquota"
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

# 打印错误并退出
error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

# 检测是否为 root 用户
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "此脚本必须以 root 用户身份运行。"
    fi
}

# --- 主逻辑 ---
main() {
    check_root
    
    info "开始卸载 PortQuota..."

    # 1. 停止并禁用服务
    info "正在停止并禁用 systemd 服务..."
    systemctl stop "$SERVICE_FILE" &> /dev/null
    systemctl disable "$SERVICE_FILE" &> /dev/null
    info "服务已停止并已禁用开机自启。"

    # 2. 移除 service 文件
    info "正在移除 systemd service 文件..."
    rm -f "$SYSTEMD_DIR/$SERVICE_FILE"
    systemctl daemon-reload
    info "Service 文件已移除。"

    # 3. 移除软链接
    info "正在移除全局命令 '$EXEC_NAME'..."
    rm -f "$BIN_DIR/$EXEC_NAME"
    info "全局命令已移除。"

    # 4. 清理 nftables 表和规则
    info "正在清理 nftables 表和规则..."
    if nft list table inet traffic &> /dev/null; then
        nft delete table inet traffic 2>/dev/null || warn "清理 nftables 表时出现警告（可能表已被删除）。"
        info "nftables 表和规则已清理。"
    else
        info "nftables 表不存在，无需清理。"
    fi

    # 5. 删除项目文件夹
    info "正在删除安装目录: $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR"
    info "项目文件已删除。"

    echo -e "\n${GREEN}✅ PortQuota 卸载完成！${NC}"
    echo -e "注意：由安装脚本初始化的 UFW 规则未被改动。"
}

main