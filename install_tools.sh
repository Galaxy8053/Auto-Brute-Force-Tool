#!/bin/bash

# =====================================================================================
#  一键安装最新版 Python, Go, screen, masscan 并下载文件脚本 (v7 - Releases 下载优化)
#
#  功能:
#  1. 自动检测并适配 Debian/Ubuntu/CentOS/AlmaLinux 等主流 Linux 发行版。
#  2. 安装系统默认的稳定版 Python 3, screen, masscan, unzip。
#  3. 从官网下载并安装最新版本的 Go 语言环境。
#  4. [核心改造] 从 GitHub Releases 下载指定 tag 的 ZIP 包并解压到当前目录。
#
#  使用方法:
#  在您的终端中运行以下单行命令:
#  bash <(curl -sL https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/main/install_tools.sh)
# =====================================================================================

# --- 配置颜色输出 ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # 无颜色

# --- 日志函数 ---
log_info() {
    echo -e "${GREEN}[信息] $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}[警告] $1${NC}"
}

log_error() {
    echo -e "${RED}[错误] $1${NC}"
}

# --- 脚本主体 ---
log_info "脚本开始执行... (v7 - Releases 下载优化)"

# 0. 权限检查
if [ "$EUID" -ne 0 ]; then
    log_warn "此脚本需要 root 权限。正在尝试使用 'sudo'..."
    SUDO="sudo"
    if ! command -v sudo &> /dev/null; then
        log_error "未找到 'sudo' 命令。请以 root 用户身份运行此脚本。"
        exit 1
    fi
else
    SUDO=""
fi

# 1. 检测系统和包管理器
PM=""
OS=""
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    log_error "无法检测到操作系统。"
    exit 1
fi

case "$OS" in
    ubuntu|debian)
        PM="apt-get"
        log_info "检测到 Debian/Ubuntu 系统，使用 apt-get。"
        ;;
    centos|almalinux|rocky)
        PM="yum"
        log_info "检测到 CentOS/AlmaLinux/Rocky 系统，使用 yum。"
        # 处理 EPEL 源
        if ! rpm -q epel-release &> /dev/null; then
            log_info "正在安装 EPEL 源..."
            $SUDO yum install -y epel-release
        fi
        ;;
    fedora)
        PM="dnf"
        log_info "检测到 Fedora 系统，使用 dnf。"
        ;;
    *)
        log_error "不支持的操作系统: $OS"
        exit 1
        ;;
esac

# 2. 安装基础依赖包
# [改造点] 在依赖列表中加入了 unzip
PACKAGES="python3 screen masscan unzip git" # 保留git以备后用
log_info "正在更新包列表并安装基础依赖: ${PACKAGES}..."
$SUDO $PM update -y
$SUDO $PM install -y $PACKAGES
if [ $? -ne 0 ]; then
    log_error "基础依赖安装失败。"
    exit 1
fi
log_info "✅ 基础依赖安装完成。"


# 3. 安装最新版 Go
# (这部分代码保持不变，它工作得很好)
log_info "正在检查并安装最新版 Go..."
GO_ARCH=$(uname -m)
case "$GO_ARCH" in
    x86_64) GO_ARCH="amd64" ;;
    aarch64) GO_ARCH="arm64" ;;
    *) log_error "不支持的 CPU 架构: $GO_ARCH"; exit 1 ;;
esac

LATEST_GO_VERSION=$(curl -sL "https://go.dev/VERSION?m=text" | head -n 1)
GO_TARBALL="${LATEST_GO_VERSION}.linux-${GO_ARCH}.tar.gz"
DOWNLOAD_URL="https://go.dev/dl/${GO_TARBALL}"

log_info "正在从 ${DOWNLOAD_URL} 下载 Go..."
curl -L -o "/tmp/${GO_TARBALL}" "${DOWNLOAD_URL}"
if [ $? -ne 0 ]; then
    log_error "下载 Go 安装包失败。请检查网络或访问 ${DOWNLOAD_URL}"
fi

log_info "正在安装 Go..."
rm -rf /usr/local/go
tar -C /usr/local -xzf "/tmp/${GO_TARBALL}"
rm "/tmp/${GO_TARBALL}"

log_info "正在配置 Go 的环境变量..."
if ! grep -q "/usr/local/go/bin" /etc/profile; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
fi
export PATH=$PATH:/usr/local/go/bin

if command -v go &> /dev/null; then
    log_info "✅ Go 安装成功: $(go version)"
else
    log_error "Go 安装失败。"
fi


# =====================================================================================
#  4. [核心改造] 下载并解压 GitHub 仓库文件
# =====================================================================================
# 使用 Releases 中的 ZIP 包，避免依赖 git，且支持私有仓库的公开发行版
# 这个链接指向我们用 Actions 自动创建的、名为 'latest-files' 的 tag
ZIP_URL="https://github.com/CXK-Computer/Auto-Brute-Force-Tool/archive/refs/tags/latest-files.zip"
ZIP_FILE="/tmp/repo.zip"
EXTRACT_DIR=$(mktemp -d) # 创建一个安全的临时解压目录

log_info "正在从 GitHub Releases 下载最新的工具包..."
# 使用 curl 下载文件，-L 参数用于跟随重定向，-o 指定输出文件
curl -L -o "$ZIP_FILE" "$ZIP_URL"
if [ $? -ne 0 ]; then
    log_error "下载工具包失败。请检查网络或手动访问 ${ZIP_URL}"
    exit 1
fi

log_info "正在解压文件..."
# -q (quiet) 安静模式, -d 指定解压目录
unzip -q "$ZIP_FILE" -d "$EXTRACT_DIR"
if [ $? -ne 0 ]; then
    log_error "解压失败。请确保 'unzip' 已安装。"
    # 清理临时文件
    rm "$ZIP_FILE"
    rm -rf "$EXTRACT_DIR"
    exit 1
fi

# GitHub 的 ZIP 包会解压到一个带 tag 名的目录中, 例如 Auto-Brute-Force-Tool-latest-files/
# 我们需要将该目录下的所有文件（包括隐藏文件）移动到当前脚本执行的目录
EXTRACTED_SUBDIR=$(ls "$EXTRACT_DIR")
log_info "正在将文件从 '$EXTRACTED_SUBDIR' 移动到当前目录..."

# shopt -s dotglob 会让 * 匹配隐藏文件（.开头的文件），这是移动所有内容的安全方式
shopt -s dotglob
mv "$EXTRACT_DIR/$EXTRACTED_SUBDIR"/* .
if [ $? -ne 0 ]; then
    log_error "移动文件失败。"
    # 清理临时文件
    rm "$ZIP_FILE"
    rm -rf "$EXTRACT_DIR"
    exit 1
fi

log_info "清理临时文件..."
rm "$ZIP_FILE"
rm -rf "$EXTRACT_DIR"

log_info "✅ 所有文件已成功下载到当前目录。"
log_info "🎉🎉🎉 脚本执行完毕！"
