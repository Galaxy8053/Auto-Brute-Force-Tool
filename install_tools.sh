#!/bin/bash

# ==============================================================================
#  一键安装最新版 Python, Go, screen, masscan 并下载文件脚本 (v5 - 已支持 AlmaLinux)
#
#  功能:
#  1. 自动检测并适配 Debian/Ubuntu/CentOS/AlmaLinux 等主流 Linux 发行版。
#  2. 安装系统默认的稳定版 Python 3。
#  3. **安装 screen 和 masscan。**
#  4. 从官网下载并安装最新版本的 Go 语言环境。
#  5. 将 https://github.com/CXK-Computer/Auto-Brute-Force-Tool 仓库的所有文件下载到当前目录。
#
#  使用方法:
#  在您的终端中运行以下单行命令:
#  bash <(curl -sL https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/main/install_tools.sh)
# ==============================================================================

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
    exit 1
}

# --- 主逻辑开始 ---
log_info "脚本开始执行..."

# 1. 检查是否以 root 用户运行
if [ "$(id -u)" -ne 0 ]; then
   log_error "此脚本需要以 root 权限运行。请使用 'sudo' 或切换到 root 用户后重试。"
fi

# 2. 安装基础依赖和 Python
log_info "正在检测操作系统并安装依赖..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    log_error "无法检测到您的操作系统。脚本无法继续。"
fi

log_info "检测到操作系统为: $OS"

if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    log_info "正在更新 apt 包管理器..."
    apt-get update -y
    log_info "正在安装 Python 3, screen, masscan 及基础工具..."
    apt-get install -y python3 curl wget git tar screen masscan || log_error "通过 apt 安装依赖失败。"

elif [[ "$OS" == "centos" || "$OS" == "rhel" || "$OS" == "fedora" || "$OS" == "almalinux" ]]; then # <--- 修改点：在此处添加了 almalinux
    log_info "正在更新 yum/dnf 包管理器..."
    if command -v dnf &> /dev/null; then
        log_info "正在安装 Python 3, screen, masscan 及基础工具..."
        dnf install -y python3 curl wget git tar screen masscan || log_error "通过 dnf 安装依赖失败。"
    else
        yum install -y epel-release
        log_info "正在安装 Python 3, screen, masscan 及基础工具..."
        yum install -y python3 curl wget git tar screen masscan || log_error "通过 yum 安装依赖失败。"
    fi
else
    log_error "不支持的操作系统: $OS。请手动安装 Python 3, Curl, Wget, Git, Tar, screen, masscan。"
fi

log_info "✅ Python 3, screen, masscan 和基础工具已成功安装。"

# 3. 安装最新版 Go
log_info "正在准备安装最新版本的 Go..."

# 检测系统架构
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) GO_ARCH="amd64" ;;
    aarch64) GO_ARCH="arm64" ;;
    *) log_error "不支持的 CPU 架构: $ARCH。无法自动安装 Go。" ;;
esac

# 从官网获取最新版本号并下载
log_info "正在从 go.dev 获取最新版本信息..."
GO_LATEST_VERSION=$(curl -sL "https://go.dev/VERSION?m=text" | head -n 1)
if [ -z "$GO_LATEST_VERSION" ]; then
    log_error "无法获取 Go 的最新版本号，请检查网络。"
fi

GO_TARBALL="${GO_LATEST_VERSION}.linux-${GO_ARCH}.tar.gz"
DOWNLOAD_URL="https://go.dev/dl/${GO_TARBALL}"

log_info "正在下载 Go ${GO_LATEST_VERSION} for ${GO_ARCH}..."
wget -q -O "/tmp/${GO_TARBALL}" "${DOWNLOAD_URL}"
if [ $? -ne 0 ]; then
    log_error "下载 Go 安装包失败。请检查网络或访问 ${DOWNLOAD_URL}"
fi

# 安装 Go
log_info "正在安装 Go..."
rm -rf /usr/local/go # 清理旧版本
tar -C /usr/local -xzf "/tmp/${GO_TARBALL}"
rm "/tmp/${GO_TARBALL}" # 清理下载的压缩包

# 配置环境变量
log_info "正在配置 Go 的环境变量..."
if ! grep -q "/usr/local/go/bin" /etc/profile; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
fi

# 使环境变量在当前会话中也生效
export PATH=$PATH:/usr/local/go/bin

# 验证安装
if command -v go &> /dev/null; then
    INSTALLED_GO_VERSION=$(go version)
    log_info "✅ Go 安装成功: ${INSTALLED_GO_VERSION}"
else
    log_error "Go 安装失败。在 PATH 中找不到 'go' 命令。"
fi

# 4. 下载 GitHub 仓库文件到当前目录
REPO_URL="https://github.com/CXK-Computer/Auto-Brute-Force-Tool.git"
TEMP_DIR=$(mktemp -d) # 创建一个安全的临时目录

log_info "正在从 GitHub 仓库下载所有文件..."
git clone --depth 1 "$REPO_URL" "$TEMP_DIR"
if [ $? -ne 0 ]; then
    rm -rf "$TEMP_DIR"
    log_error "从 GitHub 下载文件失败。请检查您的网络连接或 Git 是否已正确安装。"
fi

log_info "正在将文件移动到当前目录..."
# 启用 dotglob 以确保 .gitignore 等隐藏文件也能被移动
shopt -s dotglob
# 将临时目录中的所有内容移动到当前目录
mv -f "$TEMP_DIR"/* .
# 禁用 dotglob
shopt -u dotglob

# 清理空的临时目录
rm -rf "$TEMP_DIR"

log_info "✅ 所有文件已成功下载到当前目录。"

# --- 结束 ---
echo
log_info "🎉 所有任务已完成！"
echo -e "${GREEN}===================================================================${NC}"
echo -e "${GREEN} 环境已准备就绪，所有文件已下载到当前目录中。${NC}"
echo -e "${GREEN} 请重新登录或执行 'source /etc/profile' 以使 Go 环境变量永久生效。${NC}"
echo -e "${GREEN}===================================================================${NC}"
