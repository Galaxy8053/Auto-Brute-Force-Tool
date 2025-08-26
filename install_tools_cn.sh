#!/bin/bash

# ==============================================================================
#  一键安装最新版 Python, Go, screen, masscan 并下载文件脚本 (v4-CN-Final)
#
#  [中国大陆最终优化版]
#  此版本针对在中国大陆地区使用进行了网络优化，主要包括:
#  1. 将系统 APT/YUM/DNF 源替换为阿里云镜像源，加速依赖下载。
#  2. 将 Go 的版本检查 和 安装包下载 全部指向中国的官方镜像，彻底解决 go.dev 访问问题。
#  3. 使用 GitHub 代理，加速仓库文件下载。
#
#  使用方法:
#  将此脚本内容完整复制，保存为 install.sh 文件，然后执行:
#  bash install.sh
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

# --- 切换镜像源函数 (中国优化) ---
change_mirror() {
    log_info "正在为您切换到速度更快的阿里云镜像源..."
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        log_info "备份原始源文件到 /etc/apt/sources.list.bak..."
        cp /etc/apt/sources.list /etc/apt/sources.list.bak
        sed -i 's|http://.*.archive.ubuntu.com|http://mirrors.aliyun.com|g' /etc/apt/sources.list
        sed -i 's|http://security.ubuntu.com|http://mirrors.aliyun.com|g' /etc/apt/sources.list
        sed -i 's|http://deb.debian.org|http://mirrors.aliyun.com|g' /etc/apt/sources.list
        sed -i 's|http://security.debian.org|http://mirrors.aliyun.com|g' /etc/apt/sources.list
        log_info "镜像源已切换至阿里云。"
    elif [[ "$OS" == "centos" || "$OS" == "rhel" ]]; then
        log_info "备份原始源文件..."
        mkdir -p /etc/yum.repos.d/backup/
        mv /etc/yum.repos.d/*.repo /etc/yum.repos.d/backup/
        RELEASE_VERSION=$(rpm -q --queryformat '%{VERSION}' centos-release)
        if [ -z "$RELEASE_VERSION" ]; then
            RELEASE_VERSION=$(grep -oE '[0-9]+' /etc/redhat-release | head -n 1)
        fi
        log_info "检测到 CentOS 版本为: $RELEASE_VERSION"
        curl -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-${RELEASE_VERSION}.repo || log_error "下载阿里云 CentOS repo 文件失败。"
        if [[ "$RELEASE_VERSION" == "7" ]]; then
           curl -o /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/epel-7.repo || log_warn "下载阿里云 EPEL repo 文件失败。"
        fi
        log_info "镜像源已切换至阿里云。"
    fi
}


# --- 主逻辑开始 ---
log_info "脚本开始执行 (中国大陆最终优化版)..."

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

change_mirror

if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    log_info "正在更新 apt 包管理器..."
    apt-get update -y
    log_info "正在安装 Python 3, screen, masscan 及基础工具..."
    apt-get install -y python3 curl wget git tar screen masscan || log_error "通过 apt 安装依赖失败。"

elif [[ "$OS" == "centos" || "$OS" == "rhel" || "$OS" == "fedora" ]]; then
    log_info "正在清理并生成新的 dnf/yum 缓存..."
    if command -v dnf &> /dev/null; then
        dnf clean all && dnf makecache
        log_info "正在安装 Python 3, screen, masscan 及基础工具..."
        dnf install -y python3 curl wget git tar screen masscan || log_error "通过 dnf 安装依赖失败。"
    else
        yum clean all && yum makecache
        yum install -y epel-release || log_warn "安装 epel-release 可能需要阿里云的 epel 源。"
        log_info "正在安装 Python 3, screen, masscan 及基础工具..."
        yum install -y python3 curl wget git tar screen masscan || log_error "通过 yum 安装依赖失败。"
    fi
else
    log_error "不支持的操作系统: $OS。请手动安装。"
fi

log_info "✅ Python 3, screen, masscan 和基础工具已成功安装。"

# 3. 安装最新版 Go
log_info "正在准备安装最新版本的 Go..."

ARCH=$(uname -m)
case "$ARCH" in
    x86_64) GO_ARCH="amd64" ;;
    aarch64) GO_ARCH="arm64" ;;
    *) log_error "不支持的 CPU 架构: $ARCH。无法自动安装 Go。" ;;
esac

# [中国优化] 从中国的 Go 官方镜像获取版本号
log_info "正在从中国镜像 (golang.google.cn) 获取最新版本信息..."
GO_LATEST_VERSION=$(curl -sL "https://golang.google.cn/VERSION?m=text" | head -n 1)
if [ -z "$GO_LATEST_VERSION" ]; then
    log_error "无法获取 Go 的最新版本号，请检查网络或 'golang.google.cn' 是否可访问。"
fi

GO_TARBALL="${GO_LATEST_VERSION}.linux-${GO_ARCH}.tar.gz"
# [中国优化] 使用中国的 Go 官方镜像下载
DOWNLOAD_URL="https://golang.google.cn/dl/${GO_TARBALL}"

log_info "正在从中国镜像下载 Go ${GO_LATEST_VERSION} for ${GO_ARCH}..."
wget -q -O "/tmp/${GO_TARBALL}" "${DOWNLOAD_URL}"
if [ $? -ne 0 ]; then
    log_error "下载 Go 安装包失败。请尝试访问 ${DOWNLOAD_URL}"
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
    INSTALLED_GO_VERSION=$(go version)
    log_info "✅ Go 安装成功: ${INSTALLED_GO_VERSION}"
else
    log_error "Go 安装失败。在 PATH 中找不到 'go' 命令。"
fi

# 4. 下载 GitHub 仓库文件到当前目录
# [中国优化] 使用代理加速 GitHub 下载
REPO_URL="https://github.com/CXK-Computer/Auto-Brute-Force-Tool.git"
PROXY_REPO_URL="https://ghproxy.com/${REPO_URL}"
TEMP_DIR=$(mktemp -d)

log_info "正在通过代理从 GitHub 仓库下载所有文件..."
git clone --depth 1 "$PROXY_REPO_URL" "$TEMP_DIR"
if [ $? -ne 0 ]; then
    rm -rf "$TEMP_DIR"
    log_error "从 GitHub 下载文件失败。请检查网络连接或 Git 是否已正确安装。"
fi

log_info "正在将文件移动到当前目录..."
shopt -s dotglob
mv -f "$TEMP_DIR"/* .
shopt -u dotglob
rm -rf "$TEMP_DIR"

log_info "✅ 所有文件已成功下载到当前目录。"

# --- 结束 ---
echo
log_info "🎉 所有任务已完成！"
echo -e "${GREEN}===================================================================${NC}"
echo -e "${GREEN} 环境已准备就绪，所有文件已下载到当前目录中。${NC}"
echo -e "${GREEN} 请重新登录或执行 'source /etc/profile' 以使 Go 环境变量永久生效。${NC}"
echo -e "${GREEN}===================================================================${NC}"
