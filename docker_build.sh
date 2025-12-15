#!/bin/bash
# macOS 上使用 Docker 编译 stackplz 的便捷脚本

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Stackplz Docker 构建工具 ==="
echo ""

# 检查 Docker 是否安装
if ! command -v docker &> /dev/null; then
    echo "错误: 未找到 Docker，请先安装 Docker Desktop"
    exit 1
fi

# 检查 Docker 是否运行
if ! docker info &> /dev/null; then
    echo "错误: Docker 未运行，请启动 Docker Desktop"
    exit 1
fi

echo "选择构建方式："
echo "1. 使用 docker-compose（推荐）"
echo "2. 使用 docker build + run"
read -p "请选择 (1/2): " choice

case $choice in
    1)
        echo ""
        echo "使用 docker-compose 构建..."
        docker-compose build
        docker-compose run --rm builder
        ;;
    2)
        echo ""
        echo "使用 docker build + run 构建..."
        
        # 构建镜像（在 macOS 上使用 linux/amd64 平台）
        echo "构建 Docker 镜像（平台: linux/amd64）..."
        docker build --platform linux/amd64 -t stackplz-builder .
        
        # 运行容器
        echo "运行构建容器..."
        docker run --rm --platform linux/amd64 \
            -v "$SCRIPT_DIR:/workspace" \
            -v "$SCRIPT_DIR/../ebpf:/workspace/../ebpf" \
            -v "$SCRIPT_DIR/../ebpfmanager:/workspace/../ebpfmanager" \
            -v "$SCRIPT_DIR/bin:/workspace/bin" \
            -e GOPROXY=https://goproxy.cn,direct \
            -e GO111MODULE=on \
            stackplz-builder
        ;;
    *)
        echo "无效选择"
        exit 1
        ;;
esac

echo ""
echo "=== 构建完成 ==="
if [ -d "bin" ] && [ -n "$(ls -A bin 2>/dev/null)" ]; then
    echo "编译产物在 bin/ 目录："
    ls -lh bin/
else
    echo "警告: bin/ 目录为空或不存在"
fi

