#!/bin/bash
set -e

echo "=== Stackplz Docker 构建脚本 ==="

# 进入工作目录
cd /workspace

# 1. 克隆依赖库（如果不存在）
# Docker 容器中，依赖库挂载到 /ebpf 和 /ebpfmanager
# go.mod 中使用的是 ../ebpf，相对于 /workspace，即 /ebpf
# 所以需要确保 /ebpf 和 /ebpfmanager 存在且有内容

# 检查并克隆 ebpf
if [ ! -d "/ebpf" ] || [ ! -f "/ebpf/go.mod" ]; then
    echo "[1/5] ebpf 依赖不存在或为空，开始克隆..."
    if [ -d "/ebpf" ] && [ -z "$(ls -A /ebpf 2>/dev/null)" ]; then
        echo "      /ebpf 目录存在但为空，清空后重新克隆"
        rm -rf /ebpf/*
    fi
    if [ ! -d "/ebpf" ]; then
        mkdir -p /ebpf
    fi
    cd /ebpf
    git clone https://github.com/SeeFlowerX/ebpf .
    cd /workspace
else
    echo "[1/5] ebpf 依赖已存在: /ebpf"
fi

# 检查并克隆 ebpfmanager
if [ ! -d "/ebpfmanager" ] || [ ! -f "/ebpfmanager/go.mod" ]; then
    echo "[2/5] ebpfmanager 依赖不存在或为空，开始克隆..."
    if [ -d "/ebpfmanager" ] && [ -z "$(ls -A /ebpfmanager 2>/dev/null)" ]; then
        echo "      /ebpfmanager 目录存在但为空，清空后重新克隆"
        rm -rf /ebpfmanager/*
    fi
    if [ ! -d "/ebpfmanager" ]; then
        mkdir -p /ebpfmanager
    fi
    cd /ebpfmanager
    git clone https://github.com/SeeFlowerX/ebpfmanager .
    cd /workspace
else
    echo "[2/5] ebpfmanager 依赖已存在: /ebpfmanager"
fi

# 创建符号链接，使 ../ebpf 指向 /ebpf（相对于 /workspace）
# /workspace 的父目录是 /，所以 ../ebpf 应该是 /ebpf
# 但为了确保兼容性，创建符号链接
if [ ! -e "/ebpf_link" ] && [ -d "/ebpf" ]; then
    # 实际上不需要符号链接，因为 /workspace/../ebpf 就是 /ebpf
    # 但为了确保路径正确，我们直接验证
    echo "验证依赖库路径..."
fi

# 验证依赖库是否存在且有效
if [ ! -d "/ebpf" ] || [ ! -f "/ebpf/go.mod" ]; then
    echo "错误: ebpf 依赖库不存在或无效"
    echo "     期望路径: /ebpf"
    echo "     实际检查:"
    ls -la /ebpf 2>/dev/null || echo "/ebpf 不存在"
    exit 1
fi

if [ ! -d "/ebpfmanager" ] || [ ! -f "/ebpfmanager/go.mod" ]; then
    echo "错误: ebpfmanager 依赖库不存在或无效"
    echo "     期望路径: /ebpfmanager"
    echo "     实际检查:"
    ls -la /ebpfmanager 2>/dev/null || echo "/ebpfmanager 不存在"
    exit 1
fi

echo "依赖库验证通过:"
echo "  ebpf: /ebpf ($(ls -1 /ebpf | wc -l) 个文件/目录)"
echo "  ebpfmanager: /ebpfmanager ($(ls -1 /ebpfmanager | wc -l) 个文件/目录)"

# 2. 准备编译环境
if [ ! -d "libbpf" ]; then
    echo "[3/5] 准备编译环境（libbpf, bpftool, BTF文件）..."
    bash ./build_env.sh
else
    echo "[3/5] 编译环境已准备，跳过"
fi

# 3. 编译 arm 版本
echo "[4/5] 编译 arm 版本..."
make clean
BUILD_TAGS=forarm make
if [ -f "bin/stackplz_arm" ]; then
    echo "✓ arm 版本编译成功: bin/stackplz_arm"
else
    echo "✗ arm 版本编译失败"
    exit 1
fi

# 4. 编译 arm64 版本
echo "[5/5] 编译 arm64 版本..."
make clean
make
if [ -f "bin/stackplz_arm64" ]; then
    echo "✓ arm64 版本编译成功: bin/stackplz_arm64"
else
    echo "✗ arm64 版本编译失败"
    exit 1
fi

echo ""
echo "=== 编译完成 ==="
echo "输出文件："
ls -lh bin/stackplz_*

