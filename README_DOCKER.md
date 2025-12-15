# Docker 编译指南

## 快速开始

在 macOS 上使用 Docker 编译 stackplz：

```bash
# 方法 1: 使用便捷脚本（推荐）
./docker_build.sh

# 方法 2: 使用 docker-compose
docker-compose build
docker-compose run --rm builder

# 方法 3: 使用 docker 命令
docker build -t stackplz-builder .
docker run --rm -v $(pwd):/workspace -v $(pwd)/bin:/workspace/bin stackplz-builder
```

详细说明请查看 [DOCKER_BUILD.md](./DOCKER_BUILD.md)

## 前置要求

- Docker Desktop for Mac
- 至少 5GB 磁盘空间
- 稳定的网络连接（需要下载 NDK、依赖库等）

## 输出

编译成功后，产物在 `bin/` 目录：
- `bin/stackplz_arm` - ARM 32位版本
- `bin/stackplz_arm64` - ARM 64位版本
