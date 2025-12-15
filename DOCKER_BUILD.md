# 使用 Docker 在 macOS 上编译 Stackplz

## 前置要求

1. **Docker Desktop for Mac** - 已安装并运行
2. **足够的磁盘空间** - 至少 5GB（用于 Docker 镜像和编译产物）

## 快速开始

### 方法 1: 使用便捷脚本（推荐）

```bash
./docker_build.sh
```

脚本会引导你选择构建方式并自动完成所有步骤。

### 方法 2: 使用 docker-compose

```bash
# 构建镜像
docker-compose build

# 运行构建
docker-compose run --rm builder
```

### 方法 3: 使用 docker 命令

```bash
# 构建镜像
docker build -t stackplz-builder .

# 运行构建
docker run --rm \
    -v $(pwd):/workspace \
    -v $(pwd)/../ebpf:/workspace/../ebpf \
    -v $(pwd)/../ebpfmanager:/workspace/../ebpfmanager \
    -v $(pwd)/bin:/workspace/bin \
    -e GOPROXY=https://goproxy.cn,direct \
    -e GO111MODULE=on \
    stackplz-builder
```

## 构建过程说明

构建过程包括以下步骤：

1. **克隆依赖库**（如果不存在）：
   - `../ebpf` - 修改过的 cilium/ebpf
   - `../ebpfmanager` - 修改过的 ebpfmanager

2. **准备编译环境**：
   - 下载 libbpf
   - 下载 bpftool
   - 下载 BTF 文件

3. **编译 arm 版本**：
   - 输出: `bin/stackplz_arm`

4. **编译 arm64 版本**：
   - 输出: `bin/stackplz_arm64`

## 输出文件

编译成功后，产物在 `bin/` 目录：

```
bin/
├── stackplz_arm      # ARM 32位版本
└── stackplz_arm64    # ARM 64位版本
```

## 目录结构要求

为了正确编译，项目目录结构应该是：

```
android/
├── ebpf/              # 需要克隆
├── ebpfmanager/       # 需要克隆
└── stackplz/          # 当前项目
    ├── Dockerfile
    ├── docker-compose.yml
    ├── build_docker.sh
    └── ...
```

如果依赖库不在正确位置，Docker 构建脚本会自动克隆它们。

## 常见问题

### 1. Docker 镜像构建失败

**问题**: 网络问题导致下载失败

**解决**: 
- 检查网络连接
- 使用代理（在 Docker Desktop 中配置）
- 重试构建

### 2. 依赖库克隆失败

**问题**: GitHub 访问问题

**解决**:
- 使用代理
- 手动克隆依赖库到正确位置：
  ```bash
  cd ..
  git clone https://github.com/SeeFlowerX/ebpf
  git clone https://github.com/SeeFlowerX/ebpfmanager
  ```

### 3. 编译失败：找不到依赖

**问题**: Go 模块找不到依赖

**解决**:
- 确保依赖库在正确位置（`../ebpf` 和 `../ebpfmanager`）
- 检查 `go.mod` 中的 replace 指令

### 4. 磁盘空间不足

**问题**: Docker 镜像和编译产物占用大量空间

**解决**:
```bash
# 清理未使用的 Docker 资源
docker system prune -a

# 清理构建缓存
docker builder prune
```

## 高级用法

### 只编译 arm64 版本

修改 `build_docker.sh`，注释掉 arm 版本的编译部分。

### 使用自定义 NDK 版本

修改 `Dockerfile` 中的 NDK 下载链接和版本号。

### 加速构建（使用缓存）

Docker 会自动缓存层，但如果需要完全重新构建：

```bash
docker-compose build --no-cache
```

## 与 GitHub Actions 的对应关系

| GitHub Actions 步骤 | Docker 对应 |
|-------------------|------------|
| Clone dependencies | build_docker.sh 步骤 1-2 |
| Set up Go | Dockerfile 中安装 Go 1.18 |
| Setup Android NDK | Dockerfile 中安装 NDK r25c |
| Build | build_docker.sh 步骤 3-4 |

## 注意事项

1. **首次构建较慢**: 需要下载 Docker 镜像、NDK、依赖库等，可能需要 10-20 分钟
2. **网络要求**: 需要访问 GitHub、Google（NDK）、Go 官方源等
3. **磁盘空间**: 建议至少 10GB 可用空间
4. **内存**: 建议至少 4GB 可用内存

## 验证编译结果

编译完成后，可以检查文件：

```bash
# 检查文件是否存在
ls -lh bin/stackplz_*

# 检查文件类型（应该是 Linux ARM 可执行文件）
file bin/stackplz_arm64

# 应该显示类似：
# bin/stackplz_arm64: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, stripped
```

