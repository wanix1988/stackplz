# 基于 Ubuntu 的编译环境
FROM ubuntu:22.04

# 设置环境变量，避免交互式安装
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

# 配置阿里云镜像源（适用于 Ubuntu 22.04）
# 先使用 http 安装 ca-certificates，然后切换到 https
# 检测架构并配置相应的镜像源
# 注意：ARM64 架构需要使用 ubuntu-ports
RUN ARCH=$(dpkg --print-architecture 2>/dev/null || echo "unknown") && \
    echo "Detected architecture: $ARCH" && \
    if [ "$ARCH" = "amd64" ] || [ "$ARCH" = "i386" ]; then \
        echo "Using standard Ubuntu sources for $ARCH" && \
        echo "deb http://mirrors.aliyun.com/ubuntu/ jammy main restricted universe multiverse" > /etc/apt/sources.list && \
        echo "deb http://mirrors.aliyun.com/ubuntu/ jammy-updates main restricted universe multiverse" >> /etc/apt/sources.list && \
        echo "deb http://mirrors.aliyun.com/ubuntu/ jammy-backports main restricted universe multiverse" >> /etc/apt/sources.list && \
        echo "deb http://mirrors.aliyun.com/ubuntu/ jammy-security main restricted universe multiverse" >> /etc/apt/sources.list; \
    else \
        echo "Using ubuntu-ports sources for $ARCH" && \
        echo "deb http://mirrors.aliyun.com/ubuntu-ports/ jammy main restricted universe multiverse" > /etc/apt/sources.list && \
        echo "deb http://mirrors.aliyun.com/ubuntu-ports/ jammy-updates main restricted universe multiverse" >> /etc/apt/sources.list && \
        echo "deb http://mirrors.aliyun.com/ubuntu-ports/ jammy-backports main restricted universe multiverse" >> /etc/apt/sources.list && \
        echo "deb http://mirrors.aliyun.com/ubuntu-ports/ jammy-security main restricted universe multiverse" >> /etc/apt/sources.list; \
    fi && \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    if [ "$ARCH" = "amd64" ] || [ "$ARCH" = "i386" ]; then \
        echo "Switching to HTTPS sources for $ARCH" && \
        sed -i 's|http://mirrors.aliyun.com|https://mirrors.aliyun.com|g' /etc/apt/sources.list; \
    else \
        echo "Switching to HTTPS sources for $ARCH" && \
        sed -i 's|http://mirrors.aliyun.com|https://mirrors.aliyun.com|g' /etc/apt/sources.list; \
    fi && \
    cat /etc/apt/sources.list

# 安装基础工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    curl \
    git \
    build-essential \
    clang \
    llvm \
    make \
    tar \
    xz-utils \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 安装 Go 1.18
RUN wget https://go.dev/dl/go1.18.10.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.18.10.linux-amd64.tar.gz && \
    rm go1.18.10.linux-amd64.tar.gz

# 设置 Go 环境变量
ENV PATH=/usr/local/go/bin:$PATH
ENV GOPATH=/root/go
ENV GOPROXY=https://goproxy.cn,direct
ENV GO111MODULE=on

# 安装 Android NDK r25c
RUN mkdir -p /opt/android-ndk && \
    cd /opt/android-ndk && \
    wget https://dl.google.com/android/repository/android-ndk-r25c-linux.zip && \
    unzip android-ndk-r25c-linux.zip && \
    rm android-ndk-r25c-linux.zip && \
    mv android-ndk-r25c r25c

# 设置 NDK 环境变量
ENV ANDROID_NDK_HOME=/opt/android-ndk/r25c
ENV PATH=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH

# 设置工作目录
WORKDIR /workspace

# 复制项目文件（使用 .dockerignore 排除不需要的文件）
COPY . /workspace/

# 设置构建脚本可执行
RUN chmod +x /workspace/build_docker.sh /workspace/build_env.sh

# 默认命令
CMD ["/workspace/build_docker.sh"]

