#!/bin/bash
# build_kernel.sh - Compiles Linux Kernel 6.19.2 for WSL2

set -e

KERNEL_VERSION="6.19.2"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz"

echo "[報告] Linux Kernel ${KERNEL_VERSION} ビルドプロセスを開始。"

mkdir -p build
cd build

if [ ! -f linux.tar.xz ]; then
    echo "[報告] カーネルソースをダウンロード中..."
    curl -L -o linux.tar.xz ${KERNEL_URL}
fi

if [ ! -d linux-${KERNEL_VERSION} ]; then
    tar xf linux.tar.xz
fi

# アーキテクチャ固有の設定
ARCH="${ARCH:-x86_64}"
CROSS_COMPILE=""
KCONFIG="defconfig"

if [ "$ARCH" = "aarch64" ]; then
    CROSS_COMPILE="aarch64-linux-gnu-"
    # aarch64 では defconfig が汎用的な初期設定として機能する
    KCONFIG="defconfig"
fi

cd linux-${KERNEL_VERSION}

# 設定の適用
echo "[報告] カーネルを構成中 (ARCH: ${ARCH}, CONFIG: ${KCONFIG})..."
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} ${KCONFIG}

# ビルド
echo "[報告] カーネルをコンパイル中..."
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} -j$(nproc)

if [ "$ARCH" = "x86_64" ]; then
    KERNEL_IMAGE="arch/x86/boot/bzImage"
else
    KERNEL_IMAGE="arch/arm64/boot/Image"
fi

echo "[報告] ビルド完了: ${KERNEL_IMAGE}"
