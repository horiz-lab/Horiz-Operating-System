#!/bin/bash
# build_kernel.sh - 複数のアーキテクチャ用に Linux カーネル 6.19.2 をコンパイル

set -e

KERNEL_VERSION="6.19.3"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz"

echo "Linux Kernel ${KERNEL_VERSION} ビルドプロセスを開始。"

mkdir -p build
cd build

if [ ! -f linux.tar.xz ]; then
    echo "カーネルソースをダウンロード中..."
    curl -L -o linux.tar.xz ${KERNEL_URL}
fi

if [ ! -d linux-${KERNEL_VERSION} ]; then
    tar xf linux.tar.xz
fi

# matrix.arch → Linux カーネル ARCH / CROSS_COMPILE マッピング
INPUT_ARCH="${ARCH:-x86_64}"
CROSS_COMPILE=""
KCONFIG="defconfig"

case "${INPUT_ARCH}" in
    x86_64)
        ARCH="x86_64"
        CROSS_COMPILE=""
        KERNEL_IMAGE="arch/x86/boot/bzImage"
        ;;
    aarch64)
        ARCH="arm64"
        CROSS_COMPILE="aarch64-linux-gnu-"
        KERNEL_IMAGE="arch/arm64/boot/Image"
        ;;
    powerpc64le)
        ARCH="powerpc"
        CROSS_COMPILE="powerpc64le-linux-gnu-"
        KERNEL_IMAGE="arch/powerpc/boot/zImage"
        ;;
    s390x)
        ARCH="s390"
        CROSS_COMPILE="s390x-linux-gnu-"
        KERNEL_IMAGE="arch/s390/boot/bzImage"
        ;;
    mips64el)
        ARCH="mips"
        CROSS_COMPILE="mips64el-linux-gnuabi64-"
        KERNEL_IMAGE="arch/mips/boot/vmlinux.bin"
        ;;
    riscv64)
        ARCH="riscv"
        CROSS_COMPILE="riscv64-linux-gnu-"
        KERNEL_IMAGE="arch/riscv/boot/Image"
        ;;
    *)
        echo "未知のアーキテクチャ: ${INPUT_ARCH}。x86_64 にフォールバック。"
        ARCH="x86_64"
        CROSS_COMPILE=""
        KERNEL_IMAGE="arch/x86/boot/bzImage"
        ;;
esac

cd linux-${KERNEL_VERSION}

# 設定の適用
echo "カーネルを構成中 (ARCH: ${ARCH}, CROSS_COMPILE: ${CROSS_COMPILE:-なし}, CONFIG: ${KCONFIG})..."
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} ${KCONFIG}

# ビルド
echo "カーネルをコンパイル中..."
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} -j$(nproc)

echo "ビルド完了: ${KERNEL_IMAGE}"
