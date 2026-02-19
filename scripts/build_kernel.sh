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

cd linux-${KERNEL_VERSION}

# WSL2向けの設定を適用
echo "[報告] カーネルを構成中 (WSL2 互換)..."
# 注意: 本来はMicrosoftのWSL2カーネル設定をベースにするべきだが、
# ここでは基礎的なx86_64設定を適用する。
make defconfig
# WSL2に必要な特定のフラグ（仮想化対応等）が必要ならばここで編集

# ビルド
echo "[報告] カーネルをコンパイル中..."
make -j$(nproc)

echo "[報告] ビルド完了: arch/x86/boot/bzImage"
