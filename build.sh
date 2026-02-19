#!/bin/bash
set -e

# HorizOS Rootfs Build Script
# Base: Alpine Linux Mini Rootfs

ALPINE_VERSION="3.19.1"
ARCH="x86_64"
ROOTFS_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION:0:4}/releases/${ARCH}/alpine-minirootfs-${ALPINE_VERSION}-${ARCH}.tar.gz"

echo "[報告] HorizOS ビルドプロセスを開始。"

# ワークディレクトリの作成
ROOTFS_DIR="build/rootfs"
mkdir -p "$ROOTFS_DIR"
cd build

# rootfsのダウンロード
if [ ! -f alpine-rootfs.tar.gz ]; then
    echo "[報告] Alpine Linux mini rootfs をダウンロード中..."
    curl -L -o alpine-rootfs.tar.gz ${ROOTFS_URL}
fi

# 解凍
echo "[報告] rootfs を展開中..."
cd rootfs
tar xzf ../alpine-rootfs.tar.gz

# カスタマイズ (テンプレートの適用)
cd ../..
if [ -d "rootfs" ]; then
    echo "[報告] rootfs テンプレートを適用中..."
    cp -r rootfs/* "$ROOTFS_DIR/"
fi

# パッケージング
echo "[報告] HorizOS rootfs をパッケージング中..."
cd "$ROOTFS_DIR"
tar czf ../../horizos-rootfs.tar.gz .

echo "[報告] ビルド完了: horizos-rootfs.tar.gz"
