#!/bin/bash
set -e

# HorizOS Build Script
# This script orchestrates the build process from scratch,
# eliminating external base image dependencies for maximum ownership.

ARCH="${ARCH:-x86_64}"

echo "HorizOS スクラッチビルドプロセスを開始 (ARCH: ${ARCH})。"

# Userland (rootfs) の構築
# Alpine Linux などの外部ベースイメージを使用せず、horiz-core から構築する
bash scripts/build_rootfs.sh

# カーネルのビルド（必要に応じて）
# bash scripts/build_kernel.sh

echo "全てのビルドプロセスが完了。horiz-rootfs.tar.gz を確認せよ。"

