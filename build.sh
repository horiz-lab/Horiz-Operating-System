#!/bin/bash
set -e

# HorizOS ビルドスクリプト
# このスクリプトはゼロからのビルドプロセスを調整・実行し、
# 最大の所有権（オーナーシップ）のために外部ベースイメージの依存関係を排除します。

ARCH="${ARCH:-x86_64}"

echo "HorizOS スクラッチビルドプロセスを開始 (ARCH: ${ARCH})。"

# Userland (rootfs) の構築
# Alpine Linux などの外部ベースイメージを使用せず、horiz-core から構築する
bash scripts/build_rootfs.sh

# カーネルのビルド（必要に応じて）
# bash scripts/build_kernel.sh

echo "全てのビルドプロセスが完了。horiz-rootfs.tar.gz を確認せよ。"

