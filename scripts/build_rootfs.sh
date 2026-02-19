# scripts/build_rootfs.sh - Builds Rust Userland and packages rootfs

set -e

echo "[報告] Rust 版 Userland (Horiz-Core) ビルドプロセスを開始。"

cd horiz-core

# Rustバイナリのビルド (musl ターゲットでスタティックリンク)
RUST_TARGET="x86_64-unknown-linux-musl"
if [ "$ARCH" = "aarch64" ]; then
    RUST_TARGET="aarch64-unknown-linux-musl"
fi

echo "[報告] ターゲット ${RUST_TARGET} でビルドを実行。"
cargo build --release --target ${RUST_TARGET}

# バイナリの配置
cd ..
ROOTFS_DIR="build/rootfs"
BIN_DIR="$ROOTFS_DIR/bin"

# rootfs スケルトンの用意
mkdir -p "$ROOTFS_DIR"
if [ -d "rootfs" ]; then
    echo "[報告] rootfs テンプレートを適用中..."
    cp -r rootfs/* "$ROOTFS_DIR/"
fi

mkdir -p "$BIN_DIR"

TARGET_DIR="horiz-core/target/${RUST_TARGET}/release"
cp "${TARGET_DIR}/horiz-init" "$BIN_DIR/init"
cp "${TARGET_DIR}/horiz-sh" "$BIN_DIR/sh"
cp "${TARGET_DIR}/horiz-utils" "$BIN_DIR/horiz-utils"

# ユーティリティのシンボリックリンク作成
ln -sf horiz-utils "$BIN_DIR/ls"
ln -sf horiz-utils "$BIN_DIR/cat"
ln -sf horiz-utils "$BIN_DIR/echo"

echo "[報告] Rootfs パッケージング中..."
cd "$ROOTFS_DIR"
tar czf ../../horizos-rootfs.tar.gz .

echo "[報告] ビルド完了: horizos-rootfs.tar.gz"

