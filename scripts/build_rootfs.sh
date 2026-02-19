# scripts/build_rootfs.sh - Builds Rust Userland and creates a clean rootfs from scratch

set -e

ARCH="${ARCH:-x86_64}"
echo "[報告] Userland (Horiz Core) スクラッチビルドを開始。"

# ワークディレクトリの準備
ROOTFS_DIR="build/rootfs"
rm -rf "$ROOTFS_DIR"
mkdir -p "$ROOTFS_DIR"

# 必須ディレクトリの作成 (FHS 準拠)
mkdir -p "$ROOTFS_DIR"/{bin,dev,etc,proc,sys,tmp,var,root,home/horiz}

# Rustバイナリのビルド (musl ターゲットでスタティックリンク)
RUST_TARGET="x86_64-unknown-linux-musl"
if [ "$ARCH" = "aarch64" ]; then
    RUST_TARGET="aarch64-unknown-linux-musl"
fi

echo "[報告] ターゲット ${RUST_TARGET} でビルドを実行。"
cd horiz-core
cargo build --release --target ${RUST_TARGET}
cd ..

# バイナリの配置
BIN_DIR="$ROOTFS_DIR/bin"
TARGET_DIR="horiz-core/target/${RUST_TARGET}/release"

cp "${TARGET_DIR}/horiz-init" "$BIN_DIR/init"
cp "${TARGET_DIR}/horiz-sh" "$BIN_DIR/sh"
cp "${TARGET_DIR}/horiz-pkg" "$BIN_DIR/horiz-pkg"
cp "${TARGET_DIR}/horiz-utils" "$BIN_DIR/horiz-utils"

# ユーティリティのシンボリックリンク作成
ln -sf horiz-pkg "$BIN_DIR/pkg"
ln -sf horiz-utils "$BIN_DIR/ls"
ln -sf horiz-utils "$BIN_DIR/cat"
ln -sf horiz-utils "$BIN_DIR/echo"

# rootfs スケルトン (設定ファイル等) の適用
if [ -d "rootfs" ]; then
    echo "[報告] rootfs テンプレートを適用中..."
    cp -r rootfs/* "$ROOTFS_DIR/"
fi

# HTTPS 通信のための CA 証明書の配置
echo "[報告] CA 証明書を配置中..."
mkdir -p "$ROOTFS_DIR/etc/ssl/certs"
# ビルド環境が Debian/Ubuntu の場合、システムからコピーする。
if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
    cp /etc/ssl/certs/ca-certificates.crt "$ROOTFS_DIR/etc/ssl/certs/"
fi

# 権限設定の強化 (VULN-004 の解消)
echo "[報告] ファイル権限を強化中..."
chmod 600 "$ROOTFS_DIR/etc/shadow"
chmod 644 "$ROOTFS_DIR/etc/passwd"
chmod 700 "$ROOTFS_DIR/root"
chmod 755 "$ROOTFS_DIR/bin"/*
chmod 755 "$ROOTFS_DIR/etc/horiz"
chmod 644 "$ROOTFS_DIR/etc/horiz/pubkey"

echo "[報告] Rootfs パッケージング中..."
cd "$ROOTFS_DIR"
tar czf ../../horiz-rootfs.tar.gz .

echo "[報告] ビルド完了: horiz-rootfs.tar.gz"


