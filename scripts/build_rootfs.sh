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
case "$ARCH" in
    x86_64)
        RUST_TARGET="x86_64-unknown-linux-musl"
        ;;
    aarch64)
        RUST_TARGET="aarch64-unknown-linux-musl"
        ;;
    riscv64)
        RUST_TARGET="riscv64gc-unknown-linux-musl"
        ;;
    powerpc64le)
        RUST_TARGET="powerpc64le-unknown-linux-musl"
        ;;
    s390x)
        RUST_TARGET="s390x-unknown-linux-gnu"
        ;;
    mips64el)
        RUST_TARGET="mips64el-unknown-linux-gnuabi64"
        ;;
    *)
        echo "[警告] 未対応のアーキテクチャ: ${ARCH}"
        echo "[報告] 対応アーキテクチャ: x86_64, aarch64, riscv64, powerpc64le, s390x, mips64el"
        exit 1
        ;;
esac

echo "[報告] ターゲット ${RUST_TARGET} でビルドを実行。"
cd horiz-core
if [ "${USE_NIGHTLY:-0}" = "1" ]; then
    echo "[報告] Tier 3 ターゲット検出: nightly + build-std を使用。"
    cargo +nightly build --release --target ${RUST_TARGET} -Z build-std=std,panic_abort
else
    cargo build --release --target ${RUST_TARGET}
fi
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
[ -f "$ROOTFS_DIR/etc/shadow" ] && chmod 600 "$ROOTFS_DIR/etc/shadow"
[ -f "$ROOTFS_DIR/etc/passwd" ] && chmod 644 "$ROOTFS_DIR/etc/passwd"
[ -d "$ROOTFS_DIR/root" ] && chmod 700 "$ROOTFS_DIR/root"
[ -d "$ROOTFS_DIR/tmp" ] && chmod 1777 "$ROOTFS_DIR/tmp"
chmod 755 "$ROOTFS_DIR/bin"/*
[ -d "$ROOTFS_DIR/etc/horiz" ] && chmod 755 "$ROOTFS_DIR/etc/horiz"
[ -f "$ROOTFS_DIR/etc/horiz/pubkey" ] && chmod 644 "$ROOTFS_DIR/etc/horiz/pubkey"

echo "[報告] Rootfs パッケージング中..."
cd "$ROOTFS_DIR"
tar czf ../../horiz-rootfs.tar.gz .

echo "[報告] ビルド完了: horiz-rootfs.tar.gz"
