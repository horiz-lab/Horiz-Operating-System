#!/bin/bash
# scripts/build_iso.sh - Creates a bootable ISO image for HorizOS

set -e

ARCH="${ARCH:-x86_64}"
echo "HorizOS ISO ビルドプロセスを開始 (ARCH: ${ARCH})。"

BUILD_DIR="build/iso"
ISO_DIR="${BUILD_DIR}/root"
mkdir -p "${ISO_DIR}/boot/grub"

# 1. 必要なバイナリの確認
if [ "$ARCH" = "x86_64" ]; then
    KERNEL_IMAGE="build/linux-6.19.3/arch/x86/boot/bzImage"
    GRUB_PLATFORM="i386-pc"
elif [ "$ARCH" = "aarch64" ]; then
    KERNEL_IMAGE="build/linux-6.19.3/arch/arm64/boot/Image"
    GRUB_PLATFORM="arm64-efi"
elif [ "$ARCH" = "riscv64" ]; then
    echo "riscv64 は x86_64 ランナー環境での grub-efi モジュール制約により ISO ビルドをスキップします。"
    exit 0
else
    echo "${ARCH} は ISO ビルド未対応のアーキテクチャです。ISOステップをスキップします。"
    exit 0
fi

if [ ! -f "$KERNEL_IMAGE" ]; then
    echo "[エラー] カーネルイメージが見つかりません: ${KERNEL_IMAGE}"
    exit 1
fi

if [ ! -f "horiz-rootfs.tar.gz" ]; then
    echo "[エラー] rootfs.tar.gz が見つかりません。"
    exit 1
fi

# 2. ISO 用 initramfs の作成
echo "ISO 用 initramfs を生成中..."
INITRAMFS_DIR="${BUILD_DIR}/initramfs"
mkdir -p "${INITRAMFS_DIR}"
tar xzf horiz-rootfs.tar.gz -C "${INITRAMFS_DIR}"

# initramfs を cpio 形式で固める
(cd "${INITRAMFS_DIR}" && find . | cpio -H newc -o | gzip > "../initrd.img")
cp "${BUILD_DIR}/initrd.img" "${ISO_DIR}/boot/initrd.img"
cp "$KERNEL_IMAGE" "${ISO_DIR}/boot/vmlinuz"

# 3. GRUB 設定の作成
echo "GRUB 設定ファイルを生成中..."
cat <<EOF > "${ISO_DIR}/boot/grub/grub.cfg"
set default=0
set timeout=5

menuentry "HorizOS (${ARCH})" {
    linux /boot/vmlinuz quiet console=ttyS0 console=tty0
    initrd /boot/initrd.img
}
EOF

# 4. ISO イメージの生成
echo "xorriso を使用して ISO イメージを生成中..."
OUTPUT_ISO="horiz-${ARCH}.iso"

# GitHub Actions 環境（Ubuntu）では grub-mkrescue を使用
# --target オプションは xorriso に不正なオプションを渡すため使用しない
# x86_64: grub-pc-bin がインストール済みのため grub-mkrescue がデフォルトで i386-pc を使用
# aarch64: EFI 用モジュールディレクトリを明示指定
if [ "$ARCH" = "x86_64" ]; then
    grub-mkrescue -o "${OUTPUT_ISO}" "${ISO_DIR}" -- -as mkisofs -r
elif [ "$ARCH" = "aarch64" ]; then
    grub-mkrescue -d /usr/lib/grub/arm64-efi -o "${OUTPUT_ISO}" "${ISO_DIR}"
fi

echo "ISO ビルド完了: ${OUTPUT_ISO}"
