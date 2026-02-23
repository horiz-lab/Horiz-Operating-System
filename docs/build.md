# HorizOS ビルドシステム

HorizOSは、セキュアで独立した運用ができるようスクラッチから自身のOSイメージ（RootfsおよびISO）を構築します。
ビルドプロセス全体は `build.sh` によって一元管理されており、サブスクリプト群によって特定の操作が行われます。

## 対象アーキテクチャと特殊要件

環境変数 `ARCH` を指定することで、様々なCPUアーキテクチャのビルドが可能です。
対応アーキテクチャと、Rustクロスコンパイルに用いるターゲット:

- `x86_64` (デフォルト) -> `x86_64-unknown-linux-musl`
- `aarch64` -> `aarch64-unknown-linux-musl`
- `riscv64` -> `riscv64gc-unknown-linux-musl`
- `powerpc64le` -> `powerpc64le-unknown-linux-musl`
- `s390x` -> `s390x-unknown-linux-musl`
- `mips64el` -> `mips64el-unknown-linux-muslabi64`

### Tier 3 ターゲット向けの Nightly ビルド (`USE_NIGHTLY=1`)

`USE_NIGHTLY=1` を指定すると、標準ではビルドが困難なTier 3ターゲットや特殊環境向けに、`cargo +nightly zigbuild` (zig-cc) を経由したスタティッククロスコンパイルが自動的に利用されます（この際は `-Z build-std=std,panic_abort` オプションを使用し stdlib からビルドが行われます）。

## ビルド手順詳細

### 1. Rootfs 構築 (`scripts/build_rootfs.sh`)

- `horiz-core` 配下の Rust プロジェクト群を `cargo build --target <target-triple> --release` を用いてコンパイルします。
- 外部依存を持たないMuslスタティックバイナリ群を生成し、FHS準拠（`/bin`, `/dev`, `/etc`, `/tmp`, `/var` 等）の `rootfs/` スケルトン内へ配置します。
- **配置される主なバイナリ**:
  - `horiz-init` は `/bin/init` として配置。
  - `horiz-sh` は `/bin/sh` として配置。
  - `horiz-utils` は軽量化のため `/bin/ls`, `/bin/cat`, `/bin/echo` など各種エイリアスとしてシンボリックリンクされます。
- **セキュリティの適用**:
  - ビルドホストに `/etc/ssl/certs/ca-certificates.crt` が存在する場合、そのCA証明書をルートFS内 (`/etc/ssl/certs/`) へ同梱します。
  - 各種フォルダや設定ファイル（`/etc/shadow`, `/tmp` など）に対して厳格なパーミッション (例: `/tmp`への 1777 や `shadow` への 600) を設定し権限関連の脆弱性を防ぎます。
- 最終的に `horiz-rootfs.tar.gz` としてアーカイブ化されます。

### 2. カーネル構築 (`scripts/build_kernel.sh`)

- Linux カーネル 6.19.3 のソースコードを取得します。
- 指定されたアーキテクチャ向けにクロスコンパイラ用接頭辞（例: `aarch64-linux-gnu-`）をセットし、`defconfig` を元に最適化します。
- ビルドが完了すると、`arch/<ARCH>/boot/` 内にカーネルイメージ（`bzImage`, `Image`, `zImage` 等）が生成されます。

### 3. ブート可能 ISO 生成 (`scripts/build_iso.sh`)

- 生成された `horiz-rootfs.tar.gz` を CPIO 形式の `initrd.img` (initramfs) へ変換します。
- `grub.cfg` を生成し、ISOのブートローダー (GRUB EFI 等) の設定を組み込みます。
- （注: `riscv64` は x86_64 ランナー環境の grub-efi 制約により現在 ISO の生成をスキップします）
- `grub-mkrescue` / `xorriso` を使用して `horiz-<ARCH>.iso` を出力します。

## Docker によるビルド環境

ホスト環境への依存を無くし、各種クロスコンパイル環境（clang・zig・musl等）を準備する手間を排除するため、提供されている `Dockerfile.build` を利用したクリーンコンテナ内でのビルドが推奨されます。
