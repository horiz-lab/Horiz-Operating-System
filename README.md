# HorizOS (Horiz-Operating-System)

基礎から設計された、WSL2およびDocker向けの純粋なUNIX系OS。
x86_64 および aarch64 アーキテクチャをサポート。

## [ディレクトリ構造]

- **horiz-core/**: Userland ロジック。システム本体の機能を実装するコア・コンポーネント。
  - **crates/horiz-init**: システムの初期化・プロセス管理。
  - **crates/horiz-pkg**: パッケージ管理システム。
  - **crates/horiz-sh**: インタラクティブ・シェル。
  - **crates/horiz-utils**: 基本的なコマンド群（ls, cat, echo等）。
- **rootfs/**: OS スケルトン (テンプレート)。設定ファイルやディレクトリ構造の雛形。
- **scripts/**: 各種ビルド・自動化スクリプト。
- **build.sh**: スクラッチビルドによる迅速な rootfs 構築・統合スクリプト。

## [コンポーネント]

- **Kernel**: Linux 6.19.2 (Source Built)
- **Userland**: Horiz Core (Rust / musl Static Link)
- **Init**: horiz-init (Rust Custom Implementation)

## [ビルド手順]

環境変数 `ARCH` (x86_64, aarch64) でターゲットを指定可能（デフォルトは x86_64）。

1. **Userland の構築**:
    `bash scripts/build_rootfs.sh`
    Rust プロジェクトをビルドし、`rootfs/` スケルトンと統合された `horizos-rootfs.tar.gz` を生成。

2. **カーネルの構築**:
    `bash scripts/build_kernel.sh`
    Linux 6.19.2 をダウンロードし、WSL2/汎用向けにコンパイル。

3. **ISO イメージの生成**:
    `bash scripts/build_iso.sh`
    構築した rootfs とカーネルをパッケージングし、ブート可能な ISO イメージ (`horizos-{ARCH}.iso`) を作成。

## [使用方法]

1. **WSL2 / Docker**:
    `horizos-rootfs.tar.gz` をインポートして使用せよ。

2. **仮想マシン**:
    `horizos-{ARCH}.iso` を使用して、QEMU 等の仮想マシンプラットフォームで起動せよ。
