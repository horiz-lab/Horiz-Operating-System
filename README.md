# HorizOS (Fundamental)

基礎から設計された、WSL2およびDocker向けの純粋なUNIX系OS。

## [ディレクトリ構造]

- **horiz-core/**: Userland ロジック (Rust)。システム本体の機能を実装するコア・コンポーネント。
- **rootfs/**: OS スケルトン (テンプレート)。設定ファイルやディレクトリ構造の雛形。
- **scripts/**: 各種ビルド・自動化スクリプト。

## [コンポーネント]

- **Kernel**: Linux 6.19.2 (Source Built)
- **Userland**: Horiz-Core (Rust / Source Built / Static Link)
- **Init**: horiz-init (Rust Custom Implementation)

## [ビルド手順]

1. `bash scripts/build_rootfs.sh` を実行して Rust製 Userland を構築。
2. `bash scripts/build_kernel.sh` でカーネルを構築。

ビルドプロセスは `rootfs/` ディレクトリをスケルトンとして使用し、バイナリを配置するテンプレート駆動型を採用。

## [使用方法]

`horizos-rootfs.tar.gz` を WSL2 もしくは Docker でインポートして使用せよ。
