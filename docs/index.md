# HorizOS ドキュメント

HorizOSは、外部依存を一切持たない(Zero-Dependency)堅牢で透明性の高いシステムを目指して開発されたUnix系オペレーティングシステムです。
このドキュメント群は、システムのアーキテクチャ、ビルドプロセス、セキュリティモデル、および標準コマンドの詳細を解説します。

## 目次

### 1. システム概要

- [アーキテクチャ構成](architecture.md)
  カーネルからユーザーランド、プロセスモデルに至る全体的な設計思想と構成についての解説。
- [ビルドシステム](build.md)
  各アーキテクチャに向けたスクラッチからの完全自動ビルドプロセスと、カスタマイズ方法。
- [セキュリティ設計](security.md)
  TLS実装から署名検証、パスワード認証の仕組みまで、HorizOSが誇る高度なセキュリティモデルの詳細。

### 2. コマンドリファレンス (Userland)

Horiz-Coreとして実装されている各Rust製バイナリの仕様および利用例です。

- [horiz-init](commands/horiz-init.md) : システム初期化・特権管理・死活監視
- [horiz-auth](commands/horiz-auth.md) : 認証ライブラリと定数時間比較
- [horiz-pkg](commands/horiz-pkg.md) : TLS 1.3内蔵パッケージ管理システム
- [horiz-sh](commands/horiz-sh.md) : インタラクティブ・シェル
- [horiz-utils](commands/horiz-utils.md) : 標準のユーティリティ群（ls, cat, echo等）

### 3. APIリファレンス (Rust Docs)

内部の実装詳細やモジュール構成については、ソースコードと共に生成される `cargo doc` の出力を参照してください。
ビルド環境（例：Windows等）上でAPIドキュメントを生成する場合は、以下のようにターゲットを指定して実行します。

```bash
cd horiz-core
rustup target add x86_64-unknown-linux-musl
cargo doc --target x86_64-unknown-linux-musl --no-deps --open
```
