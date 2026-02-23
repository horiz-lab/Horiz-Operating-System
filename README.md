# HorizOS (Horiz-Operating-System)

基礎から設計された、WSL2およびDocker向けの純粋なUNIX系OS。
x86_64, aarch64, riscv64, powerpc64le, s390x, mips64el の主要 6 種類のアーキテクチャをサポート。
外部依存を一切排除した「Zero-Dependency」設計により、完全な透明性を実現。

## 主要なセキュリティ機能

### horiz-init

- **特権分離 (Privilege Separation)**: ログイン認証後、子プロセスへの `setuid`/`setgid` による適切な UID/GID への特権放棄。
- **セキュアな乱数源 (CSPRNG)**: `/dev/urandom` を活用したエントロピー確保。
- **シンボリックリンク攻撃対策**: ログ書き込み前にシンボリックリンクを検出してスキップ。

### horiz-auth

- **タイミング攻撃耐性**: XOR ベースの定数時間比較によるパスワードハッシュ検証。
- **SHA-256 (独自実装)**: パスワードのハッシュ化 (10,000 回ストレッチング) に使用。
- **セキュアなソルト生成**: `/dev/urandom` を利用した 16 バイトランダムソルト生成。

### horiz-pkg

- **Ed25519 署名検証 (独自実装)**: Twisted Edwards curve ベースのパッケージ署名検証。
- **SHA-512 (独自実装)**: ダウンロード後および書き込み後のデータ整合性チェックに使用。
- **原子的な配置 (TOCTOU 対策)**: 一時ファイルへの書き込み後に `rename` で原子的に置換。
- **パストラバーサル対策**: パッケージ名に `/`・`\`・`..` が含まれる場合は即時拒否。
- **DoS 対策**: HTTP/HTTPS レスポンスのバッファサイズを 100MB に制限。
- **ゼロ依存 TLS 1.3 クライアント (独自実装)**: 外部ライブラリを一切使用せず HTTPS 通信を実現。X25519, ChaCha20-Poly1305, HKDF, SHA-256 を組み込み済み。
- **TLS 証明書チェーン検証**: Ed25519 サーバー証明書の署名検証に対応し、中間者攻撃 (MITM) を防止。
- **トラストストア設定**: デフォルトで `/etc/horiz/certs.pem` を信頼済みルート証明書として読み込む。`--trust <CA_PEM_PATH>` オプションでカスタマイズ可能。

> [!TIP]
> `horiz-pkg` のより詳細なコマンドラインオプション、およびカスタムトラストストアを用いたセキュアなダウンロード方法については [horiz-pkg コマンド リファレンス](docs/commands/horiz-pkg.md) を参照してください。

## ディレクトリ構造

- **horiz-core/**: Userland ロジック。システム本体の機能を実装するコア・コンポーネント。
  - **crates/horiz-init**: システム初期化・特権管理・死活監視・構造化ロギング。 ([詳細リファレンス](docs/commands/horiz-init.md))
  - **crates/horiz-pkg**: 原子的なパッケージ配置と署名検証を備えた管理システム。 ([詳細リファレンス](docs/commands/horiz-pkg.md))
  - **crates/horiz-sh**: インタラクティブ・シェル。 ([詳細リファレンス](docs/commands/horiz-sh.md))
  - **crates/horiz-utils**: 基本的なコマンド群（ls, cat, echo, パス正規化等）。 ([詳細リファレンス](docs/commands/horiz-utils.md))
  - **crates/horiz-auth**: 定数時間比較と CSPRNG を備えた認証ライブラリ。 ([詳細リファレンス](docs/commands/horiz-auth.md))
- **scripts/**: 各種ビルド・自動化スクリプト。
- **build.sh**: スクラッチビルドによる迅速な rootfs 構築・統合スクリプト。

## コンポーネント・特徴

- **Kernel**: Linux 6.19.3 (Source Built)
- **Userland**: Horiz Core (Rust / musl Static Link / Zero-Dependency)
- **Init**: horiz-init (Custom Implementation with **Service Supervision**)
- **Security**: 独自実装の SHA-256/512, Ed25519 による署名検証と整合性チェック。
- **Logging**: `/var/log/system.log` へのタイムスタンプ付き構造化ログ出力。

## ビルド手順

環境変数 `ARCH` でターゲットを指定可能（デフォルトは x86_64）。対応値: `x86_64`, `aarch64`, `riscv64`, `powerpc64le`, `s390x`, `mips64el`。

1. **Userland の構築**:
    `bash scripts/build_rootfs.sh`
    Rust プロジェクトをビルドし、`rootfs/` スケルトンと統合された `horiz-rootfs.tar.gz` を生成。

2. **カーネルの構築**:
    `bash scripts/build_kernel.sh`
    Linux 6.19.2 をダウンロードし、WSL2/汎用向けにコンパイル。

3. **ISO イメージの生成**:
    `bash scripts/build_iso.sh`
    構築した rootfs とカーネルをパッケージングし、ブート可能な ISO イメージ (`horiz-{ARCH}.iso`) を作成。

## 使用方法

1. **WSL2 / Docker**:
    `horiz-rootfs.tar.gz` をインポートして使用。

2. **仮想マシン**:
    `horiz-{ARCH}.iso` を使用して、QEMU 等の仮想マシンプラットフォームで起動。

## ホライズちゃん かわいい

![horiz 1](assets/images/horiz%201.png)
![horiz 2](assets/images/horiz%202.png)
