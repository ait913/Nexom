
# Nexom
Lightweight Python Web Framework (WSGI)

Nexomは短いコードで最低限動作し、シンプルで理解のしやすい設計・構造を目指しています。
また細かい仕様も変更でき、多様な処理に対応します。

## はじめる
最初のサーバーを起動するには、3つの手順が必要です。

1. プロジェクトディレクトリを作成
2. nexomをpipでインストール、アプリのビルド
3. 起動

### 1.プロジェクトディレクトリの作成
**準備**

用意していない場合はディレクトリを作成し、仮想環境も準備してください
```
mkdir banana_project
cd banana_project

python -m venv venv
source venv/bin/activate
```
### 2. pipでインストール、サーバーのビルド
**インストール**

nexomをインストールします。
```
pip install
```
**テンプレートアプリのビルド**

プロジェクトディレクトリ上で、以下のコマンドを実行してください(名前は自由)
```
python -m nexom create-app sample(名前)
```

### 3.起動
以下のコマンドを起動します。
```
gunicorn sample.wsgi:app --config sample.gunicorn.conf.py
```
ブラウザからアクセスできるようになります。
デフォルトのポートは8080です。

[https://localhost:8080](https://localhost:8080)

ポートなどの設定は `config.py` から変更してください。

