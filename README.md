
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

※まだベータ版のため、最新のバージョンを確認してください。
```
pip install nexom==0.1.5
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

## Nginx等使用して外部公開する
`config.py` で指定したポートにプロキシしてください。
```
server {
    listen 443 ssl;
        server_name nexom.aisaba.net;

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        location / {
                proxy_pass http://localhost:8080;
        }
}
```

## Systemdに登録して自動起動する
**Ubuntuの場合**
1. `/etc/systemd/system` に、 `banana_sample.service` を作成します。
2. `banana_sample.service` に以下を書き込みます。(これは一例です。環境に合わせて設定してください。)

サーバーのディレクトリが `/home/ubuntu/nexom` にある場合
```
[Unit]
Description=Nexom Web Freamework
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/home/ubuntu/banana_project
Environment="PYTHONPATH=/home/ubuntu/banana_project"
ExecStart=/home/ubuntu/banana_project/venv/bin/gunicorn sample.wsgi:app --config sample/gunicorn.conf.py
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
```

以下のコマンドを実行します
```
sudo systemd daemon-reload
sudo systemd enable banana_sample
sudo systemd start banana_sample
```

### テンプレートユニットを活用して複数のサーバーを効率的に管理
_テンプレートユニットを活用し .service ファイルを一枚にまとめられます。

`/etc/systemd/system/banana-project@.service`
```
[Unit]
Description=Nexom Web Server (%i)
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/home/ubuntu/banana_project
Environment="PYTHONPATH=/home/ubuntu/banana_project"
ExecStart=/home/ubuntu/banana_project/venv/bin/gunicorn ％iwsgi:app --config %i/gunicorn.conf.py
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
```
```
sudo systemd daemon-reload

sudo systemd enable banana-project@banana1
sudo systemd enable banana-project@banana2
sudo systemd enable banana-project@banana3

sudo systemd start banana-project@banana1
sudo systemd start banana-project@banana2
sudo systemd start banana-project@banana3
```

2026 1/25
