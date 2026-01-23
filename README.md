
# Nexom
Lightweight Python Web Framework (WSGI)

Nexomは短いコードで最低限動作し、シンプルで理解のしやすい設計・構造を目指しています。
また細かい仕様も変更でき、多様な処理に対応します。

## はじめる
最初のサーバーを起動するには、3つの手順が必要です。

1. ディレクトリを作成
2. nexomをpipでインストール、サーバーのビルド
3. 起動

### 1.ディレクトリの作成
**準備**
用意していない場合はディレクトリを作成し、仮想環境も準備てください
```
mkdir sample
cd sample

python -m venv venv
source venv/bin/activate
```
### 2.npipでインストール、サーバーのビルド
**インストール**
nexomをインストールします。
※まだベータ版のため、最新のバージョンを確認してください。
```
pip install nexom==0.1.3
```
**テンプレートサーバーのビルド**
サーバーを置きたいディレクトリ上で、以下のコマンドを実行してください(sampleは自由)
```
python -m nexom build-server sample
```

### 3.起動
以下のコマンドを起動します。
```
gunicorn wsgi:app
```
ブラウザからアクセスできるようになります。
デフォルトのポートは8080です。
[httpls://localhost:8080](httpls://localhost:8080)
ポートなどの設定は `config.py` から変更してください。

## Nginx等使用して外部公開する
`config.py` で指定したポートにプロキシしてください。
```
server {
    listen 443 ssl;
        server_name nexom.ceez7.com;

        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        location / {
                proxy_pass http://localhost:8080;
        }
}
```

## Systemdに登録して自動起動する
**Ubuntuの場合**
1. `/etc/systemd/system` に、 `your_server_name.service` を作成します。
2. `your_server_name.service` に以下を書き込みます。(これは一例です。環境に合わせて設定してください。)

サーバーのディレクトリが `/home/ubuntu/nexom` にある場合
```
[Unit]
Description=Nexom Web Freamework
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/home/ubuntu/nexom
Environment="/home/ubuntu/nexom/venv/bin"
ExecStart=/home/ubuntu/nexom/venv/bin/gunicorn wsgi:app
[Install]
WantedBy=multi-user.target
```

以下のコマンドを実行します
```
sudo systemd daemon-reload
sudo systemd enable your_server_name
sudo systemd start your_server_name
```

### テンプレートユニットを活用して複数のサーバーを効率的に管理
以下の構成でサーバーが建てられていたとします。
```
/home/ubuntu/BananaProject/
└─ web/
   ├─ banana1 (Nexomサーバー)/
   │  └─ wsgi.py
   ├─ banana2 (Nexomサーバー)/
   │  └─ wsgi.py
   └─ banana3 (Nexomサーバー)/
      └─ wsgi.py
```
この構成の場合、テンプレートユニットを活用し .service ファイルを一枚にまとめられます。

`/etc/systemd/system/banana-project@.service`
```
[Unit]
Description=Nexom Web Server (%i)
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/home/ubuntu/BananaProject/web/%i
Environment="/home/ubuntu/BananaProject/web/%i/venv/bin"
ExecStart=/home/ubuntu/BananaProject/web/%i/venv/bin/gunicorn wsgi:app
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

2026 1/24