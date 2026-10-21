# Codex リリース前ゲート レビュー (1.2.0、2026-10-21)

対象: a39b09b..e6da40f。判定 GO-WITH-FIXES。Leader の処理: 全主張を Claude 側で再現テスト化 (`tests/test_release_gate.py`) して確定してから Developer に修正を回す (Codex 否定的主張は独立検証なしで受理しない規約)。

---

対象は **`a39b09b..e6da40f`**。ファイルは変更していません。レビュー中に作業ツリーが外部から変更されたため、未コミット変更は判定対象外です。

**1. SECURITY DEFECTS（重大度順）**

1. **High：ハッシュ移行が変更済みパスワードを旧値に戻す。**  
   `src/nexom/app/auth.py:1281`  
   旧形式のパスワードで login の照合成功 → 別 worker でパスワード変更完了 → login 側の再ハッシュ UPDATE、という順序で、旧パスワードが再設定されます。更新条件が `uid` だけで、照合したハッシュが現在も有効か確認しません。独立した DB 接続で再現し、最終状態は **旧パスワード=True、新パスワード=False**。変更時の失効処理後にセッションも発行されます。

2. **High：属性位置判定の抜けによる XSS。**  
   `src/nexom/core/object_html_render.py:292`  
   `title="prefix {{x}}"` は属性と判定されず、ネストした render の Markup が素通しになります。例えば：
   - 内側：`<span data-x="{{x}}">ok</span>`
   - 攻撃入力：` onmouseover=alert(1) `
   - 外側：`<div title="prefix {{x}}">`  
   
   出力は `<div title="prefix <span data-x=" onmouseover=alert(1) ">…` となり、外側 div にイベント属性が成立します。攻撃者が直接 `Markup()` を呼ぶ必要はありません。HTTP §4 の正規表現には忠実ですが、「Markup は本文位置のみ」という安全契約を満たしません。

3. **High：危険属性の禁止検査を回避できる。**  
   `src/nexom/core/object_html_render.py:156`  
   `<p ONCLICK="{{x}}">`、または `<p onclick="if ('x') {{x}}">` に通常文字列 `alert(1)` → 読み込み時の OH06 が発生せず、実行可能なハンドラを出力します。原因は大小文字の区別と、外側とは異なる引用符でも走査を打ち切る正規表現です。これも設計に内在する HTTP-01 の残存です。

4. **Medium：外部 Redirect 判定を先頭空白で回避できる。**  
   `src/nexom/app/response.py:30`  
   `Redirect(" /\\evil.example")`、`Redirect("\t/\\evil.example")` → `allow_external=False` でも受理。URL パーサ側の空白処理と、元文字列に対する prefix 検査が不一致です。WHATWG URL 解釈では `https://evil.example/` になります。HTTP-11 は未閉鎖です。

5. **Medium：生成される Content-Type がヘッダ検証を通らない。**  
   `src/nexom/app/response.py:81`、`:88`  
   `Response(content_type="text/plain\r\nX-Evil: 1")` → CRLF を含むヘッダを生成します。`headers=` と cookie には検証がありますが、`content_type` 経路にはありません。gunicorn では拒否に依存し、別の WSGI 配信経路ではヘッダ注入につながります。HTTP-10 の修正漏れです。

6. **Medium：アップロード件数上限の競合。**  
   `src/nexom/app/parallel_storage.py:548`、`:555`  
   同じ所有者の active が7件のとき、2接続が両方 `count_active()==7` を確認して登録 → **上限8件に対し9件**になります。再現済み。件数確認と INSERT が一体化されておらず、DATA-06 の上限は並行要求に対して成立しません。

**2. DESIGN MISMATCHES／テストが捉えていない仕様矛盾**

- **`safe_url()` と属性エスケープの組合せが壊れる。**  
  `src/nexom/core/object_html_render.py:65`、`:293`  
  `href="{{u}}"` に `safe_url("/?a=1&b=2")` → `href="/?a=1&amp;amp;b=2"`。ブラウザへ渡る URL は `/?a=1&amp;b=2` となり、パラメータ名が変わります。個々の実装手順には忠実ですが、HTTP §4 の推奨使用法・一度だけエスケープする契約と矛盾します。

- **auth の WSGI 雛形ではガード／400変換より先に例外になる。**  
  `src/nexom/assets/auth/wsgi.py:49`  
  `CONTENT_LENGTH="abc"` → 外側の `Request()` が失敗し500。`AuthService.handler()` 内なら400 A01、非許可クライアントなら先に403になるはずです。auth G 系の「解析より先にガード」と実際の公開入口が一致しません。

- 上記 XSS・Redirect・アップロード競合は、主に**設計手順自体の不足**です。「設計どおりだから修正不要」とは判定できません。

**3. SQLite ResourceWarning の所在**

**テストだけとは断定できません。両方あります。**

- 通常経路の多くはテスト側の終了処理漏れです。  
  `tests/test_auth_hardening.py:169` の fixture、`tests/test_parallel_storage.py:96` の fixture は接続を閉じません。`tests/test_version_and_log.py:242`、`:250`、`:255` なども同様です。
- **production 側にも起動失敗時の close 漏れがあります。**  
  `src/nexom/app/auth.py:300` で接続を作った後、`:303` の master 初期化が例外になっても閉じません。`tests/test_auth_hardening.py:1135`／`:1140` の「パスワードなし／短すぎる」ケースで、tracemalloc により接続生成元まで確認しました。`src/nexom/app/db.py:55` の初期化例外にも後始末がありません。

元の「3件」との一対一対応は、その実行ログなしには確定できません。警告数は GC タイミングとフィルタに左右され、未クローズ接続数とは一致しません。

**4. 移行ガイド外の回帰リスク**

- **既存 uploader は「変更不要」ではありません。**  
  `src/nexom/app/parallel_storage.py:180`、`:582`  
  4 MiB を既存 JS が3 MiB＋1 MiBに分割すると、新実装は2 MiB＋2 MiBを要求して最初のチャンクを拒否します。storage §8-2 の互換性説明は誤りです。
- **URL のクエリ・署名付き URL が壊れる。** 上記 `safe_url()` の二重エスケープは、移行ガイドに従って変更したアプリで発生します。
- **一部の旧アカウントはログイン不能。**  
  `src/nexom/app/auth.py:1235`、`:1237`  
  旧版で許容された256文字超の ID、256 UTF-8 byte 超のパスワードは、既存行でも拒否されます。auth §10.2 の「既存ユーザーはそのままログイン可」には例外があります。

検証上、全件再実行は571件成功、通信を伴う30件は sandbox の localhost bind 禁止で失敗／実行不能でした。601件 GREEN の独立再確認はできていません。

**判定：GO-WITH-FIXES。** リリース必須条件は、上記 SECURITY DEFECTS 1〜6、`safe_url()` の二重エスケープ、チャンク互換性の解決です。現状のままの出荷は承認しません。
