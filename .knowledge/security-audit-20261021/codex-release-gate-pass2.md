# Codex リリース前ゲート 第 2 パス (277c799 の修正検証、2026-10-21)

判定 GO-WITH-FIXES。必須: RG01 セッション競合 / RG02 引用符内 `<` で状態リセット / RG03 `<p/onclick=` / RG04 途中 TAB / RG11 ポリシー>1024 の不整合。付随: RG06 トランザクション合成、RG07 AttrSafe 直接生成 (遠隔性なし)。

---

**修正は一部不完全です。** `277c799` のコードで回帰テストは **15 passed**。ただし追加プローブで以下の残存問題を再現しました。行番号は同コミット基準。リポジトリのファイルは変更しておらず、レビュー中に入った外部の未コミット変更は対象外です。

1. **RG01：ハッシュ復活は修正済み。セッション競合は残存。**  
   `src/nexom/app/auth.py:1303,1310`  
   旧ハッシュ・salt 条件付き UPDATE は正しい。しかし「旧PW照合 → 別要求でPW変更・セッション失効 → 再ハッシュUPDATEが0件 → セッション発行」で、**旧認証結果から有効なtokenが発行される**ことを再現。資格情報の再確認とセッションINSERTを同一トランザクションで行う必要があります。新規退行ではなく修正漏れです。

2. **RG02：XSS迂回が残存。**  
   `src/nexom/core/object_html_render.py:114`  
   `<div title="a < {{x}}">`、または `title="a <!-- {{x}}"` で属性判定がFalseになります。内側 `<span data-x="{{x}}">ok</span>` に入力 ` onmouseover=alert(1) ` を渡したrender結果を挿入すると、外側divにイベント属性が成立します。`rfind("<")` が引用符内の `<` に状態をリセットするためです。  
   引用符内の `>`、同一タグの複数スロット、単純な未閉鎖タグは正常。`<script>` 本文は誤判定しますが、もともと明示的な非対応領域です。

3. **RG03：禁止検査の迂回が残存。**  
   `src/nexom/core/object_html_render.py:107`  
   大文字・異種引用符の修正は正常。しかし `<p/onclick="{{x}}">` に通常文字列 `alert(1)` を渡すと受理され、イベント属性になります。`<iframe/srcdoc="{{x}}">` も検査を通過。属性直前を空白などに限定する正規表現では不十分です。

4. **RG04：外部リダイレクト迂回が残存。**  
   `src/nexom/app/response.py:30,189`  
   `Redirect("/\t\\evil.example")` が受理されます。WHATWG URL実装で `https://evil.example/` への解決を確認しました。先頭だけの制御文字検査では、途中のTAB除去後に成立する `/\` を防げません。

5. **RG05：修正済み。**  
   `src/nexom/app/response.py:85`  
   charset付加後のContent-Type全体が検証されます。CRLF経路の迂回・新規退行は見つかりませんでした。

6. **RG06：件数競合は修正済み。ただしトランザクション合成に欠陥。**  
   `src/nexom/app/db.py:104`、`src/nexom/app/parallel_storage.py:389,554`  
   ロックはcountからINSERTまで維持され、元の上限超過は防げます。一方、内部`register()`の明示的commitにより、外側ブロックで例外を起こしても登録行が残ることを再現。新APIのrollback保証を満たしません。現行登録経路での上限迂回とは区別すべき問題です。なおRG06テストは例外を握り潰すため、正常な並行成功まで検証していません。

7. **RG07：二重エスケープは修正済み。型の生成制約は未実装。**  
   `src/nexom/core/object_html_render.py:58,76,328`  
   `AttrSafe('" onmouseover="alert(1)')` は検証なしで生成でき、属性注入になります。「safe_urlだけが生成する」という設計上の保証はありません。  
   ただし通常文字列・render結果が**自動的にAttrSafeへ昇格する経路は未確認**。連結・format・joinはMarkup、replaceはstrになります。直接コンストラクタに攻撃入力を渡すアプリ側処理が必要であり、無条件の遠隔脆弱性とは判定しません。

8. **RG08：修正済み。**  
   `src/nexom/assets/auth/wsgi.py:51,56`、`src/nexom/app/auth.py:359`  
   handler内の接続元ガードが先行し、不正Content-Lengthは許可元400／非許可元403。後置Requestは本文を再読せず、例外も応答を500へ変更しません。新規退行は未確認。

9. **RG09：対象の接続リークは修正済み。**  
   `src/nexom/app/auth.py:319`、`src/nexom/app/db.py:57,94`  
   master初期化失敗・DB初期化失敗・SQLite設定失敗のclose経路を確認。対象経路の修正漏れ・新規退行は未確認。

10. **RG10：互換性回復ではなく、仕様変更として文書化。**  
    `src/nexom/app/parallel_storage.py:178`、`.designs/20261021-storage-deps-hardening.md:519`  
    4MiBを3MiB＋1MiBで送る旧クライアントは引き続き失敗します。後続文書は「要修正」と移行手順を明記しており、旧説明との矛盾は解消。テスト反転は互換性修正の証明ではありません。

11. **RG11：既定ポリシーでは改善。設定次第で新規退行。**  
    `src/nexom/app/auth.py:124,132,143,1255`  
    1024超の旧資格情報が拒否される制限は文書化済み。ただし `AuthPolicy(password_max_bytes=2048)` で `"p"*1025` は**新規登録できるのにログイン不能**と再現。変更時も同じ不整合があります。登録・変更の許容範囲をログイン上限以下に統一する必要があります。

**GO-WITH-FIXES（必須：RG01の失効競合、RG02・RG03のXSS迂回、RG04の外部転送迂回、RG11の登録／ログイン上限不整合）**
