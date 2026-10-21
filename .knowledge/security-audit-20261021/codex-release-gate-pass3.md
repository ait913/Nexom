# Codex リリース前ゲート 第 3 パス (177459e + b3f0e67 検証、2026-10-21)

判定 GO-WITH-FIXES。必須 2: (1) script-data double-escape (`<script><!--<script>…//</script>`) と foreign content の CDATA (`<svg><script><![CDATA[//</script>`) でトークナイザが本文判定、(2) `execute()` の SQL エラー rollback が SAVEPOINT を破壊。RG01/02/03/04/06/07/11 の旧迂回と b3f0e67 の 7 件、PS17 は閉鎖確認。

---

**必須修正が2点残ります。** 対象は `177459e`＋`b3f0e67`。途中でHEADが `e7c1e8a` に進みましたが、`src/` の差分はありません。当方によるリポジトリ変更はありません。

1. **高：HTML tokenizerの本文判定を再迂回できます。**  
   `src/nexom/core/object_html_render.py:208`
   
   以下はどちらも `{{x}}` が `DATA` と判定され、通常文字列 `globalThis.PROBE=123;` を受理します。

   ```html
   <script><!--<script>
   //</script>
   {{x}}
   </script>
   ```

   ```html
   <svg><script><![CDATA[//</script>
   {{x}}
   ]]></script></svg>
   ```

   最初の `</script>` は、前者ではdouble-escaped状態を解除するだけ、後者ではCDATA本文です。したがってスロットは依然として実行可能なscript本文にあります。[HTML仕様](https://html.spec.whatwg.org/multipage/parsing.html#script-data-double-escape-end-state)との照合、render受理、仕様上の本文をNodeで実行するところまで確認しました。ブラウザ起動は失敗したため、ブラウザ実行の実証は未完了です。該当状態を実装するか、安全に拒否してください。

2. **中：RG06はSQLエラー時のネストが未修正です。**  
   `src/nexom/app/db.py:200`、`:217`、`:131`  
   `execute()`／`execute_many()` が接続全体をrollbackするため、SAVEPOINTを破壊します。  
   「外側で行1をINSERT → 内側で重複キーエラー → 捕捉 → 行2をINSERT」で、正常終了後に**行2だけ残る**ことを再現。外側の変更とロックが途中で失われます。トランザクション中のrollbackはコンテキスト側に委ねる必要があります。

その他の閉鎖確認：

| 項目 | 結果・位置 |
|---|---|
| RG01 | 閉鎖。再ハッシュ有無の両経路で旧資格情報による発行を拒否。`auth.py:1312` |
| RG02/RG03 | 旧バイパスは閉鎖。引用符内`<`／`<!--`、空白、`/`、大文字、複数スロットを確認。ただし上記の新迂回が残存。`object_html_render.py:142` |
| RG04 | 閉鎖。通常のローカル転送で全C0＋DELを途中に入れて拒否確認。`response.py:190` |
| RG11 | 閉鎖。上限2048で1025文字のID・PWによる登録／ログイン成功。`auth.py:97` |
| RG06 | 明示commit・通常例外のrollbackは修正済み。SQLエラーは上記残存。`db.py:176` |
| RG07 | 公開APIから除去済み。Python上の生成禁止を保証するものではない点は残る。`object_html_render.py:58` |

`b3f0e67` のRouter None契約、LogoutPageのform POST、READY計上／ERROR除外、削除前owner検査と`force=True,pid=None`、DB新規作成0600、Cookieマッピングに追加欠陥は確認していません。PS17も**UPLOADING・既存チャンク維持 → 再送 → READY → commit成功**を確認しました（`parallel_storage.py:587`）。

テストは **586 passed**。30件はポートbind禁止で失敗／setup error。途中で外部追加された未コミットのテストは、この集計に含みません。

**GO-WITH-FIXES（必須：script／CDATA判定の迂回防止、SQLエラー時のSAVEPOINT保証）**
