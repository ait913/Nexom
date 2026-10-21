# Codex リリース前ゲート 第 4 パス (14ab676 検証、2026-10-21)

初回は「try to bypass」の言い回しが OpenAI 安全フィルタで判定なし終了 (knowledge/tool-quirk/codex-behavior.md に記録)。仕様適合検証の言い回しで再実行した結果が以下。判定 GO-WITH-FIXES、必須 3: integration point の HTML 名前空間復帰 / `<!-->` 即時終了 / `[CDATA[` 大小文字。DB・Redirect・pid None は閉鎖確認。Leader 注: いずれもテンプレート作者が書く側の迂回で遠隔到達性なし。第 5 ラウンドで修正しトークナイザ反復は打ち切り、脅威モデルを doc に明記。

---

**必須修正が残ります。** HEAD `caba34f`（修正 `14ab676`）を確認。ファイル変更なし。DB の指摘は解消していますが、HTML の分類はまだ保守的ではありません。

以下は実コードの分類結果と WHATWG 仕様によるブラウザ側の判定です。ブラウザ実機実行はしていません。表中の行番号は `src/nexom/core/object_html_render.py`。

| テンプレート／スロット位置 | Nexom の判定 | ブラウザでは script 本文か |
|---|---|---|
| `<script><!-->{{x}}</script>` | 拒否：RAWTEXT（276、291行） | はい。`>` は escaped 状態を解除するだけ |
| `<script><!--<script a=b></script>{{x}}</script>` | 拒否：RAWTEXT（279、283行） | はい。内側の終了タグは double-escaped を解除するだけ |
| `<svg><p>{{x}}</p></svg>` | DATA（220行） | いいえ。`p` で foreign content を離れる |
| `<svg><foreignObject><script>{{x}}</script>…` | DATA＋foreign-script フラグで拒否（220、370行） | はい。HTML script |
| `<math><annotation-xml><script>{{x}}</script>…` | 同上、拒否 | 実行可能な script ではない。encoding 属性なしでは MathML 要素 |
| `<svg><desc><script>{{x}}</script>…` | 同上、拒否 | はい。HTML script |
| `<svg><svg></svg>{{x}}</svg>` | DATA（193行） | いいえ |
| `<script></SCRIPT >{{x}}` | DATA（268行） | いいえ |
| `<script></script/>{{x}}` | DATA（268行） | いいえ。構文エラーでも script は閉じる |
| `<script>{{x}}</script`＋EOF | 拒否：RAWTEXT | はい。未完成終了タグは本文扱い |
| `<svg><script><![CDATA[a]]b{{x}}…` | 拒否：CDATA（260行） | はい。`]]` だけでは終了しない |
| `<svg><![CDATA[]]{{x}}>`／`…]{{x}}]>` | 拒否：CDATA | いいえ。ただし script 内なら script 本文 |
| `<svg><![CDATA[a]]>{{x}}</svg>` | DATA | いいえ |
| `<![CDATA[{{x}}]]>`（HTML 名前空間） | 拒否：COMMENT（236行） | いいえ。bogus comment |

`{{x]]>}}` のように**スロット自体**を分断した場合は、スロットとして認識されず置換もされません（94行）。

以上の単純形は許容できます。[script 状態の仕様](https://html.spec.whatwg.org/multipage/parsing.html#script-data-escaped-state)、[CDATA の仕様](https://html.spec.whatwg.org/multipage/parsing.html#cdata-section-state)、[foreign content の仕様](https://html.spec.whatwg.org/multipage/parsing.html#parsing-main-inforeign)と照合しました。

ただし、次の **3反例はすべて DATA と判定され、通常文字列 `globalThis.PROBE=123;` のロード・render を受理**しました。仕様上はいずれも実行可能な script 本文です。

```html
<svg><foreignObject><script>//</foreignObject>
{{x}}</script></foreignObject></svg>

<!--><script>//-->
{{x}}</script>

<svg><![cdata[><script>//]]>
{{x}}</script></svg>
```

- **foreign content の判定不足**：祖先終了タグで script までスタックから除去します。ブラウザでは `foreignObject` 内は HTML script なので、その終了タグは本文です。`desc`、および `<svg><p><script>//</p>` でも同様。修正箇所：`object_html_render.py:193`、`:201`、`:220`。[integration point の仕様](https://html.spec.whatwg.org/multipage/parsing.html#tree-construction)
- **コメントの早期終了不足**：`<!-->` はブラウザでは直ちに閉じますが、実装は後続の `-->` まで読み飛ばします。修正箇所：`object_html_render.py:227`、`:255`。[comment start の仕様](https://html.spec.whatwg.org/multipage/parsing.html#comment-start-state)
- **CDATA の大小文字誤判定**：`[CDATA[` は大小文字を区別します。小文字版は bogus comment ですが、実装の `.lower()` は CDATA として扱い、後続 script 開始を読み飛ばします。修正箇所：`object_html_render.py:231`。[markup declaration open の仕様](https://html.spec.whatwg.org/multipage/parsing.html#markup-declaration-open-state)

DB はメモリ内 SQLite で、`execute()` の重複キー、`execute_many()` の途中失敗、遅延外部キーによる COMMIT 失敗を検証しました。すべて **暗黙 BEGIN → ROLLBACK、`in_transaction=False`**。ネストした SQL エラーでも外側の変更を保持します。`src/nexom/app/db.py:200`、`:217`、`:234`、`:138`。

Redirect の RS02 は `allow_external` 両値で確認済み（`src/nexom/app/response.py:194`）。pid `None`／空文字の `PsPermissionError` も確認済み（`src/nexom/app/parallel_storage.py:364`）。

**GO-WITH-FIXES（必須：foreign／HTML 名前空間遷移、コメント早期終了、CDATA の大小文字判定の3点を修正）**
