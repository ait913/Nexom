# Codex リリース前ゲート 第 5 パス (2f4bc35 検証、2026-10-21)

判定 GO-WITH-FIXES。第 4 パスの 3 反例・通常描画 4 項目・追加状態 79 ケースは全て期待どおり。新規 3 系統 (いずれもテンプレート作者側の病的マークアップが前提、遠隔到達性なし): (1) `annotation-xml encoding` の文字参照未復号・重複属性の後勝ち、(2) `</p>` `</br>` 終了タグの breakout 欠落、(3) integration point 直下の `<![CDATA[` を bogus comment と誤認。Leader: 2LLM で打ち切り基準が割れたため Touri 裁定へ (CLAUDE.md エスカレーション規約)。

---

HEAD `2f4bc35` の `git show HEAD -- src/` を確認しました。**前回3件は解消していますが、受理側に倒れる仕様差が3系統残ります。** ファイル変更なし。以下、行番号は `src/nexom/core/object_html_render.py`。ブラウザ側の判定は WHATWG 仕様との照合で、実機実行ではありません。

- **前回3反例**：すべて `ObjectHTML(...)` 構築時に `TemplateUnsafeSlotError`。名前空間復帰（:263）、`<!-->`（:298）、CDATA の大小文字（:313）の修正を確認。
- **通常描画**：本文のエスケープ、引用符付き属性、ネストした render の `Markup`、`href` の `safe_url` は4/4成功。二重エスケープなし（:692）。
- **追加状態**：RCDATA の終了タグ大小文字・区切り・属性付き終了タグ、RAWTEXT 全要素、plaintext の EOF、`--!>`、bogus comment、MathML 5要素、開始タグ breakout／font 条件の79ケースは期待どおり。

**必須修正：以下はすべてロード・render が成功し、通常文字列を script 本文へ出力します。**

1. **`encoding` の文字参照未復号・重複属性の後勝ち**（:233、:244）

   ```html
   <math><annotation-xml encoding="text&#x2f;html"><script>//</annotation-xml>
   {{x}}</script>
   ```

   `encoding="text/html" encoding="x"` でも再現。ブラウザは文字参照を復号し、重複属性では先頭を採用するため HTML script。実装は foreign と判断し、祖先終了タグで script 保護を解除して **DATA として受理**します。[仕様](https://html.spec.whatwg.org/multipage/parsing.html#tree-construction)

2. **終了タグ `</p>`／`</br>` の breakout 欠落**（:252、:258）

   ```html
   <svg></p><script>//</svg>
   {{x}}</script>
   ```

   `</br>` でも再現。ブラウザは foreign content を抜けますが、実装は抜けず、後続 `</svg>` で保護を解除して **DATA として受理**します。開始タグ一覧は一致しています。[仕様](https://html.spec.whatwg.org/multipage/parsing.html#parsing-main-inforeign)

3. **integration point 直下の CDATA を bogus comment と誤認**（:225、:313）

   ```html
   <svg><foreignObject><![CDATA[><textarea>]]><script>{{x}}</script>
   ```

   CDATA 判定は子の処理モードではなく現在ノードの名前空間に従います。ブラウザでは `<textarea>` は CDATA 内の文字、その後は HTML script。実装は **RCDATA として受理**します。[仕様](https://html.spec.whatwg.org/multipage/parsing.html#markup-declaration-open-state)

その他、MathML text integration point の `mglyph`／`malignmark` 例外が未実装です（:225、:242）。確認例 `<math><mtext><mglyph><xmp>{{x}}` は過剰拒否で、その例は許容方向。ただし、例外欠落全体が安全側とは保証できません。[仕様](https://html.spec.whatwg.org/multipage/parsing.html#tree-construction)

開発者作成テンプレートという前提でも、上記3系統は「残る仕様差は拒否側のみ」というゲート条件を満たしません。

**GO-WITH-FIXES（必須：encoding 属性解釈、終了タグ breakout、integration point の CDATA 判定）**
