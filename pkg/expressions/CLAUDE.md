# pkg/expressions

- untrusted 入力のツリー (anti_untrustedmap.go) を変更するときは、BuiltinUntrustedInputs と CreateUntrustedInputsWithTaintedReusableWorkflowInputs が生成するコピー側の両方に反映されるかを確認する (reusable workflow 経路は後者を通る)。
- ノード追加時、Children == nil (leaf) は単独出現で常に報告、非 nil (中間) は toJSON 等の関数引数内でのみ報告と、検出条件そのものが変わる。leaf/中間は意図して選ぶ。
- anti_untrustedchecker.go のエラーメッセージ文言 "potentially untrusted" は pkg/core/taint.go が文字列マッチしている (IsUntrustedInput への移行途中)。文言を変えると taint 検出が黙って壊れるため、変更時は先に呼び出し元を移行する。
- untrusted 検出は NewExprSemanticsChecker の第 1 引数 checkUntrustedInput=true のときだけ有効。呼び出し側 (pkg/core) がフラグを渡し忘れてもエラーにならず検出だけが全滅する。
