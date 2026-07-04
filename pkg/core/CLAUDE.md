# pkg/core

一般的な Go 慣習と異なる意図的パターンの一覧。DRY 化・並列化・「検出漏れの修正」を提案する前に確認する。

## ルール実装

- ルール名はハイフン区切り (code-injection-critical)、docs URL と docs/*.md のファイル名は連結形 (codeinjectioncritical)。自動変換はなく両方手動で揃える。
- Critical/Medium 2 本立てルールを新設するときは codeinjection.go を雛形にする: 共有実装 + thin factory、Medium 側は hasNormal && !hasPrivileged で発火して二重報告を防ぐ。トリガー判定は workflow.On を直接見ず JobTriggerAnalyzer を使う (job-level if: を考慮するため)。privileged trigger 集合は privilegedtriggers.go の既存 2 種から選び、似たマップを新設しない。
- untrusted 式の判定は pkg/expressions の BuiltinUntrustedInputs 登録と ExprError.IsUntrustedInput 参照で行う。独自の github.event.* リストや正規表現を書かない。
- プロセス横断の状態 (rate limit 記録・重複抑制) を持つルールは、LintFile / LintFiles / Lint の 3 エントリポイント先頭の reset*RunState 呼び出しに参加する。reset を忘れると 2 回目以降の Lint 呼び出しで警告が黙って消える (library 利用とテスト分離が壊れる)。
- composite action (トップレベル runs:) と dependabot ファイルは validate 冒頭で短絡され、workflow 用ルールには一切渡らない。新ルールがこれらを見ないのは仕様。

## テスト

- 支配的スタイルは YAML を parse せず ast 構造体を手組みし、VisitWorkflowPre → VisitJobPre → VisitStep を実走査と同じ順で手で呼ぶテーブル駆動。VisitWorkflowPre の呼び忘れはルール内キャッシュが空のまま「エラー 0 件」で偽パスする。

## taint (taint.go / secretinlog.go / cross_file_taint.go)

- taint の seed は 2 系統で混ぜない: TaintTracker はスクリプトリテラル内の ${{ }} から (taint.go)、SecretInLogRule は YAML の env: から (secretinlog.go)。機能追加はどちらが taint 源かで置き場所を決める。
- sanitizeForShellParse の placeholder 名 (_SISAKULINT_E_<n>_) は正規表現マッチ順のカウンタ採番で、secretinlog.go の expressionOffsetsByPlaceholder が同じ採番を独立に再構築して突き合わせる。共有定数はなく、片側だけ採番規則や正規表現を変えると位置対応が黙ってずれる (コンパイルエラーにならない)。
- shellvar: マーカーの扱いは非対称が正: TaintTracker は expandShellvarMarkers で展開して報告し、SecretInLogRule は autofix の mask 対象解決のため raw のまま保持する。揃えるリファクタは報告か autofix のどちらかを壊す。
- 検出抑制 (Offset 順序判定・::add-mask:: の出現位置判定・positional の全上流 mask 判定) は前方データフローと autofix 冪等性のための意図的な絞り込み。「検出漏れ」としてレビュー指摘・「修正」しない。seedTaintFromExpressions の scope 非対応も既知の限界で follow-up 管理 (バグ報告対象外)。
- ResolvePendingChains は errgroup.Wait() 後に単一スレッドで走る前提でロックを持たない。linter.go 側で呼び出し位置を Wait 前に動かす・並列化する変更は競合を生む。
