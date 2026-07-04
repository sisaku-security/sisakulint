# pkg/ast

- ノード追加はこのパッケージだけで完結しない。pkg/core/parse_*.go の対応コンストラクタが Pos を埋める必要があり、この結合をコンパイラは検査しない。String ノードは pkg/core の newString 経由で構築しないと Quoted / Literal (YAML style フラグ) と BaseNode が欠落し、下流ルールが誤動作する。
- RawYAMLValue 実装の position フィールド名 Posi は、インターフェースの Pos() メソッドとの同名衝突回避 (typo ではない)。
