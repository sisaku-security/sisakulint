# pkg/shell

- bash AST 上の純関数のみで構成し、GitHub Actions の知識 (${{ }}, secrets.* の意味論) を持ち込まない。${{ }} は bash 構文として不正でパーサを壊すため、前処理 (sanitizeForShellParse) は呼び出し側 pkg/core の責務。
- ScopedTaint は sink 判定に At(stmt)、cross-step 伝播の記録に Final を使い分ける。At の Final フォールバック、未呼び出し関数の不可視、再帰 depth 1、forward reference 非追跡、関数内 non-local 代入の非伝播は、いずれも bash 挙動への忠実性か FP 抑制のための確定仕様 (docs/superpowers/specs/ の #446-#448 設計書が根拠)。網羅性の欠陥としてレビュー指摘・「修正」しない。
- Entry.Sources の順序と Offset の意味論は pkg/core の報告 origin・autofix 対象選択・golden テストが依存する公開契約。並び替え・set 化をしない。
