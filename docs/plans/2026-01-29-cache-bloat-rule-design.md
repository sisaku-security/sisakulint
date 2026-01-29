# CacheBloatRule 設計ドキュメント

## 概要

`actions/cache/restore` と `actions/cache/save` のペアを使用しているワークフローで、適切なif条件がない場合に警告し、キャッシュ肥大化を防止するルール。

## 背景

Goのビルドキャッシュなどが肥大化する問題は多くのプロジェクトで発生している。原因は以下の通り：

1. 古いキャッシュをリストア
2. 新しいビルド成果物を追加
3. 全体を再保存

これにより、キャッシュが累積的に増大していく。

## 解決策

- master/main branchへのpush時: キャッシュをリストアせず、クリーンビルドで新規キャッシュを作成
- PRのCI実行時: masterブランチで作られたキャッシュを読み取り専用で使用

## 検出条件

- 同一ジョブ内に `actions/cache/restore` と `actions/cache/save` の両方が存在
- かつ、以下のいずれかの条件を満たさない場合に警告:
  - restore: `github.event_name` を使用し、`push`を除外する条件がある
  - save: `github.event_name` を使用し、`push`に限定する条件がある

## 警告レベル

Warning（推奨レベル）

## ファイル構成

- `pkg/core/cachebloatrule.go` - ルール実装
- `pkg/core/cachebloatrule_test.go` - テスト
- `script/actions/cache-bloat-vulnerable.yaml` - 脆弱パターン例
- `script/actions/cache-bloat-safe.yaml` - 安全パターン例
- `docs/cachebloatrule.md` - ドキュメント

## 検出ロジック

1. VisitJobPre: ジョブ内のステップをスキャン
2. cache/restore と cache/save のステップを収集
3. ペアが存在する場合:
   - restore のif条件をチェック（pushを除外しているか）
   - save のif条件をチェック（pushに限定しているか）
4. 不適切な条件があれば警告を出力

## if条件の判定

- `github.event_name != 'push'` - OK（restore用）
- `github.event_name == 'push'` - OK（save用）
- `!contains(github.event_name, 'push')` - OK（restore用）
- 上記パターンの否定形も適切に判定

## エラーメッセージ

```
[cache-bloat] actions/cache/restore should have condition to skip on push events
to prevent cache bloat. Add 'if: github.event_name != 'push'' to restore step.

[cache-bloat] actions/cache/save should have condition to run only on push events
to prevent cache bloat. Add 'if: github.event_name == 'push'' to save step.
```

## auto-fix

- 既存のif条件がない場合: 新規にif条件を追加
- 既存のif条件がある場合: `&& github.event_name != 'push'`（または`== 'push'`）を追記

### 修正パターン

restore:
- Before: `if:` なし
- After: `if: github.event_name != 'push'`

save:
- Before: `if:` なし
- After: `if: github.event_name == 'push'`

既存条件がある場合:
- Before: `if: steps.cache.outputs.cache-hit != 'true'`
- After: `if: steps.cache.outputs.cache-hit != 'true' && github.event_name == 'push'`

## テストケース

1. restore/save両方にif条件なし - 両方で警告
2. restoreのみif条件なし - restoreのみ警告
3. saveのみif条件なし - saveのみ警告
4. 両方に適切なif条件あり - 警告なし
5. restoreのみ存在（saveなし） - 警告なし
6. 統合版`actions/cache`のみ使用 - 警告なし（対象外）
