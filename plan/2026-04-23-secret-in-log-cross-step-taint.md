# secret-in-log cross-step taint 実装計画 (Issue #437)

## Goal

`secret-in-log` ルールの taint 伝播を、単一 run ステップから **同一 Job 内の step 間** へ拡張する。
`echo "VAR=$DERIVED" >> $GITHUB_ENV` のような `$GITHUB_ENV` 経由の伝播を taint source として
後続 step に引き継ぎ、これまで未検出だった FN を検出する。

## 検出対象（未検出だったパターン）

```yaml
steps:
  - run: |
      DERIVED=$(echo $SECRET_JSON | jq -r '.key')
      echo "TOKEN=$DERIVED" >> $GITHUB_ENV
  - run: |
      echo "$TOKEN"   # ← 検出対象
```

## 対応範囲

### In scope
- `echo "NAME=$VAL" >> $GITHUB_ENV` / `echo NAME=$VAL >> "$GITHUB_ENV"`（クォート有無）
- `echo "NAME=$VAL" > $GITHUB_ENV`（overwrite）
- `printf '%s\n' "NAME=$VAL" >> $GITHUB_ENV`（第 1 引数が NAME=VAL 形式）
- `cat <<EOF >> $GITHUB_ENV\nNAME=$VAL\nEOF`（heredoc、本文内で tainted 参照）
- 同一 job 内で step1 → step2 → step3 と連鎖する伝播

### Out of scope（follow-up として別 issue）
- クロス job 伝播 (`needs.*.outputs.*`)（#432）
- reusable workflow 跨ぎ (#433)
- `${NAME}` / bash-specific な変数展開拡張のコーナーケース
- `$GITHUB_ENV` に書く際の **add-mask** 補助 auto-fix（MVP では当面、sink 側 step の既存 auto-fix で対処）

## 実装方針

### データフロー

```
prev step の script
  └─ taint source (workflow/job/step env + crossStepEnv)
       └─ propagateTaint → tainted vars
            ├─ findEchoLeaks → leaks（既存）
            └─ collectGitHubEnvTaintWrites → crossStepEnv に追加 ★新規
```

### 変更箇所

- `SecretInLogRule` に `crossStepEnv map[string]string` フィールド追加。
- `VisitJobPre` 冒頭で `crossStepEnv` を空 map に初期化。
- `checkStep` 内の初期 tainted に `crossStepEnv` を merge。
- `checkStep` 終端で `collectGitHubEnvTaintWrites` を呼び、検出した env var を `crossStepEnv` に蓄積。
- `$GITHUB_ENV` への書き込みを AST ベースで検出する補助関数群を追加:
  - `stmtWritesToGitHubEnv(stmt) bool`
  - `collectGitHubEnvTaintWrites(file, tainted) map[string]string`
  - `parseEnvAssignmentName(word) string`（`NAME=` 先頭 Lit のパース）

### 境界条件
- `$GITHUB_OUTPUT` は **対象外**（env とは別で、後続 step の環境変数にはならない）。
- `>&2` 等で stderr に書いても `$GITHUB_ENV` ファイルに書かれるわけではないのでスキップ。
- 書き込み先が `$GITHUB_ENV` 以外 (`file.txt` 等) ならスキップ。
- `printf` は第一引数の Word が `NAME=` から始まる場合のみ対応（シンプル実装）。
- 同じ名前の env var が step env と crossStepEnv 両方にある場合、step env 側の origin で上書き（原 secret が明確な方を優先）。

## TDD タスク

### Task 1: RED - step 間伝播テスト追加
- `TestSecretInLog_CrossStep_BasicEnvWrite`
- `TestSecretInLog_CrossStep_HeredocEnvWrite`
- `TestSecretInLog_CrossStep_TaintDoesNotCrossJob`
- `TestSecretInLog_CrossStep_EnvWriteWithoutTaintIsIgnored`
- `TestSecretInLog_CrossStep_ChainedSteps`（step1→step2→step3）
- `TestSecretInLog_CrossStep_GitHubOutputDoesNotPropagate`
- `TestSecretInLog_CrossStep_OverwriteByStepEnv`

### Task 2: GREEN - 最小実装
- `crossStepEnv` フィールドを追加
- `VisitJobPre` で reset
- `checkStep` で merge + 書き込み収集
- `collectGitHubEnvTaintWrites` と補助関数を実装

### Task 3: REFACTOR
- 重複コード整理
- コメント整備

### Task 4: docs/example
- `docs/secretinlogrule.md` の "Single-step scope only" 節を更新
- `script/actions/secret-in-log-vulnerable.yaml` に cross-step パターンを追加
- `script/actions/secret-in-log-safe.yaml` にも対応 safe パターン

### Task 5: CLAUDE.md 更新
- 変更の要点を記載（cross-step 対応）

### Task 6: lint / test / commit
- `go test ./pkg/core -run TestSecretInLog`
- `golangci-lint run --fix pkg/core/secretinlog.go pkg/core/secretinlog_test.go`
- commit 粒度: (1) テスト+実装 (2) docs (3) example

## 進捗

- [x] Task 1 (RED)
- [x] Task 2 (GREEN)
- [x] Task 3 (REFACTOR)
- [x] Task 4 (docs/example)
- [x] Task 5 (CLAUDE.md)
- [ ] Task 6 (lint/test/commit)
