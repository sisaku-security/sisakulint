# CLAUDE.md

sisakulint は GitHub Actions workflow (.github/workflows/*.yml) の静的解析ツール。OWASP Top 10 CI/CD Security Risks 相当の検査を実装し、多くのルールが auto-fix と SARIF 出力に対応する。

## コマンド

```bash
go build ./cmd/sisakulint
go test ./...                          # 品質保証はローカル実行のみ (CI は test を回さない)
sisakulint script/actions/<file>.yaml  # fixture の手動検証
sisakulint -fix dry-run                # 修正プレビュー
sisakulint -debug
```

## アーキテクチャ

workflow 走査 → AST 化 (pkg/ast + pkg/core/parse_*.go) → ルール適用 (pkg/core、visitor による depth-first: WorkflowPre → JobPre → Step → JobPost → WorkflowPost) → 報告 → 要求時 auto-fix。式 ${{ }} は pkg/expressions、シェル taint は pkg/shell、GitHub API は pkg/remote。パッケージ固有の規約は各ディレクトリの CLAUDE.md にある。

ルール一覧の正は pkg/core/linter.go の makeRules の返り値と docs/ のルール別 md。この文書には一覧を持たない (二重管理は必ず陳腐化するため)。

## 全域で効く前提 (誤認されやすいが正しいもの)

- CI は go test も lint も実行しない。CI.yaml は gofmt の diff を表示するだけで fail もしない。push は何も検証しないため、コミット前にローカルで go test ./... を通すことがタスク完了条件。
- 新ルールの追加は複数ファイルの同期契約: makeRules への登録、docs/<slug>.md、docs/_index.md の件数表 (手動集計)、script/actions/<rule>.yaml と <rule>-safe.yaml、script/README.md の表。コードとテストだけでは未完了。
- 実効設定は .github/sisakulint.{yaml,yml}。-init が生成する .github/action.yaml はローダーに読まれない (既知の乖離、gitignore 済み)。
- GitHub API トークンの解決経路は 2 つ併存する。CLI 本経路は pkg/core/github_token.go の ResolveGitHubToken (-github-token > SISAKULINT_GITHUB_TOKEN > GITHUB_TOKEN > GH_TOKEN、サブプロセスプローブなし #484)。pkg/remote/fetcher.go の getToken は gh auth token / git credential fill を今もプローブする旧経路で、-remote スキャンと RemoteActionsMetadataCache が使う。認証を触るときは先にどちらの経路かを特定する。
- exit code: 0 = 問題なし / 1 = 検出あり / 2 = オプション誤り / 3 = 致命的エラー (-fix on 中の GitHub API rate limit 超過を含む #474)。
- missing-timeout-minutes ルールは opt-in。-enable-rule missing-timeout-minutes を付けたときだけ走る (登録済みでも既定無効)。
- Go バージョンの正は go.mod と .go-version (1.25.10)。CI.yaml と Dockerfile (1.24.0)、release.yml (1.25) は追従漏れなので基準にしない。
- リリースは v*.*.* の tag push でのみ発火する。main push ではデプロイされない。
- docs/RULES_GUIDE.md、docs/ARCHITECTURE.md、script/github_to_aws/ への参照が一部ドキュメントに残っているが実在しない。探しに行かない。

## ルール追加の最小手順

pkg/core/myrule.go に BaseRule を埋め込んだ struct を作り、Visit* メソッドで rule.Errorf(pos, ...) する。makeRules (pkg/core/linter.go) に登録し、pkg/core/myrule_test.go と上記の同期契約ぶんを揃える。実装規約は pkg/core/CLAUDE.md を参照。
