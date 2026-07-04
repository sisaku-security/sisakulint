# .github

- reviewdog.yaml が PR ごとに sisakulint 自身をビルドして全ワークフローに SARIF で dogfood する。ワークフロー編集は sisakulint の規約 (action の commit SHA pin、permissions の明示) を満たさないと PR 上で自動指摘される。
- CI.yaml は gofmt の diff 表示のみでテストも lint も実行せず fail もしない。動作保証はローカルの go test ./... が唯一。
- リリースは v*.*.* の tag push で release.yml が発火 (goreleaser + Homebrew tap 更新、PAT の TAP_GITHUB_TOKEN が必要)。tap の更新先が release.yml (ultra-supara/...) と .goreleaser.yml (sisaku-security/...) で食い違ったまま残っている。
- 実効設定は .github/sisakulint.yaml。-init が生成する action.yaml は読まれず gitignore 済み。
