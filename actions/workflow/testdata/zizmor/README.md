# zizmorcore/zizmor の test data（手を加えずに写したもの）

zizmorcore/zizmor（https://github.com/zizmorcore/zizmor 、MIT License）の test data を、手を加えずに写した。取得は 2026-11-16。

- 版: `99a054ed9283c90abdd2d5b9fb5101d27dde9783`
- 元の path: `crates/zizmor/tests/integration/test-data/invalid/invalid-action-1/action.yml`（1 file）（この directory の下に、元の repository の root からの path のまま置いた）
- license: MIT License。元の license の file を `LICENSE` に写して置いた
- 写した file の git の blob の SHA が、上の版の元の file の blob の SHA と同じことを確かめた（2026-11-16、`gh api repos/<owner>/<repo>/contents/<元の path>?ref=<版>` の `sha` と `git hash-object` を比べた）
- この directory の file の数: 2（この `README.md` を除き、license の file を含む）
- この directory の file の一覧全体の sha256（この directory で `find . -type f -not -path ./README.md -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum`）: `28c167df811da94e23f6ffbd36fc6366cb13d13fbb13656b26ebecd660d9263d`
- 読むテスト: `TestActionToolSeeds`（`action_test.go`）。file の数と sha256 は `TestThirdPartyCopies` が固定する

