# rhysd/actionlint の test data（手を加えずに写したもの）

rhysd/actionlint（https://github.com/rhysd/actionlint 、MIT License）の test data を、手を加えずに写した。取得は 2026-11-16。

- 版: tag `v1.7.12`（commit `914e7df21a07ef503a81201c76d2b11c789d3fca`）
- 元の path: `testdata/projects/` の下の `action.yaml` 14 と `testdata/action_metadata/input-duplicate/action.yml`（15 file）（この directory の下に、元の repository の root からの path のまま置いた）
- license: MIT License。元の license の file を `LICENSE.txt` に写して置いた
- 写した file の git の blob の SHA が、上の版の元の file の blob の SHA と同じことを確かめた（2026-11-16、`gh api repos/<owner>/<repo>/contents/<元の path>?ref=<版>` の `sha` と `git hash-object` を比べた）
- この directory の file の数: 16（この `README.md` を除き、license の file を含む）
- この directory の file の一覧全体の sha256（この directory で `find . -type f -not -path ./README.md -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum`）: `03fcdbcc729ec157be57ee63a0d542df08674040a033a7e1937b88f607bcfac2`
- 読むテスト: `TestActionToolSeeds`（`action_test.go`）。file の数と sha256 は `TestThirdPartyCopies` が固定する

