# actions/languageservices の test data（手を加えずに写したもの）

actions/languageservices（https://github.com/actions/languageservices 、MIT License）の test data を、手を加えずに写した。取得は 2026-11-16。

- 版: `4043eda158e16579cc5fb1b0b07a4bce2a76f0b5`
- 元の path: `workflow-parser/testdata/reader/*.yml`（195 file）（この directory の下に、元の repository の root からの path のまま置いた）
- license: MIT License。元の license の file を `LICENSE` に写して置いた
- 写した file の git の blob の SHA が、上の版の元の file の blob の SHA と同じことを確かめた（2026-11-16、`gh api repos/<owner>/<repo>/contents/<元の path>?ref=<版>` の `sha` と `git hash-object` を比べた）
- この directory の file の数: 196（この `README.md` を除き、license の file を含む）
- この directory の file の一覧全体の sha256（この directory で `find . -type f -not -path ./README.md -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum`）: `71ba6d1c05c38030ff2123e31eb2bac3daaffce96ae9c79ffb72452792b9f8f5`
- 読むテスト: `TestLanguageservicesReader`（`reader_test.go`）。file の数と sha256 は `TestThirdPartyCopies` が固定する
- 同じ 195 file は、commit `b71ac284fc6a7382c22ecbf3e0009a6ae216823b`（release-v0.3.61）でも名前と blob の SHA が同じである（2026-11-16 に `gh api` で 2 つの版の directory の一覧を比べた）
