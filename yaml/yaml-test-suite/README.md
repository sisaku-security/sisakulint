# yaml-test-suite

YAML パーサーの正しさを確かめるための、期待値付きのテスト集（https://github.com/yaml/yaml-test-suite 、MIT License、`main/License`）。取得したファイルは手を加えずに置いている。取得は 2026-09-23。

## 置いたもの

| ディレクトリ | 中身 | 取得元 |
|---|---|---|
| `data-2022-01-17/` | テストごとのディレクトリに展開した形。パーサーの検査にはこちらを使う | リリースタグ `data-2022-01-17` → commit `6e6c296ae9c9d2d5c4134b4b64d01b29ac19ff6f`（2022-01-17） |
| `main/` | 原稿の形（`src/*.yaml` に 1 ファイル 1 テスト ID）と ReadMe・License・生成スクリプト | `main` ブランチ commit `da267a5c4782e7361e82889e76c0dc7df0e1e870`（2025-12-25） |

ファイルの一覧をパスで並べて sha256 を取り、その一覧全体の sha256 を取った値（`find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum`）:

- `data-2022-01-17/`: `6a5624dc250afa4b501fee5fbc2f21327437d71c9206b811b5c72414dc33e035`
- `main/`: `7c9a154c5ec96e6363b20c50bfe1f5a6cc5b5a3fd33ba0f5cf84fe6db0d8220a`

どちらも `.git` は外してある。

## data-2022-01-17 の中身

- テスト ID のディレクトリが 350 個。1 つの ID が複数の小テストを持つ場合は `00/`・`01/` … の下に分かれ、小テストまで数えると `in.yaml` は 402 件ある。
- 各テストのファイルは `main/ReadMe.md` の「The `data` branch files」に説明がある。`===` がテスト名、`in.yaml` が入力、`test.event` がパーサーの出すべきイベント列、`in.json` が読んだ値の JSON（282 件）、`out.yaml` が標準的な書き出し（249 件）、`emit.yaml` が emitter の出力（55 件）、`error` はそのファイルが在れば「読めてはいけない」（95 件）。
- `name/` と `tags/` はテスト名とタグから引くための索引である。
- 入力の中で、見えにくい文字は記号で表している（末尾の空白は `␣`、タブは `»` 類、改行の無い終端は `∎` など）。これも `main/ReadMe.md` の「Special Characters」にある。

## 取得のときに確かめたこと

- `main/ReadMe.md` は、`data` ブランチを直接使わず `data-YYYY-MM-DD` のリリースを使うよう求めている（未リリースの commit を含み、ときどき squash と force push をするため）。そのためリリース `data-2022-01-17` を置いた。最新のリリースである。
- `data` ブランチ（commit `6ad3d2c6`、2022-01-17、"Regenerated data from main 45db50ae"）も取得して比べ、全 3,387 ファイルがリリースと一致した。比べたあとで消した。
- リリースの元になった `main` の `45db50ae` から今の `main`（`da267a5c`）までの 9 commit が変えたのは `bin/` の 3 ファイルと `ReadMe.md` だけで、テスト本体の `src/` は変わっていない。したがってリリースは今のテスト集と同じである。
- `main/src/` には 351 ファイルあり、リリースより 1 つ多い。差の `ZYU8` は `skip: true` が付いたテストで、「1.2 の生成規則では妥当だが有用ではなく、将来は不正にする見込みなので、パーサーに対応を促したくない」という注記がある。意図して展開から外されている。
