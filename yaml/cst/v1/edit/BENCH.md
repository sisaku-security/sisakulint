# yaml/cst/v1/edit のベンチマーク

2026-09-24 に測った。値は `-count 5` の中央値。

- 環境: Intel N100（4 コア）、linux/amd64、go1.26.5
- コマンド: `go test ./yaml/cst/v1/edit/ -run '^$' -bench . -benchmem -count 5`

## 結果

| ベンチマーク | 入力 | 1 件あたりの時間 | 1 件あたりの確保 |
|---|---|---:|---:|
| `BenchmarkParseRealWorld` | `yaml/corpus/files/real-world/` の 480 件を `cst.Parse` | 254 µs | 約 46 KB、32 回 |
| `BenchmarkReplaceApply` | そのうち、複数行の literal の `run:` を持つ 393 件で、最初の語を 1 つ `Replace` して `Apply` | 327 µs | 約 92 KB、251 回 |
| `BenchmarkInsertApply` | そのうち、`steps:` を持つ 394 件で、最初の step の `env` に変数を 1 つ `Insert` して `Apply`（`env` が無ければ `env` ごと足す） | 432 µs | 約 82 KB、345 回 |
| `BenchmarkManyReplaces` | `k0: v` から `k4999: v` までの 5,000 行の mapping で、5,000 個の値の `Replace` を 1 回の `Apply` で当てる | 77 ms（`Apply` 1 回） | 約 17 MB、165,515 回 |

5 回の測定のばらつきは大きい（`Parse` は 238〜330 µs、`Replace`・`Apply` は 262〜479 µs、`Insert`・`Apply` は 259〜468 µs）。

構造の編集の前（2026-09-23、`2026-09-23-yaml-edit` の実装）の値: `Parse` 245 µs、`Replace`・`Apply` 364 µs・約 69 KB・64 回。

## 読み取れること

- **1 回の編集の費用**: 1 回の `Apply` は、読み直し 1 回（`Parse` と同じ費用）に加え、構文の確かめ、差分（編集の範囲にかかる部分木だけを辿る）、期待との照合の分だけかかる。`Replace`・`Apply` の時間は、差分を足す前とばらつきの範囲で変わらない。確保は 1 件あたり約 23 KB・約 190 回増えた（差分の対応の表と、辿った範囲の `scalar.Decode`）。
- **構造の編集**: `Insert`・`Apply` は `Replace`・`Apply` より約 100 µs 多い。`layoutAt` が文書を辿ってインデントの幅と sequence の形を決めることと、書き出しの分である。393 件・394 件は `run:`・`steps:` を持つファイルなので、480 件の平均より大きいファイルに寄っている可能性がある（比べてはいない）。
- **autofix の規模**: 1 ファイルの autofix を 1 回の `Apply` にまとめれば、ファイルあたり 1 ms を超えない。規則ごとに `Apply` を分けても、数十回で十数 ms 程度である。
- **多数の編集**: 5,000 個の編集を 1 回で当てて 77 ms。差分の `reached` と `newPos` を二分探索にする前は 451 ms で、ノードごとに全部の編集を見ていた。前は 5,000 個で 184 ms かかっていた（原因は根から辿る `scalarAt`）が、`scalarAt` を消して解消した。確かめの中の `changeOf` と `rawReach` が変更の数と編集の数の積に比例していたのは、2026-09-24 に索引と二分探索にして直した（`scale_test.go`。信頼できない入力で 2 乗の時間がかからないこと）。
- **確保**: 新しいバッファ、読み直した木、差分の対応の表、値の確かめの `Decode`、逆の編集の複写。時間は合格条件にしていないので、詰めていない。
