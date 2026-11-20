# yaml/cst/v1 のベンチマーク

2026-09-23 に測った。値は `-count 5` の中央値。

- 環境: Intel N100（4 コア）、linux/amd64、go1.26.5
- コマンド: `go test ./yaml/cst/v1/ -run '^$' -bench . -benchmem -count 5`

## 結果

| ベンチマーク | 入力 | 時間 | 速度 | 確保 |
|---|---|---:|---:|---:|
| `BenchmarkRealWorld` | `yaml/corpus/files/real-world/` の 480 件（平均 約 7.3 KB） | 1 件あたり 254 µs | 28.6 MB/s | 1 件あたり 約 46 KB、32 回 |
| `BenchmarkSuite` | yaml-test-suite の 402 件（平均 約 46 byte） | 1 件あたり 8.0 µs | 5.7 MB/s | 1 件あたり 約 1.4 KB、17 回 |
| `BenchmarkScale/59KB` | real-world の 1 件（59 KB） | 2.2 ms | 27 MB/s | 528 KB、50 回 |
| `BenchmarkScale/948KB` | 同じものを 16 文書つないだもの | 37 ms | 25.6 MB/s | |
| `BenchmarkScale/15179KB` | 同じものを 256 文書つないだもの | 723 ms | 21.5 MB/s | |
| `BenchmarkNestedFlowKeys/10` | `[[…a]: x]: x…` を 10 段 | 17 µs | | |
| `BenchmarkNestedFlowKeys/100` | 同 100 段 | 247 µs | | |
| `BenchmarkNestedFlowKeys/500` | 同 500 段 | 4.7 ms | | |

## 読み取れること

- **長さへの比例**: 59 KB から 15 MB まで、1 byte あたりの時間はほぼ一定である（27 → 21 MB/s）。15 MB で少し遅くなるのは、確保が入力の約 6 倍になるので GC の分だと考えている（確かめてはいない）。
- **置換 ＝ バイト列の置換 ＋ 全体の読み直し で足りるか**: 実物の workflow は 1 件あたり平均 254 µs で読める。1 回の置換ごとに全体を読み直しても、数百回の置換で 0.1 秒程度である。v2 を作る理由には、今の速度はならない。
- **入れ子の implicit key**: 段数に対して線形ではなく、10 倍の段数で 14 倍、5 倍で 19 倍かかる。flow pair かどうかを調べる先読み（`maybePair`）が段ごとに行の残りを読むためである。先読みは 1025 文字で打ち切るので、最悪でも「段数 × 1025 文字」に抑えられる。入れ子の深さの上限（1000）とあわせ、`TestDepthLimit`・`TestLongNestedKeysFailFast` で 1 秒以内に終わることを確かめている。
- **速さそのもの**: 28 MB/s は、字句の切り出しを独立させた parser より遅いと見込まれる（比べてはいない）。上位は `checkChars`（ASCII の早道を入れる前は 21%）、`plainInLine`・`plainChar`、`reset`・`open` だった。v1 では速さを合格条件にしていないので、これ以上は詰めていない。

## 途中で直した性能の問題

- 入れ子の flow sequence が段ごとに 2 回ずつ読み直され、段数に対して指数的に遅くなっていた。flow pair の先読み（`maybePair`）と、ns-flow-pair と flow collection の失敗を「位置・n・c・囲んでいる implicit key」ごとに覚えること（`memoFail`）で直した。最初は implicit key の外だけで覚えていたが、key の中で失敗する 120 byte ほどの入力（`[[…[a,,]: x]…: y`、22 段）に 4 秒かかることが分かり、key の中にも広げた（`TestFailingNestedKeysAreFast`）。
- 1024 文字を超える implicit key の中で、入れ子の各段が代わりの読み方を試し直していた。いちばん外の key が 1024 文字か深さの上限を超えた時点で、その key 全体をあきらめるようにした（`keyTooLong`・`keyOver`）。

## GitHub モード（2026-09-24）

同じ環境とコマンドで、`-bench 'RealWorld|UnclosedNested' -count 5` を測った。値は中央値。

| ベンチマーク | 入力 | ModeSpec | ModeGitHub | 確保（両モードで同じ） |
|---|---|---:|---:|---:|
| `BenchmarkRealWorld`・`BenchmarkRealWorldGitHub` | real-world の 480 件 | 1 件あたり 319 µs | 1 件あたり 251 µs | 1 件あたり 約 46 KB、32 回 |
| `BenchmarkUnclosedNestedGitHub` | block の中で閉じない `[x, ` を 999 段（4 KB） | 5.9 ms | 14.0 ms | 339 KB、55 回 |

- real-world の差は、測定のばらつきの中にある。この回は ModeSpec も 1 件あたり 265〜337 µs と散らばり、前回の 254 µs より遅かった（同じ機械の別の負荷と考えている。確かめてはいない）。
- 閉じない flow の入れ子は、緩めて読んだ後に最も外側を 1 回だけ厳密に読み直すので、ModeSpec の約 2.4 倍で済む。各段で読み直していた前の実装では、同じ入力に 1.8〜2.9 秒かかっていた。
