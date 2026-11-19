# actions/workflow のベンチマーク

2026-09-24 に測った。値は `-count 5` の中央値。

- 環境: Intel N100（4 コア）、linux/amd64、go1.26.5
- コマンド: `go test ./actions/workflow/ -run '^$' -bench . -benchmem -count 5`
- 入力: `yaml/corpus/files/real-world/` の workflow（manifest の `kind` が `workflow`）の 409 件。1 回の繰り返しで 1 件を読む。

## 結果

| ベンチマーク | 内容 | 1 件あたりの時間 | 速度 | 1 件あたりの確保 |
|---|---|---:|---:|---:|
| `BenchmarkCST` | `cst.ParseMode(src, ModeGitHub)` だけ | 362 µs | 21.9 MB/s | 約 51 KB、32 回 |
| `BenchmarkWorkflow` | それに `workflow.Parse` を足したもの | 947 µs | 8.4 MB/s | 約 247 KB、約 3850 回 |

## 読み取れること

- モデルの分は 1 件あたり約 585 µs で、CST を読む時間の約 1.6 倍である。workflow 1 件を 1 ms 以内で読める。
- 確保の回数は、CST の 32 回に対してモデルが約 3800 回である。profile（`-memprofile`）で大きかったのは、key ごとの entry と、スカラーごとの `scalar.Value`（値と区間の列）と、式の字句解析だった。
- 途中で、mapping の entry と step の列を、要素の数で先に確保するようにした（1 件あたりの確保が約 340 KB から約 247 KB に減った）。
- 速さは合格条件にしていないので、これ以上は詰めていない。詰めるなら、スカラーの値を要る時まで作らないこと、`ofKind` の結果を生成器で表にしておくことが候補である。

## 型にしない key の値の検査（2026-10-13）

`checkRest` を足す前（`c6c2b1ef`）と後（`6afd047e`）の `BenchmarkWorkflow`。コマンドと入力は上と同じで、値は `-count 5` の中央値。前は `git worktree add` で別に取り出した木で測った。

| | 1 件あたりの時間 | 1 件あたりの確保 |
|---|---:|---:|
| 前 | 1012 µs | 約 285 KB、4228 回 |
| 後 | 990 µs | 約 352 KB、4523 回 |

- 時間は、5 回のばらつき（前 868〜1147 µs、後 980〜1331 µs）の中で差が見えない。
- 確保は約 24% 増えた。読んだ値と mapping の記録（2 つの map）と、型にしない key を辿って作る `scalar.Value` の分である。合格条件にはしない。
