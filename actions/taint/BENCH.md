# actions/taint のベンチマーク

2026-09-25 に測った。値は `-count 5` の中央値。

- 環境: Intel N100（4 コア）、linux/amd64、go1.26.5
- コマンド: `go test ./actions/taint/ -run '^$' -bench 'Parse|Analyze' -benchmem -count 5`
- 入力: `yaml/corpus/files/real-world/` の workflow（manifest の `kind` が `workflow`）の全件。1 回の繰り返しで 1 件を読む。

## 結果

| ベンチマーク | 内容 | 1 件あたりの時間 | 1 件あたりの確保 |
|---|---|---:|---:|
| `BenchmarkParse` | `cst.ParseMode` と `workflow.Parse` | 683 µs | 約 270 KB、約 4,010 回 |
| `BenchmarkAnalyze` | それに `taint.Analyze` を足したもの | 1,042 µs | 約 376 KB、約 4,340 回 |
| `BenchmarkLookup` | 1 つの参照を、攻撃者の event と action の全部の組で引く | 47 µs（1 組 0.6 µs） | — |

## 読み取れること

- 解析の分は 1 件あたり約 360 µs で、workflow を読む時間の約半分である。
- `Lookup` は、表を経路の trie にして引く。線形に走っていたときは 1 組あたり約 17 µs だった。`workflow_call` と composite action では、参照ごとに攻撃者の event と action の全部の組を引くので、ここが解析の時間を決める。
- 速さは合格条件にしていない。
