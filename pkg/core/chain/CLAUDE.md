# pkg/core/chain

Pure-data package backing the leakage-path chain visualization (`-format "{{mermaid .}}"`, see `docs/chain-visualization.md`). Deliberate constraints that differ from the rest of `pkg/core` — check this list before adding an import, a detection heuristic, or a "helpful" AST lookup here.

## Import direction is one-way and non-negotiable

- This package imports only `github.com/sisaku-security/sisakulint/pkg/ast` and the standard library. **Never import `pkg/core`.** `pkg/core` already imports `pkg/core/chain` (to push `SinkRecord`s and call `Assemble`); importing back would create a cycle and fail the build immediately, so there's no "just this once" version of this rule.
- Anything that needs `pkg/core`-only machinery — `JobTriggerAnalyzer`, the `PrivilegedTriggers` maps, `BuiltinUntrustedInputs`, rule structs — belongs in the adapter, `pkg/core/chain_adapter.go`, which translates AST + collected records into the pure-data `AssemblerInput` before calling `Assemble`. If you find yourself wanting an `ast.Workflow` traversal helper that isn't already in `ast`, add it to the adapter, not here.
- `Assemble(AssemblerInput) *ChainModel` and `MermaidRenderer.Render(*ChainModel) string` take and return pure data only — no `io.Writer`, no `*ast.Workflow`, no rule references. This is what keeps the package trivially table-driven-testable without hand-building a full lint run.

## Node ID scheme (assembler.go) — do not improvise a different one

IDs are stable strings used both for dedup (shared nodes across chains) and for edge endpoints:

| Kind | ID format | Notes |
|---|---|---|
| Trigger | `trigger:<name>` | Shared across all jobs in the file with the same event name |
| Permission | `perm:<jobID>` | One per job |
| Source | `source:<SourceKind int>:<SourceName>` | Shared whenever kind+name match — this is what makes fan-out badges possible |
| Action | `action:<jobID>:<line>:<col>` | One per step position |
| Sink | `sink:<ruleName>:<jobID>:<line>:<col>` | Keyed by rule too, so two rules firing on the same line get distinct sink nodes |

Changing any of these formats changes which nodes get treated as "the same shared node" across records — that's a behavior change to fan-out detection and `ChainCount`, not a refactor. If you need a new node kind's ID scheme, follow the same `<prefix>:<disambiguating fields>` shape and update this table.

## Determinism is a hard requirement, not a style preference

- Nodes sort by `(Kind, Line, Col, ID)`; edges sort by `(From, To, Kind)` (see `sortedNodes` / `dedupEdges` in `assembler.go`). This is what makes `mermaid_test.go`'s golden test (`testdata/blastradius.mmd`) and `TestMermaidDeterministic` possible — map iteration order must never leak into rendered output.
- If you add a new map keyed by node ID or similar, sort before iterating in anything that produces output (rendering, summaries). An unsorted `for range` over a `map[string]*Node` anywhere in the render path will make golden tests flaky.

## The lower half is never fabricated — this is the whole point of the package as a security tool

- `Source → Action → Sink` (`EdgeUsedBy`, `EdgeFlowsTo`, and cross-job `EdgeNeeds`) are solid-line edges representing **proven dataflow**. `Assemble` draws them only from `SinkRecord`s that a rule actually pushed via `chain.SinkCollector` — see `TestAssembleNoRecordsNoDataflowEdges` in `assembler_test.go`, which asserts zero dataflow nodes/edges when `Records` is empty. Do not add a code path that infers or guesses a Source/Action/Sink node or edge from `JobContext` alone; if a rule didn't report it, it must not appear.
- `Trigger → Permission → Source` (`EdgeGrants`, `EdgeEnables`) are dashed-line **context annotations** built from `AssemblerInput.JobContexts`, which the adapter derives from the AST (not from rule findings). They mean "this trigger/permission combination makes the source reachable," not "this trigger provably reaches this sink" — see `EdgeKind.IsContext()` and the renderer's solid-vs-dashed split in `mermaid.go`. Keep this distinction when adding new edge kinds: decide up front which half it belongs to and wire `IsContext()` accordingly.
- `linkCrossJobNeeds` (assembler.go) only extends a chain across a `needs:` boundary when `SinkRecord.SourceOrigin` matches `needs\.([A-Za-z0-9_-]+)\.outputs\.` — and only to action nodes that already exist for that upstream job. No upstream action nodes (i.e., the upstream job pushed no `SinkRecord`) means no edge, not a fabricated one. See `docs/chain-visualization.md`'s "known v1 limitations" for which rules do and don't populate `SourceOrigin` this way today.
- Untrusted-ness of a `Source`/`Trigger` (`Node.Untrusted`, feeding `computeUntrustedReachable`'s BFS) is inherited from `SinkRecord.SourceKind` / `TriggerRef.Untrusted`, both decided upstream by `pkg/core` before this package ever sees them. Do not add a second `github.event.*` allowlist or regex here to re-derive it — that duplicates `pkg/expressions.BuiltinUntrustedInputs` and the two will drift (see the equivalent rule in `../CLAUDE.md`).

## Tests

- Table-driven, constructing `AssemblerInput`/`SinkRecord` by hand (no YAML parsing, no `Rule` instances) — see `assembler_test.go`'s `nodeByID`/`hasEdge` helpers, which are the expected way to assert on a `*ChainModel` rather than string-matching rendered mermaid.
- `mermaid_test.go` covers rendering separately from assembly; prefer adding assembler behavior tests in `assembler_test.go` and renderer/formatting tests in `mermaid_test.go` rather than mixing both concerns in one table.
- Golden file `testdata/blastradius.mmd` pins exact renderer output for `sampleModel()`. Regenerate deliberately with `UPDATE_GOLDEN=1 go test ./pkg/core/chain/ -run TestMermaidGolden -v`, and diff the result by eye before committing — a passing regenerate is not the same as a correct one.
