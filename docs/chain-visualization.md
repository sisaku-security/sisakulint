+++
title = 'Leakage Path Chain Visualization'
date = 2026-07-05T00:00:00+09:00
draft = false
+++

### Overview

sisakulint's flow rules (secret leakage, code/argument/env/path injection, SSRF, output clobbering, reusable-workflow taint, and AI-agent prompt injection — 21 rules in total) each detect one **segment** of a larger attack chain:

```
trigger → permission → (secret | untrusted input) → action(step) → sink (log / network / artifact / expr / boundary)
```

Individually, each finding only tells you "this line is risky." It doesn't show you the full blast radius: which trigger lets an attacker reach this, what permissions are in play, and how many other sinks the same tainted value flows into. The chain visualization feature assembles every flow-rule finding in a file into a single graph and renders it as a [mermaid](https://mermaid.js.org/) flowchart, so the whole chain — and its fan-out — is visible at a glance.

This is a **view over existing findings**, not a new detector: the graph draws exactly the source→action→sink edges that flow rules already reported, plus contextual trigger/permission annotations built from the AST. See [Coverage equals rule coverage](#coverage-equals-rule-coverage) below for what that implies.

### Usage

Pass `mermaid` as the format function via `-format`:

```bash
sisakulint -format "{{mermaid .}}" .github/workflows/deploy.yml
```

This prints one fenced ` ```mermaid ` block per linted file to stdout, each preceded by a `%% file: <path>` comment. Paste the block into any mermaid-aware renderer (GitHub/GitLab markdown, the [mermaid live editor](https://mermaid.live/), Hugo shortcodes, etc.).

To save the graph(s) to a file instead of printing them to the terminal:

```bash
sisakulint -format "{{mermaid .}}" .github/workflows/ > chains.md
```

`chains.md` is then a normal markdown file — open it in any mermaid-capable previewer, or commit it as a point-in-time snapshot of a workflow's blast radius during a security review.

Chain assembly only runs when the format string references `mermaid`; every other `-format` (`{{sarif .}}`, the default, custom templates) is byte-for-byte unaffected, so turning this on never changes existing CI output.

### Reading the graph

Every graph has (up to) five node kinds, clustered into `subgraph job_<id>` blocks for `Action`/`Sink` nodes so multi-job workflows stay readable:

| Node | Shape | Meaning |
|---|---|---|
| Trigger | stadium `([...])` | A workflow event (`pull_request_target`, `push`, …) that can reach this chain |
| Permission | hexagon `{{...}}` | The job's effective `permissions:` (or `implicit(default token)` if undeclared) |
| Source | rectangle `[...]` | A secret (`secrets.X`) or untrusted input (`github.event.*`, `needs.*.outputs.*`, …) that a rule traced |
| Action | rectangle `[...]`, inside a job subgraph | The step that consumes the source (`run: ...` / `uses: ...`) |
| Sink | asymmetric `>...]`, inside a job subgraph | Where the rule reported the leak/injection: `log`, `network`, `artifact`, `expr`, or `boundary` |

Edges carry one of two visual meanings, and the distinction is load-bearing:

- **Solid arrows (`-->`)** — `used-by`, `flows-to`, and cross-job `needs` edges. These are **proven dataflow**: the assembler only draws them from a `SinkRecord` a rule actually pushed. It never fabricates a solid edge.
- **Dashed arrows (`-.->`)** — `grants` (Trigger→Permission) and `enables` (Permission→Source). These are **context, not proof**: they say a trigger/permission combination makes a source reachable, not that it necessarily reaches a specific sink. The real proof is the solid path underneath.

If you only remember one rule: **trust solid lines as fact, read dashed lines as "this is the enabling condition."**

### The four emphasis mechanisms

The renderer layers four cues onto the base graph so the highest-impact fix is obvious without reading every node:

1. **Blast-radius summary line** — a `%% blast-radius: ...` mermaid comment directly above the graph, e.g. `untrusted:1 secrets:2 sinks:3 (log:1/network:1/artifact:1)`. One line answers "how bad is this file" before you look at a single node.
2. **Untrusted-reachable highlighting** — every node reachable from an untrusted trigger or untrusted source (via a forward BFS over the drawn edges) gets `classDef untrusted` (red fill). Everything else gets `classDef safe` (greyed out), so the parts of the graph that are actually attacker-reachable pop out visually.
3. **Fan-out badges** — a shared Trigger/Permission/Source node that multiple chains pass through gets a `[&rarr;N sinks]` suffix on its label, where `N` is the number of chains (`ChainCount`) flowing through it. This is what makes a single leaked secret used in three places visually read as "one root cause, three symptoms" instead of three unrelated warnings.
4. **Leverage marker (🔧)** — exactly one non-terminal node (a Trigger, Permission, or Source — never an Action/Sink) is picked as the highest-leverage fix point: the one with the largest `ChainCount`, tie-broken upstream-first (Trigger > Permission > Source) and then by ID. It gets a 🔧 prefix on its label and `classDef fixhere` (a thick blue outline). This is the "fix here, not there" node — mitigating it (e.g., scoping the permission, removing the trigger, rotating/removing the secret) collapses every chain that passes through it at once.

### Example

`script/actions/chainviz-blastradius.yaml` is a `pull_request_target` job whose `secrets.DEPLOY_TOKEN` is read by three separate steps — `echo` (secret-in-log), `curl` (secret-exfiltration), and `actions/upload-artifact@v3` (secrets-in-artifacts). Running `-format "{{mermaid .}}"` against it produces (abridged):

```
%% blast-radius: untrusted:1 secrets:2 sinks:3 (log:1/network:1/artifact:1)
flowchart TD
  n_trigger_pull_request_target(["🔧 pull_request_target [&rarr;3 sinks]"])
  n_perm_build{{"contents:write [&rarr;3 sinks]"}}
  n_source_0_secrets_DEPLOY_TOKEN["secrets.DEPLOY_TOKEN [&rarr;2 sinks]"]
  n_source_0_secrets_*["secrets.*"]
  subgraph job_build["job: build"]
    n_action_build_33_7["echo"]
    n_action_build_38_9["curl"]
    n_action_build_39_9["uses: actions/upload-artifact@v3"]
    n_sink_secret_in_log_build_33_7>"log"]
    n_sink_secret_exfiltration_build_38_9>"network"]
    n_sink_secrets_in_artifacts_build_39_9>"artifact"]
  end
  n_action_build_33_7 -->|flows-to| n_sink_secret_in_log_build_33_7
  ...
  n_source_0_secrets_DEPLOY_TOKEN -->|used-by| n_action_build_33_7
  n_source_0_secrets_DEPLOY_TOKEN -->|used-by| n_action_build_38_9
  n_trigger_pull_request_target -.->|grants| n_perm_build
  ...
```

Reading it: the summary line says one untrusted trigger reaches two distinct secret sources feeding three sinks across all three sink kinds. `secrets.DEPLOY_TOKEN` carries the `[&rarr;2 sinks]` badge because both `secret-in-log` and `secret-exfiltration` read the same env var — one leaked secret, two symptoms. `secrets.*` (secrets-in-artifacts' generic source placeholder; see `pkg/core/secretsinartifacts.go`) renders as its own node rather than joining the shared one, since that rule doesn't correlate to a specific secret name. The 🔧 marker sits on the `pull_request_target` trigger node — the highest-ChainCount non-terminal node — because removing or gating that trigger (or moving to least-privilege permissions) collapses all three findings at once, whereas fixing any single step only removes one symptom.

`script/actions/chainviz-crossjob.yaml` demonstrates the cross-job case: job `produce` writes `github.head_ref` to `$GITHUB_OUTPUT`, and job `consume` reads `needs.produce.outputs.ref` straight into a `curl` URL. The graph draws a solid `-->|needs|` edge from `produce`'s action node(s) to the tainted source node in `consume`'s chain, so the two jobs' subgraphs visibly connect into one attack path instead of reading as two unrelated findings.

### Coverage equals rule coverage

**An empty or small graph does not mean the workflow is safe.** The assembler performs zero detection of its own — it only draws what a flow rule already reported via a `SinkRecord`. If a leak pattern isn't covered by any of the 21 wired rules (or the rule's detection has a false negative), it is invisible to this graph exactly as it would be invisible to the plain lint output. Treat the chain graph as a *summary and prioritization aid* for findings sisakulint already produces, not as an independent safety proof. `script/actions/chainviz-safe.yaml` renders down to a bare `flowchart TD` with no dataflow edges — that's the expected shape for a genuinely clean file, but the same shape would also appear for a file with an undetected leak.

### Known v1 limitations

1. **`reusable-workflow-taint` chains do not appear when scanning a real multi-file project.** The [reusable-workflow-taint rule]({{< ref "reusableworkflowtaint.md" >}}) correlates a caller's untrusted `with:` input against a callee's `inputs.*` sink across file boundaries. When cross-file chain resolution is enabled (i.e., a real directory scan where the callee can be resolved), that correlation is reported through `LocalReusableWorkflowCache`'s `ResolvePendingChains` → `FormattedError` path in `pkg/core/cross_file_taint.go`, which has no access to a `Rule` instance or its `chain.SinkCollector` — so no `SinkRecord` is pushed for it, and the chain never reaches the graph. Only the single-file fallback path (chain resolution disabled, e.g. a lone file with no resolvable caller/callee, such as a library caller with no project context) pushes a `SinkRecord` and shows up. The other 20 flow rules are unaffected and render normally in real scans.
2. **Cross-job `needs` edges only draw when a rule's `SourceOrigin` literally contains the `needs.<job>.outputs.<name>` pattern.** The assembler (`linkCrossJobNeeds` in `pkg/core/chain/assembler.go`) matches `SinkRecord.SourceOrigin` against a `needs\.([A-Za-z0-9_-]+)\.outputs\.` regex and only connects the upstream job's action nodes when it hits. `CodeInjectionRule` and `RequestForgeryRule`'s deferred cross-job path (`VisitWorkflowPost`) format `SourceOrigin` as `"needs.<job>.outputs.<name> (tainted via ...)"`, so this pattern does appear for those two rule families today (confirmed against real output in `pkg/core/chain_e2e_test.go::TestChainVizE2ECrossJobNeeds`). A rule that instead records only the resolved underlying taint source (dropping the literal `needs.*` expression text) would not produce this edge even if the underlying cross-job detection itself is correct — the graph would simply show both jobs' chains as disconnected rather than fabricating a link it can't prove.
3. **A chained-derivation secret source may render as a separate node from the same secret referenced directly elsewhere.** When [secret-in-log]({{< ref "secretinlogrule.md" >}}) detects a leak through a shell-variable derivation chain (e.g. `Y="$TOKEN"; echo "$Y"`), the `Source` node is labeled with the raw `shellvar:` origin marker instead of the resolved `secrets.*` reference — `SecretInLogRule` deliberately keeps the marker raw so its autofix can resolve the mask target (see the shellvar-asymmetry note in `pkg/core/CLAUDE.md`). If another rule (e.g. [secret-exfiltration]({{< ref "secretexfiltration.md" >}})) references the same underlying secret directly, the two produce distinct `Source` nodes rather than one shared node with a fan-out badge. Single-hop leaks — the common case, and the one in the worked example above — resolve to `secrets.*` and share correctly; only multi-hop shell derivations are affected. This is a v1 display limitation, not a missed detection: both leaks are still reported.

### See also

- [secret-in-log]({{< ref "secretinlogrule.md" >}}), [secret-exfiltration]({{< ref "secretexfiltration.md" >}}), [secrets-in-artifacts]({{< ref "secretsinartifacts.md" >}}) — secret-sourced flow rules
- [code-injection-critical]({{< ref "codeinjectioncritical.md" >}}), [output-clobbering]({{< ref "outputclobbering.md" >}}), [request-forgery]({{< ref "requestforgery.md" >}}) — untrusted-input-sourced flow rules
- [reusable-workflow-taint]({{< ref "reusableworkflowtaint.md" >}}) — see the known limitation above for its interaction with this feature
- `pkg/core/chain/CLAUDE.md` — package conventions for `pkg/core/chain` (node ID scheme, determinism, the "lower half is never fabricated" invariant)
