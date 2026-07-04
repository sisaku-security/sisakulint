# pkg/core

Deliberate patterns that differ from common Go practice. Check this list before proposing DRY refactors, parallelization, or "missed detection" fixes.

## Rule implementation

- Rule names are hyphenated like code-injection-critical; docs URLs and docs/*.md filenames are concatenated like codeinjectioncritical. There is no automatic conversion — keep both in sync by hand.
- When adding a Critical/Medium rule pair, use codeinjection.go as the template: a shared implementation plus thin factories, with the Medium variant firing on hasNormal && !hasPrivileged to prevent double reporting. Determine triggers through JobTriggerAnalyzer rather than reading workflow.On directly, because it accounts for job-level if:. Pick the privileged-trigger set from the two existing maps in privilegedtriggers.go; do not create a similar map.
- Judge untrusted expressions by registering in pkg/expressions BuiltinUntrustedInputs and reading ExprError.IsUntrustedInput. Do not write your own github.event.* list or regex.
- Rules holding process-wide state such as rate limit tracking or dedupe must participate in the reset*RunState calls at the top of the three entry points LintFile / LintFiles / Lint. Missing the reset silently swallows warnings on the second and later Lint calls in one process, which breaks library callers and test isolation.
- Composite action files with a top-level runs: key and dependabot files are short-circuited at the top of validate and never reach workflow rules. A new rule not seeing them is by design.

## Tests

- The dominant style is table-driven tests that hand-build ast structs without parsing YAML and call VisitWorkflowPre → VisitJobPre → VisitStep manually in real traversal order. Forgetting VisitWorkflowPre leaves rule-internal caches empty and produces a false pass with zero errors.

## Taint: taint.go / secretinlog.go / cross_file_taint.go

- Taint seeds come from two separate sources that must not be merged: TaintTracker seeds from ${{ }} inside script literals in taint.go, while SecretInLogRule seeds from the YAML env: section in secretinlog.go. Place new features by which taint source they belong to.
- sanitizeForShellParse placeholders named _SISAKULINT_E_<n>_ are numbered by regex match order, and expressionOffsetsByPlaceholder in secretinlog.go independently reconstructs the same numbering to correlate positions. There is no shared constant; changing the numbering scheme or the regex on one side silently misaligns positions with no compile error.
- The shellvar: marker handling is intentionally asymmetric: TaintTracker expands markers via expandShellvarMarkers for reporting, while SecretInLogRule keeps them raw so the autofix can resolve its mask target. Unifying the two breaks either reporting or autofix.
- Detection suppression — Offset ordering, ::add-mask:: position checks, and the all-upstreams-masked rule for positionals — is deliberate narrowing for forward dataflow correctness and autofix idempotency. Do not review-flag or "fix" it as missed detection. The scope-unawareness of seedTaintFromExpressions is likewise a known limitation tracked as follow-up.
- ResolvePendingChains runs single-threaded after errgroup.Wait() and holds no locks by design. Moving the call before Wait() or parallelizing it in linter.go introduces data races.
