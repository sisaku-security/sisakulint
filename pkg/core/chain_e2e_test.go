package core

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// runLinterMermaid lints a single fixture file with the {{mermaid .}} custom
// error format and returns everything written to stdout. Single-file lints
// go through Linter.LintFile (LintFiles delegates to it for a 1-element
// slice), which independently assembles and sets the chain models since it
// doesn't pass through the errgroup.Wait()-gated post-Wait section that
// multi-file LintFiles uses (see the "単一ファイルパス" comment in
// linter.go's LintFile).
func runLinterMermaid(t *testing.T, path string) string {
	t.Helper()
	var buf bytes.Buffer
	linter, err := NewLinter(&buf, &LinterOptions{CustomErrorMessageFormat: "{{mermaid .}}"})
	if err != nil {
		t.Fatalf("NewLinter: %v", err)
	}
	if _, err := linter.LintFiles([]string{path}, nil); err != nil {
		t.Fatalf("LintFiles: %v", err)
	}
	return buf.String()
}

// TestChainVizE2EBlastRadius exercises chainviz-blastradius.yaml end-to-end:
// a single pull_request_target job whose secrets.DEPLOY_TOKEN env var fans
// out to three different sink kinds (secret-in-log, secret-exfiltration,
// secrets-in-artifacts). Confirmed against real `-format "{{mermaid .}}"`
// output before writing these assertions.
func TestChainVizE2EBlastRadius(t *testing.T) {
	out := runLinterMermaid(t, "../../script/actions/chainviz-blastradius.yaml")
	if !strings.Contains(out, "flowchart TD") {
		t.Fatalf("no mermaid output:\n%s", out)
	}
	// All 3 sink kinds appear in the blast-radius summary comment line.
	if !strings.Contains(out, "%% blast-radius: untrusted:1 secrets:2 sinks:3 (log:1/network:1/artifact:1)") {
		t.Errorf("summary line missing or sink kinds incomplete:\n%s", out)
	}
	// secret-in-log and secret-exfiltration share the same secrets.DEPLOY_TOKEN
	// source node (both read it from env), so the assembler fans it out with
	// a "-> 2 sinks" badge instead of drawing two disconnected chains.
	if !strings.Contains(out, `n_source_build_0_secrets_DEPLOY_TOKEN["secrets.DEPLOY_TOKEN [&rarr;2 sinks]"]`) {
		t.Errorf("expected shared secrets.DEPLOY_TOKEN source node with fan-out badge:\n%s", out)
	}
	// untrusted-reachable emphasis is present (pull_request_target reaches everything here).
	if !strings.Contains(out, "classDef untrusted") {
		t.Error("missing untrusted emphasis classDef")
	}
	if !strings.Contains(out, "class n_trigger_pull_request_target fixhere") {
		t.Errorf("expected the shared trigger to be marked as the leverage (fixhere) node:\n%s", out)
	}
}

// TestChainVizE2ESafeIsMinimal exercises chainviz-safe.yaml: a push-triggered
// job with read-only permissions, no secrets, and no untrusted input. No flow
// rule pushes a SinkRecord, so the assembled graph must carry zero dataflow
// (used-by/flows-to) edges — confirming an empty graph reflects a genuinely
// clean workflow rather than a rendering bug that silently drops edges.
func TestChainVizE2ESafeIsMinimal(t *testing.T) {
	out := runLinterMermaid(t, "../../script/actions/chainviz-safe.yaml")
	if !strings.Contains(out, "flowchart TD") {
		t.Fatalf("no mermaid output:\n%s", out)
	}
	if strings.Contains(out, "|used-by|") || strings.Contains(out, "|flows-to|") {
		t.Errorf("safe workflow produced dataflow edges:\n%s", out)
	}
	if !strings.Contains(out, "blast-radius: untrusted:0 secrets:0 sinks:0 ()") {
		t.Errorf("expected an all-zero blast-radius summary for the safe fixture:\n%s", out)
	}
}

// TestChainVizE2ECrossJobNeeds exercises chainviz-crossjob.yaml: job
// "produce" writes github.head_ref (untrusted) to $GITHUB_OUTPUT, and
// downstream job "consume" reads needs.produce.outputs.ref into a curl URL.
//
// EdgeNeeds draws only when the downstream SourceOrigin keeps the literal
// "needs.<job>.outputs.<name>" expression and the producer-side SinkRecord
// identifies the same OutputName, so the edge connects to the action that wrote
// the referenced job output rather than every action in the producer job.
func TestChainVizE2ECrossJobNeeds(t *testing.T) {
	out := runLinterMermaid(t, "../../script/actions/chainviz-crossjob.yaml")
	if !strings.Contains(out, "flowchart TD") {
		t.Fatalf("no mermaid output:\n%s", out)
	}
	// Both jobs' sinks are present regardless of whether the needs edge draws.
	if !strings.Contains(out, `subgraph job_produce["job: produce"]`) {
		t.Errorf("missing produce job subgraph:\n%s", out)
	}
	if !strings.Contains(out, `subgraph job_consume["job: consume"]`) {
		t.Errorf("missing consume job subgraph:\n%s", out)
	}
	if !strings.Contains(out, "sink_output_clobbering_critical_produce") {
		t.Errorf("missing produce-side output-clobbering sink:\n%s", out)
	}
	if !strings.Contains(out, "sink_request_forgery_critical_consume") {
		t.Errorf("missing consume-side request-forgery sink:\n%s", out)
	}
	// The cross-job edge itself: confirmed present against real output.
	if !strings.Contains(out, "-->|needs|") {
		t.Errorf("expected a cross-job needs edge linking produce's output-writer action to consume's tainted source:\n%s", out)
	}
	// Node IDs are whitelist-sanitized to [A-Za-z0-9_], so the parens/spaces in
	// the SourceName ("needs.produce.outputs.ref (tainted via github.head_ref)")
	// collapse to underscores in the ID.
	if !strings.Contains(out, "n_source_consume_1_needs_produce_outputs_ref__tainted_via_github_head_ref_") {
		t.Errorf("expected the needs-derived source node naming the upstream job and its taint origin:\n%s", out)
	}
}

// TestChainVizE2ELintEntryPointRendersMermaid is the regression for the review
// finding that Lint() (the -remote entry point, called from runRemoteScan) did
// not wire chain assembly like LintFiles/LintFile — so a mermaid format rendered
// empty on remote scans. runLinterMermaid exercises LintFile; this exercises Lint.
func TestChainVizE2ELintEntryPointRendersMermaid(t *testing.T) {
	path := "../../script/actions/chainviz-blastradius.yaml"
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	linter, err := NewLinter(&buf, &LinterOptions{CustomErrorMessageFormat: "{{mermaid .}}"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := linter.Lint(path, content, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "flowchart TD") {
		t.Errorf("Lint() entry point produced no mermaid graph:\n%s", buf.String())
	}
}

// TestChainVizE2EIgnoreFiltersRecords is the regression for PR #531's review
// comment: -ignore must suppress a finding from the chain graph AND its
// blast-radius counts, not just the textual output. Here -ignore secret-in-log
// must drop the log sink and its "log:" tally while leaving the other two sinks.
func TestChainVizE2EIgnoreFiltersRecords(t *testing.T) {
	path := "../../script/actions/chainviz-blastradius.yaml"
	var buf bytes.Buffer
	linter, err := NewLinter(&buf, &LinterOptions{
		CustomErrorMessageFormat: "{{mermaid .}}",
		ErrorIgnorePatterns:      []string{"secret-in-log"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := linter.LintFiles([]string{path}, nil); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "secret_in_log") {
		t.Errorf("-ignore secret-in-log must remove its sink node from the graph:\n%s", out)
	}
	if strings.Contains(out, "log:") {
		t.Errorf("blast-radius summary still counts the ignored log sink:\n%s", out)
	}
	// The non-ignored sinks must remain — ignore is scoped, not a blanket wipe.
	if !strings.Contains(out, "secret_exfiltration") || !strings.Contains(out, "secrets_in_artifacts") {
		t.Errorf("non-ignored sinks should still render:\n%s", out)
	}
}

// TestChainVizE2EStaleChainsClearedOnUnparseable guards the review fix (coderabbit):
// a file with no ParsedWorkflow (here a composite action, short-circuited in
// validate) must clear the formatter's chains, not re-render the previous file's
// graph when one Linter scans multiple files (the -remote / reuse pattern).
func TestChainVizE2EStaleChainsClearedOnUnparseable(t *testing.T) {
	var buf bytes.Buffer
	linter, err := NewLinter(&buf, &LinterOptions{CustomErrorMessageFormat: "{{mermaid .}}"})
	if err != nil {
		t.Fatal(err)
	}
	wf, err := os.ReadFile("../../script/actions/chainviz-blastradius.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := linter.Lint("blast.yml", wf, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "DEPLOY_TOKEN") {
		t.Fatalf("first lint should render the graph:\n%s", buf.String())
	}

	buf.Reset()
	// composite action: top-level runs: key -> short-circuited, ParsedWorkflow nil
	composite := []byte("name: x\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n")
	if _, err := linter.Lint("action.yml", composite, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "DEPLOY_TOKEN") {
		t.Errorf("stale chain from the previous file leaked into an unparseable file's output:\n%s", buf.String())
	}
}
