package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// remoteCalledRepo is a repository whose workflow calls a reusable
// workflow of another repository, with the answer of workflow.definition
// in facts.json: the step of the reusable workflow checks out the code of
// the pull request (a finding of untrusted-checkout, moved to the uses)
// and writes a step output it does not analyze into a run script (an
// inconclusive finding of code-injection, moved to the uses). It returns
// the directory and the file of facts.
func remoteCalledRepo(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	called := "on: workflow_call\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - id: s\n        uses: some/action@v1\n      - run: echo \"${{ steps.s.outputs.x }}\"\n"
	answer, err := json.Marshal(map[string]any{
		"query": map[string]string{"kind": "workflow.definition", "repo": "o/wf", "path": ".github/workflows/w.yml", "ref": "v1"},
		"state": "found",
		"value": map[string]string{"commit": strings.Repeat("e", 40), "content": called},
	})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		".github/workflows/ci.yml": "on: pull_request_target\npermissions: {}\njobs:\n  c:\n    uses: o/wf/.github/workflows/w.yml@v1\n",
		"facts.json":               `{"schema":"sisakulint/facts/v0","facts":[` + string(answer) + "]}\n",
	}
	for n, s := range files {
		p := filepath.Join(dir, n)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir, filepath.Join(dir, "facts.json")
}

// TestTextFactPlaceLine: text writes a place in the file of a fact with
// its line and column, as it writes a place of an input, not with the
// offset of its byte.
func TestTextFactPlaceLine(t *testing.T) {
	dir, f := remoteCalledRepo(t)
	got := run(t, raw("--root", dir, "--facts", f, "-v"))
	if !strings.Contains(got.stdout, "fact workflow.definition repo=o/wf path=.github/workflows/w.yml ref=v1:8:20") {
		t.Errorf("the place of the ref in w.yml is not written with its line and column:\n%s", got.stdout)
	}
	if strings.Contains(got.stdout, "ref=v1 @") {
		t.Errorf("a place in w.yml is written with the offset of its byte:\n%s", got.stdout)
	}
}

// TestSARIFFactPlacesInMessage: the message of a result names the places
// in the files of facts, which relatedLocations leaves out, for a finding
// and for an inconclusive finding.
func TestSARIFFactPlacesInMessage(t *testing.T) {
	dir, f := remoteCalledRepo(t)
	got := run(t, raw("--root", dir, "--facts", f, "--format", "sarif"))
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID  string `json:"ruleId"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				RelatedLocations []json.RawMessage `json:"relatedLocations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(got.stdout), &log); err != nil {
		t.Fatalf("%v: %s", err, got.stdout)
	}
	seen := map[string]bool{}
	for _, r := range log.Runs[0].Results {
		if r.RuleID != "untrusted-checkout.checkout" && !strings.HasPrefix(r.RuleID, "code-injection.") {
			continue
		}
		seen[strings.SplitN(r.RuleID, ".", 2)[0]] = true
		if !strings.Contains(r.Message.Text, "workflow.definition repo=o/wf path=.github/workflows/w.yml ref=v1 line ") {
			t.Errorf("%s: the message does not name the place in w.yml: %q", r.RuleID, r.Message.Text)
		}
		for _, l := range r.RelatedLocations {
			if strings.Contains(string(l), "w.yml") {
				t.Errorf("%s: a related location in the file of a fact: %s", r.RuleID, l)
			}
		}
	}
	if !seen["untrusted-checkout"] || !seen["code-injection"] {
		t.Fatalf("results of untrusted-checkout and code-injection: %v", seen)
	}
}
