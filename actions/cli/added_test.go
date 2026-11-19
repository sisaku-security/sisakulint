package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// labelApproved is a repository whose workflow runs the code of a pull
// request in a job that a label approves: a run that adds an attacker
// who adds a label gets a finding of untrusted-checkout there.
func labelApproved(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	src := "on:\n  pull_request_target:\n    types: [labeled]\npermissions: {}\njobs:\n  test:\n    if: github.event.label.name == 'safe to test'\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          persist-credentials: false\n      - run: make test\n"
	if err := os.WriteFile(filepath.Join(dir, ".github", "workflows", "w.yml"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// addedReport is the attackers of a report and the marks of its findings
// of untrusted-checkout.
type addedReport struct {
	Added    []string `json:"added_attackers"`
	Findings []struct {
		Rule  string   `json:"rule"`
		Added []string `json:"added_attackers"`
	} `json:"findings"`
}

func readAdded(t *testing.T, out string) (added []string, marks [][]string) {
	t.Helper()
	var r addedReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for _, f := range r.Findings {
		if f.Rule == "untrusted-checkout" {
			marks = append(marks, f.Added)
		}
	}
	return r.Added, marks
}

// TestAddAttackerFlag: the attackers of --add-attacker, given again or
// joined by commas, are those of the report, each once;
// the finding only they give is marked; a run without them is unmarked.
func TestAddAttackerFlag(t *testing.T) {
	dir := labelApproved(t)
	if added, marks := readAdded(t, run(t, args("--root", dir)).stdout); added != nil || len(marks) != 0 {
		t.Errorf("no --add-attacker: added %v, marks %v", added, marks)
	}
	for _, e := range []Env{
		args("--root", dir, "--add-attacker", "triage-account", "--add-attacker", "read-member"),
		args("--root", dir, "--add-attacker", "read-member,triage-account"),
		args("--root", dir, "--add-attacker", "triage-account,read-member,triage-account"),
	} {
		got := run(t, e)
		added, marks := readAdded(t, got.stdout)
		if !slices.Equal(added, []string{"read-member", "triage-account"}) {
			t.Errorf("%v: added %v", e.Args, added)
		}
		if len(marks) != 1 || !slices.Equal(marks[0], []string{"triage-account"}) {
			t.Errorf("%v: marks %v, want one finding of triage-account", e.Args, marks)
		}
		if got.code&3 == 0 {
			t.Errorf("%v: exit %d, want bit 1 or 2 of the marked finding", e.Args, got.code)
		}
	}
}

// TestAddAttackerConfiguration: the key add-attacker of the configuration
// file adds the attackers too.
func TestAddAttackerConfiguration(t *testing.T) {
	dir := labelApproved(t)
	c := configurationFile(t, t.TempDir(), "add-attacker: [triage-account]\n")
	added, marks := readAdded(t, run(t, args("--root", dir, "--config", c)).stdout)
	if !slices.Equal(added, []string{"triage-account"}) || len(marks) != 1 {
		t.Errorf("added %v, marks %v", added, marks)
	}
}

// TestAddAttackerUsage: an unknown value, and --fix with --add-attacker,
// are errors of usage (exit 64); the message of an unknown value names the
// values.
func TestAddAttackerUsage(t *testing.T) {
	dir := labelApproved(t)
	got := run(t, args("--root", dir, "--add-attacker", "admin"))
	if got.code != 64 || !strings.Contains(got.stderr, "read-member") || !strings.Contains(got.stderr, "secrets-writer") {
		t.Errorf("unknown: exit %d, stderr %q", got.code, got.stderr)
	}
	if got := run(t, args("--root", dir, "--add-attacker", "triage-account", "--fix")); got.code != 64 || !strings.Contains(got.stderr, "--add-attacker") {
		t.Errorf("with --fix: exit %d, stderr %q", got.code, got.stderr)
	}
}

// TestAddAttackerOutputs: the text writes the mark under the finding, and
// SARIF writes it in the properties of the result.
func TestAddAttackerOutputs(t *testing.T) {
	dir := labelApproved(t)
	sarif := filepath.Join(t.TempDir(), "r.sarif")
	got := run(t, raw("--root", dir, "--add-attacker", "triage-account", "--sarif", sarif, "-v"))
	if !strings.Contains(got.stdout, "added attacker: triage-account") {
		t.Errorf("text: %s", got.stdout)
	}
	b, err := os.ReadFile(sarif)
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID     string `json:"ruleId"`
				Properties struct {
					Added []string `json:"added_attackers"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &log); err != nil || len(log.Runs) != 1 {
		t.Fatalf("SARIF: %v", err)
	}
	marked := 0
	for _, r := range log.Runs[0].Results {
		if strings.HasPrefix(r.RuleID, "untrusted-checkout.") && slices.Equal(r.Properties.Added, []string{"triage-account"}) {
			marked++
		}
	}
	if marked != 1 {
		t.Errorf("SARIF: %d marked results of untrusted-checkout, want 1", marked)
	}
}
