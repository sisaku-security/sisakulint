package workflow

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// Why the model's diagnostics differ from the expected result of a reader
// test of languageservices: an expected error without a diagnostic, a
// diagnostic without an expected error, or an expected error on a line
// with no diagnostic. Each file is "options --- workflow --- (name
// --- workflow)* --- expected JSON"; the expected results are those of
// GitHub's parsers other than TypeScript unless the options skip Go and
// C#.
const (
	whySemantic = "a check beyond the schema: called workflows, limits of size, matrix, runs-on, a container's image"
	whyRemote   = "a remote called workflow, which the model does not fetch (local calls are checked: CheckCall)"
	whyAnchors  = "GitHub supports anchors since 2025-09-18 (changelog); the expected result is older"
	whyTSOnly   = "a TypeScript-only test of on-strict; GitHub reads events loosely"
	whyCST      = "yaml/cst/v1 ModeGitHub rejects a # right after ] (YamlDotNet 5.3.0 reads it as a comment; not fixed yet)"
)

var readerDiffers = map[string]string{
	"errors-anchor-tag.yml":                                  whyAnchors,
	"errors-job-runs-on-group-invalid-prefix.yml":            whySemantic,
	"errors-jobs-at-least-one.yml":                           whySemantic,
	"errors-matrix-empty-vector.yml":                         whySemantic,
	"errors-matrix-max-depth.yml":                            whySemantic,
	"errors-max-depth.yml":                                   whySemantic,
	"errors-max-file-size.yml":                               whySemantic,
	"errors-max-job-limit-with-reusable-workflow.yml":        whySemantic,
	"errors-max-result-size.yml":                             whySemantic,
	"errors-reusable-workflow-job-inputs-required.yml":       whyRemote,
	"errors-reusable-workflow-job-inputs-type-mismatch.yml":  whyRemote,
	"errors-reusable-workflow-job-inputs-undefined.yml":      whyRemote,
	"errors-reusable-workflow-job-nested-depth-exceeded.yml": whySemantic,
	"errors-reusable-workflow-job-secrets-required.yml":      whyRemote,
	"errors-reusable-workflow-job-secrets-undefined.yml":     whyRemote,
	"errors-reusable-workflow-max-result-size.yml":           whySemantic,
	"events-single-invalid-config.yml":                       whyTSOnly,
	"events-single-invalid.yml":                              whyTSOnly,
	"job-container-missing-image.yml":                        whySemantic,
	"yaml-schema-sequence.yml":                               whyCST,
}

// The permission checks of called workflows are the same check many times.
func readerDiffer(name string) (string, bool) {
	if strings.HasPrefix(name, "errors-reusable-workflow-permissions-not-allowed-") ||
		strings.HasPrefix(name, "errors-reusable-workflow-job-nested-permissions-not-allowed-") {
		return whySemantic, true
	}
	why, ok := readerDiffers[name]
	return why, ok
}

type readerExpect struct {
	Errors []struct{ Message string } `json:"errors"`
	Jobs   []struct {
		ID    json.RawMessage `json:"id"`
		Steps []struct {
			Uses json.RawMessage `json:"uses"`
			Run  json.RawMessage `json:"run"`
		} `json:"steps"`
	} `json:"jobs"`
}

func TestLanguageservicesReader(t *testing.T) {
	dir := "testdata/languageservices/workflow-parser/testdata/reader"
	files, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no reader tests in %s: %v", dir, err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		name := filepath.Base(f)
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		docs := strings.Split("\n"+string(b), "\n---\n")
		var want readerExpect
		if err := json.Unmarshal([]byte(docs[len(docs)-1]), &want); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		src := []byte(docs[1])
		tr := cst.ParseMode(src, cst.ModeGitHub)
		w, diags := Parse(tr)
		why, known := readerDiffer(name)
		if (len(want.Errors) > 0) != (len(diags) > 0) || len(missedLines(tr, want, diags)) > 0 {
			if !known {
				t.Errorf("%s: expected errors %v, diagnostics %v, lines without a diagnostic %v", name, want.Errors, diags, missedLines(tr, want, diags))
			}
			seen[name] = true
			continue
		}
		if known {
			t.Errorf("%s: listed as differing (%s), but agrees", name, why)
		}
		if len(want.Errors) > 0 {
			continue
		}
		// The jobs and the steps GitHub makes of the workflow.
		if len(want.Jobs) != len(w.Jobs.Value.Entries) {
			t.Errorf("%s: %d jobs, want %d", name, len(w.Jobs.Value.Entries), len(want.Jobs))
			continue
		}
		for i, wj := range want.Jobs {
			j := w.Jobs.Value.Entries[i].Value.Value
			checkStepString(t, name, "job id", wj.ID, j.ID)
			if j.Kind != JobRunner {
				continue
			}
			steps := j.Steps.Value.Items
			if len(steps) != len(wj.Steps) {
				t.Errorf("%s: job %s has %d steps, want %d", name, j.ID.AsString(), len(steps), len(wj.Steps))
				continue
			}
			for k, ws := range wj.Steps {
				checkStepString(t, name, "uses", ws.Uses, steps[k].Uses.Value.String)
				checkStepString(t, name, "run", ws.Run, steps[k].Run.Value)
			}
		}
	}
	t.Logf("%d reader tests, %d differ for a listed reason", len(files), len(seen))
	var missing []string
	for n := range readerDiffers {
		if !seen[n] {
			missing = append(missing, n)
		}
	}
	sort.Strings(missing)
	for _, n := range missing {
		t.Errorf("%s: listed as differing but not seen", n)
	}
}

var lineOf = regexp.MustCompile(`\(Line: (\d+), Col: \d+\)`)

// missedLines are the lines of the expected errors, where the message says
// one, that have no diagnostic of the model.
func missedLines(tr *cst.Tree, want readerExpect, diags []Diagnostic) []int {
	have := map[int]bool{}
	for _, d := range diags {
		have[tr.Position(d.Span.Start).Line] = true
	}
	var missed []int
	for _, e := range want.Errors {
		m := lineOf.FindStringSubmatch(e.Message)
		if m == nil {
			continue
		}
		// The workflow is the second document; line numbers count from it.
		if n, _ := strconv.Atoi(m[1]); !have[n] {
			missed = append(missed, n)
		}
	}
	return missed
}

// checkStepString compares a value the expected result has as a plain
// string (an expression is an object there, and is not compared).
func checkStepString(t *testing.T, file, key string, want json.RawMessage, got String) {
	t.Helper()
	var s string
	if len(want) == 0 || json.Unmarshal(want, &s) != nil {
		return
	}
	if got.AsString() != s {
		t.Errorf("%s: %s %q, want %q", file, key, got.AsString(), s)
	}
}
