package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"mvdan.cc/sh/v3/syntax"
)

func TestNewSecretInLogRule(t *testing.T) {
	t.Parallel()

	rule := NewSecretInLogRule()
	if rule.RuleName != "secret-in-log" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "secret-in-log")
	}
	if !strings.Contains(rule.RuleDesc, "log") {
		t.Errorf("RuleDesc should mention 'log', got %q", rule.RuleDesc)
	}
}

func TestSecretInLog_CollectSecretEnvVars(t *testing.T) {
	t.Parallel()

	env := &ast.Env{
		Vars: map[string]*ast.EnvVar{
			"token": {
				Name:  &ast.String{Value: "TOKEN"},
				Value: &ast.String{Value: "${{ secrets.API_TOKEN }}"},
			},
			"other": {
				Name:  &ast.String{Value: "OTHER"},
				Value: &ast.String{Value: "${{ github.event.inputs.x }}"},
			},
		},
	}

	rule := NewSecretInLogRule()
	got := rule.collectSecretEnvVars(env)

	if len(got) != 1 {
		t.Fatalf("expected 1 secret env var, got %d: %v", len(got), got)
	}
	if got["TOKEN"] != "secrets.API_TOKEN" {
		t.Errorf("expected TOKEN -> secrets.API_TOKEN, got %q", got["TOKEN"])
	}
}

func parseShellForTest(t *testing.T, script string) *syntax.File {
	t.Helper()
	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(script), "")
	if err != nil {
		t.Fatalf("failed to parse shell script: %v", err)
	}
	return file
}

func TestSecretInLog_PropagateTaint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		script   string
		initial  map[string]string
		expected map[string]bool // 期待される tainted 変数名
	}{
		{
			name: "command substitution with jq",
			script: `PRIVATE_KEY=$(echo "$GCP_KEY" | jq -r '.private_key')
echo "$PRIVATE_KEY"`,
			initial:  map[string]string{"GCP_KEY": "secrets.GCP"},
			expected: map[string]bool{"GCP_KEY": true, "PRIVATE_KEY": true},
		},
		{
			name: "chained assignment",
			script: `STEP1="$TOKEN"
STEP2=$(echo "$STEP1")`,
			initial:  map[string]string{"TOKEN": "secrets.T"},
			expected: map[string]bool{"TOKEN": true, "STEP1": true, "STEP2": true},
		},
		{
			name: "untainted variables stay untainted",
			script: `MSG="hello"
SAFE=$(date)`,
			initial:  map[string]string{"TOKEN": "secrets.T"},
			expected: map[string]bool{"TOKEN": true},
		},
		{
			name:     "assignment from untainted source does not taint",
			script:   `NOT_TAINTED=$(ls /tmp)`,
			initial:  map[string]string{"TOKEN": "secrets.T"},
			expected: map[string]bool{"TOKEN": true},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rule := NewSecretInLogRule()
			file := parseShellForTest(t, tc.script)
			got := rule.propagateTaint(file, tc.initial)
			if len(got) != len(tc.expected) {
				t.Fatalf("tainted set size = %d (%v), want %d (%v)", len(got), got, len(tc.expected), tc.expected)
			}
			for name := range tc.expected {
				if _, ok := got[name]; !ok {
					t.Errorf("expected %q to be tainted, was not. got=%v", name, got)
				}
			}
		})
	}
}

func TestSecretInLog_FindEchoLeaks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		script   string
		tainted  map[string]string
		wantHits []struct {
			varName string
			command string
		}
	}{
		{
			name: "echo of tainted var",
			script: `echo "Key: $PRIVATE_KEY"
`,
			tainted: map[string]string{"PRIVATE_KEY": "shellvar:GCP_KEY"},
			wantHits: []struct {
				varName string
				command string
			}{{"PRIVATE_KEY", "echo"}},
		},
		{
			name: "printf of tainted var",
			script: `printf "%s\n" "$TOKEN"
`,
			tainted: map[string]string{"TOKEN": "secrets.API"},
			wantHits: []struct {
				varName string
				command string
			}{{"TOKEN", "printf"}},
		},
		{
			name: "echo of untainted var",
			script: `echo "$MSG"
`,
			tainted:  map[string]string{"TOKEN": "secrets.API"},
			wantHits: nil,
		},
		{
			name: "add-mask suppresses echo",
			script: `echo "::add-mask::$TOKEN"
echo "Value: $TOKEN"
`,
			tainted:  map[string]string{"TOKEN": "secrets.API"},
			wantHits: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rule := NewSecretInLogRule()
			file := parseShellForTest(t, tc.script)
			runStr := &ast.String{Value: tc.script, Pos: &ast.Position{Line: 1, Col: 1}}
			got := rule.findEchoLeaks(file, tc.tainted, tc.script, runStr)
			if len(got) != len(tc.wantHits) {
				t.Fatalf("found %d leaks, want %d. got=%v", len(got), len(tc.wantHits), got)
			}
			for i, want := range tc.wantHits {
				if got[i].VarName != want.varName || got[i].Command != want.command {
					t.Errorf("hit[%d]: got {%s,%s}, want {%s,%s}",
						i, got[i].VarName, got[i].Command, want.varName, want.command)
				}
			}
		})
	}
}

func TestSecretInLog_VisitJob_Integration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		envVars    map[string]string
		runScript  string
		wantErrors int
	}{
		{
			name:       "jq-derived key leaked via echo",
			envVars:    map[string]string{"GCP_KEY": "${{ secrets.GCP_SERVICE_ACCOUNT_KEY }}"},
			runScript:  "PRIVATE_KEY=$(echo \"$GCP_KEY\" | jq -r '.private_key')\necho \"key: $PRIVATE_KEY\"",
			wantErrors: 1,
		},
		{
			name:       "chained assignment leaked via printf",
			envVars:    map[string]string{"TOKEN": "${{ secrets.API_TOKEN }}"},
			runScript:  "STEP1=\"$TOKEN\"\nSTEP2=$(echo \"$STEP1\")\nprintf 'val=%s\\n' \"$STEP2\"",
			wantErrors: 1,
		},
		{
			name:       "direct echo of secret env",
			envVars:    map[string]string{"SECRET": "${{ secrets.PLAIN }}"},
			runScript:  "echo \"val=$SECRET\"",
			wantErrors: 1,
		},
		{
			// goat case11 の元シナリオをそのまま固定化するゴールデンテスト。
			// script/actions/goat-secret-in-build-log.yml の該当 step と同等。
			name:    "goat case11 golden: GCP private key via jq",
			envVars: map[string]string{"GCP_SERVICE_ACCOUNT_KEY": "${{ secrets.GCP_SERVICE_ACCOUNT_KEY }}"},
			runScript: "# Extracting the private key from the GCP service account key\n" +
				"PRIVATE_KEY=$(echo $GCP_SERVICE_ACCOUNT_KEY | jq -r '.private_key')\n\n" +
				"# Simulate using the private key\n" +
				"echo \"Using the private key for some operation\"\n\n" +
				"# Log the private key (simulating a mistake)\n" +
				"echo \"GCP Private Key: $PRIVATE_KEY\"",
			wantErrors: 1,
		},
		{
			name:       "add-mask before use (safe)",
			envVars:    map[string]string{"GCP_KEY": "${{ secrets.GCP_SERVICE_ACCOUNT_KEY }}"},
			runScript:  "PRIVATE_KEY=$(echo \"$GCP_KEY\" | jq -r '.private_key')\necho \"::add-mask::$PRIVATE_KEY\"\necho \"key: $PRIVATE_KEY\"",
			wantErrors: 0,
		},
		{
			name:       "unrelated echo (safe)",
			envVars:    map[string]string{"TOKEN": "${{ secrets.API_TOKEN }}"},
			runScript:  "MSG=\"hello\"\necho \"$MSG\"",
			wantErrors: 0,
		},
		{
			name:       "secret used with curl but not echo (safe)",
			envVars:    map[string]string{"TOKEN": "${{ secrets.API_TOKEN }}"},
			runScript:  "curl -H \"Authorization: Bearer $TOKEN\" https://api.github.com/user",
			wantErrors: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rule := NewSecretInLogRule()

			envVars := map[string]*ast.EnvVar{}
			for name, val := range tc.envVars {
				envVars[strings.ToLower(name)] = &ast.EnvVar{
					Name:  &ast.String{Value: name},
					Value: &ast.String{Value: val},
				}
			}

			step := &ast.Step{
				Env: &ast.Env{Vars: envVars},
				Exec: &ast.ExecRun{
					Run: &ast.String{Value: tc.runScript, Pos: &ast.Position{Line: 1, Col: 1}},
				},
			}
			job := &ast.Job{Steps: []*ast.Step{step}}

			if err := rule.VisitJobPre(job); err != nil {
				t.Fatalf("VisitJobPre returned err: %v", err)
			}
			if got := len(rule.Errors()); got != tc.wantErrors {
				t.Errorf("errors = %d, want %d. details=%v", got, tc.wantErrors, rule.Errors())
			}
		})
	}
}

func TestSecretInLog_AutoFix_InsertsAddMask(t *testing.T) {
	t.Parallel()

	original := "PRIVATE_KEY=$(echo \"$GCP_KEY\" | jq -r '.private_key')\necho \"key: $PRIVATE_KEY\""
	step := &ast.Step{
		Env: &ast.Env{Vars: map[string]*ast.EnvVar{
			"gcp_key": {
				Name:  &ast.String{Value: "GCP_KEY"},
				Value: &ast.String{Value: "${{ secrets.GCP }}"},
			},
		}},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: original, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}

	rule := NewSecretInLogRule()
	if err := rule.VisitJobPre(&ast.Job{Steps: []*ast.Step{step}}); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	if len(rule.AutoFixers()) == 0 {
		t.Fatal("expected at least one auto-fixer")
	}
	for _, f := range rule.AutoFixers() {
		if err := f.Fix(); err != nil {
			t.Fatalf("Fix: %v", err)
		}
	}

	got := step.Exec.(*ast.ExecRun).Run.Value
	// add-mask should be inserted AFTER the assignment, not before
	if !strings.Contains(got, "PRIVATE_KEY=$(echo \"$GCP_KEY\" | jq -r '.private_key')\necho \"::add-mask::$PRIVATE_KEY\"") {
		t.Errorf("add-mask should be inserted AFTER the assignment, got: %q", got)
	}
}

func TestSecretInLog_AutoFix_EnvOnlyVar_PrependsAtTop(t *testing.T) {
	t.Parallel()

	// env-only case: SECRET is directly from secrets.P, no shell assignment
	original := `echo "$SECRET"`
	step := &ast.Step{
		Env: &ast.Env{Vars: map[string]*ast.EnvVar{
			"secret": {
				Name:  &ast.String{Value: "SECRET"},
				Value: &ast.String{Value: "${{ secrets.P }}"},
			},
		}},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: original, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}

	rule := NewSecretInLogRule()
	if err := rule.VisitJobPre(&ast.Job{Steps: []*ast.Step{step}}); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	if len(rule.AutoFixers()) == 0 {
		t.Fatal("expected at least one auto-fixer")
	}
	for _, f := range rule.AutoFixers() {
		if err := f.Fix(); err != nil {
			t.Fatalf("Fix: %v", err)
		}
	}

	got := step.Exec.(*ast.ExecRun).Run.Value
	// For env-only vars (origin "secrets.*"), prepend at top is correct
	if !strings.HasPrefix(got, `echo "::add-mask::$SECRET"`) {
		t.Errorf("expected add-mask prepended at top for env-only var, got: %q", got)
	}
}

func TestSecretInLog_JobLevelEnv(t *testing.T) {
	t.Parallel()

	// Job-level env: contains the secret ref; step has no env of its own.
	// The rule should still detect the leak.
	runScript := "PRIVATE=$(echo \"$GCP_KEY\" | jq -r '.private_key')\necho \"key: $PRIVATE\""

	jobEnvVars := map[string]*ast.EnvVar{
		"gcp_key": {
			Name:  &ast.String{Value: "GCP_KEY"},
			Value: &ast.String{Value: "${{ secrets.GCP }}"},
		},
	}

	step := &ast.Step{
		Env: nil, // step has no env
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: runScript, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}
	job := &ast.Job{
		Env:   &ast.Env{Vars: jobEnvVars},
		Steps: []*ast.Step{step},
	}

	rule := NewSecretInLogRule()
	if err := rule.VisitJobPre(job); err != nil {
		t.Fatalf("VisitJobPre returned err: %v", err)
	}
	if got := len(rule.Errors()); got != 1 {
		t.Errorf("errors = %d, want 1. details=%v", got, rule.Errors())
	}
}

func TestSecretInLog_WorkflowLevelEnv(t *testing.T) {
	t.Parallel()

	// Workflow-level env: contains the secret ref; job and step have no env.
	// The rule should still detect the leak.
	runScript := "PRIVATE=$(echo \"$GCP_KEY\" | jq -r '.private_key')\necho \"key: $PRIVATE\""

	workflowEnvVars := map[string]*ast.EnvVar{
		"gcp_key": {
			Name:  &ast.String{Value: "GCP_KEY"},
			Value: &ast.String{Value: "${{ secrets.GCP }}"},
		},
	}

	step := &ast.Step{
		Env: nil, // step has no env
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: runScript, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}
	job := &ast.Job{
		Env:   nil, // job has no env
		Steps: []*ast.Step{step},
	}
	workflow := &ast.Workflow{
		Env:  &ast.Env{Vars: workflowEnvVars},
		Jobs: map[string]*ast.Job{"leak": job},
	}

	rule := NewSecretInLogRule()
	if err := rule.VisitWorkflowPre(workflow); err != nil {
		t.Fatalf("VisitWorkflowPre returned err: %v", err)
	}
	if err := rule.VisitJobPre(job); err != nil {
		t.Fatalf("VisitJobPre returned err: %v", err)
	}
	if got := len(rule.Errors()); got != 1 {
		t.Errorf("errors = %d, want 1. details=%v", got, rule.Errors())
	}
}

func TestSecretInLog_AutoFix_SkipsWhenAlreadyMasked(t *testing.T) {
	t.Parallel()

	original := "PRIVATE_KEY=$(echo \"$GCP_KEY\" | jq -r '.private_key')\necho \"::add-mask::$PRIVATE_KEY\"\necho \"$PRIVATE_KEY\""
	step := &ast.Step{
		Env: &ast.Env{Vars: map[string]*ast.EnvVar{
			"gcp_key": {
				Name:  &ast.String{Value: "GCP_KEY"},
				Value: &ast.String{Value: "${{ secrets.GCP }}"},
			},
		}},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: original, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}

	rule := NewSecretInLogRule()
	_ = rule.VisitJobPre(&ast.Job{Steps: []*ast.Step{step}})
	if len(rule.Errors()) != 0 {
		t.Errorf("expected 0 errors (already masked), got %d", len(rule.Errors()))
	}
}
