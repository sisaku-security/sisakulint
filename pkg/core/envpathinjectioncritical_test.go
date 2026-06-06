package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestEnvPathInjectionCriticalRule(t *testing.T) {
	t.Parallel()
	rule := EnvPathInjectionCriticalRule()
	if rule.RuleName != "envpath-injection-critical" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "envpath-injection-critical")
	}
}

func TestEnvPathInjectionCritical_PrivilegedTriggers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		trigger     string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "pull_request_target + GITHUB_PATH",
			trigger:     "pull_request_target",
			runScript:   `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
			wantErrors:  1,
			description: "Should detect PATH injection in privileged trigger",
		},
		{
			name:        "issue_comment + GITHUB_PATH",
			trigger:     "issue_comment",
			runScript:   `echo "${{ github.event.comment.body }}" >> $GITHUB_PATH`,
			wantErrors:  1,
			description: "Should detect PATH injection in issue_comment",
		},
		{
			name:        "workflow_run + GITHUB_PATH with head_commit",
			trigger:     "workflow_run",
			runScript:   `echo "${{ github.event.head_commit.message }}" >> "$GITHUB_PATH"`,
			wantErrors:  1,
			description: "Should detect PATH injection in workflow_run",
		},
		{
			name:        "pull_request (not privileged)",
			trigger:     "pull_request",
			runScript:   `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
			wantErrors:  0,
			description: "Should not detect for non-privileged trigger",
		},
		{
			name:    "multiple GITHUB_PATH writes",
			trigger: "pull_request_target",
			runScript: `echo "${{ github.event.pull_request.title }}" >> "$GITHUB_PATH"
echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
			wantErrors:  2,
			description: "Should detect both PATH injections",
		},
		{
			name:        "safe with trusted input",
			trigger:     "pull_request_target",
			runScript:   `echo "/usr/local/bin" >> "$GITHUB_PATH"`,
			wantErrors:  0,
			description: "Should not detect for hardcoded path",
		},
		{
			name:        "safe with github.workspace",
			trigger:     "pull_request_target",
			runScript:   `echo "${{ github.workspace }}/bin" >> "$GITHUB_PATH"`,
			wantErrors:  0,
			description: "Should not detect for trusted github.workspace",
		},
		{
			name:        "extracted path from untrusted input",
			trigger:     "pull_request_target",
			runScript:   `echo "${{ github.event.comment.body }}" >> "$GITHUB_PATH"`,
			wantErrors:  1,
			description: "Should detect untrusted input even in complex patterns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := EnvPathInjectionCriticalRule()

			// Create workflow with specified trigger
			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: tt.trigger},
					},
				},
			}

			// Create job with GITHUB_PATH write
			job := &ast.Job{
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Value: tt.runScript,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			}

			// Visit workflow first
			err := rule.VisitWorkflowPre(workflow)
			if err != nil {
				t.Fatalf("VisitWorkflowPre() returned error: %v", err)
			}

			// Then visit job
			err = rule.VisitJobPre(job)
			if err != nil {
				t.Fatalf("VisitJobPre() returned error: %v", err)
			}

			gotErrors := len(rule.Errors())

			if gotErrors != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d", tt.description, gotErrors, tt.wantErrors)
				for _, err := range rule.Errors() {
					t.Logf("  error: %s", err.Description)
				}
			}
		})
	}
}

func TestEnvPathInjectionCritical_AutoFix(t *testing.T) {
	t.Parallel()
	rule := EnvPathInjectionCriticalRule()

	// Create workflow with privileged trigger
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request_target"},
			},
		},
	}

	// Create job with vulnerable GITHUB_PATH write
	job := &ast.Job{
		Steps: []*ast.Step{
			{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
		},
	}

	// Visit workflow and job
	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)

	errors := rule.Errors()
	if len(errors) == 0 {
		t.Fatal("expected errors but got none")
	}

	// Get the step
	step := job.Steps[0]

	// Apply fix
	err := rule.FixStep(step)
	if err != nil {
		t.Fatalf("FixStep() returned error: %v", err)
	}

	// Verify the fix
	run := step.Exec.(*ast.ExecRun)
	if run.Run == nil {
		t.Fatal("run script is nil")
	}

	// Check that the expression was sanitized with realpath
	if !strings.Contains(run.Run.Value, `realpath`) {
		t.Errorf("expected sanitization with realpath, got: %s", run.Run.Value)
	}

	// Check that env var was added
	if step.Env == nil || len(step.Env.Vars) == 0 {
		t.Error("expected env vars to be added")
	}
}

func TestEnvPathInjectionCritical_FixStep_ComposesWithCodeInjection(t *testing.T) {
	tests := []struct {
		name       string
		run        string
		want       string
		absentEnvs []string
	}{
		{
			name:       "pull request body gets realpath after code injection fix",
			run:        `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
			want:       `echo "$(realpath "$PR_BODY")" >> "$GITHUB_PATH"`,
			absentEnvs: []string{"PR_BODY_PATH"},
		},
		{
			name: "multiple github path writes get realpath after code injection fix",
			run: `echo "${{ github.event.pull_request.title }}" >> "$GITHUB_PATH"
echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"
echo "${{ github.event.comment.body }}" >> "$GITHUB_PATH"`,
			want: `echo "$(realpath "$PR_TITLE")" >> "$GITHUB_PATH"
echo "$(realpath "$PR_BODY")" >> "$GITHUB_PATH"
echo "$(realpath "$COMMENT_BODY")" >> "$GITHUB_PATH"`,
			absentEnvs: []string{"PR_TITLE_PATH", "PR_BODY_PATH", "COMMENT_BODY_PATH"},
		},
		{
			name:       "workflow run head branch gets realpath after code injection fix",
			run:        `echo "${{ github.event.workflow_run.head_branch }}" >> "$GITHUB_PATH"`,
			want:       `echo "$(realpath "$WORKFLOWRUN_HEAD_BRANCH")" >> "$GITHUB_PATH"`,
			absentEnvs: []string{"WORKFLOWRUN_HEAD_BRANCH_PATH"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workflow, job, step := envPathInjectionCriticalWorkflowWithRun(tt.run)
			codeRule := CodeInjectionCriticalRule(nil)
			envPathRule := EnvPathInjectionCriticalRule()

			if err := codeRule.VisitWorkflowPre(workflow); err != nil {
				t.Fatalf("code VisitWorkflowPre() error = %v", err)
			}
			if err := codeRule.VisitJobPre(job); err != nil {
				t.Fatalf("code VisitJobPre() error = %v", err)
			}
			if err := envPathRule.VisitWorkflowPre(workflow); err != nil {
				t.Fatalf("envpath VisitWorkflowPre() error = %v", err)
			}
			if err := envPathRule.VisitJobPre(job); err != nil {
				t.Fatalf("envpath VisitJobPre() error = %v", err)
			}

			if len(codeRule.AutoFixers()) == 0 {
				t.Fatal("expected code-injection autofixer")
			}
			if len(envPathRule.AutoFixers()) == 0 {
				t.Fatal("expected envpath-injection autofixer")
			}

			if err := codeRule.FixStep(step); err != nil {
				t.Fatalf("code FixStep() error = %v", err)
			}
			if err := envPathRule.FixStep(step); err != nil {
				t.Fatalf("envpath FixStep() error = %v", err)
			}

			got := step.Exec.(*ast.ExecRun).Run.Value
			if got != tt.want {
				t.Errorf("fixed run script = %q, want %q", got, tt.want)
			}
			for _, envName := range tt.absentEnvs {
				if _, ok := step.Env.Vars[strings.ToLower(envName)]; ok {
					t.Errorf("unexpected dead env var %q", envName)
				}
			}
		})
	}
}

func TestEnvPathInjectionCritical_FixStep_AvoidsExistingEnvCollisionAfterCodeInjection(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
	)
	step.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "PR_BODY"},
			Value: &ast.String{Value: "/tmp/from-user"},
		},
	}}

	codeRule := CodeInjectionCriticalRule(nil)
	envPathRule := EnvPathInjectionCriticalRule()

	if err := codeRule.VisitWorkflowPre(workflow); err != nil {
		t.Fatalf("code VisitWorkflowPre() error = %v", err)
	}
	if err := codeRule.VisitJobPre(job); err != nil {
		t.Fatalf("code VisitJobPre() error = %v", err)
	}
	if err := envPathRule.VisitWorkflowPre(workflow); err != nil {
		t.Fatalf("envpath VisitWorkflowPre() error = %v", err)
	}
	if err := envPathRule.VisitJobPre(job); err != nil {
		t.Fatalf("envpath VisitJobPre() error = %v", err)
	}

	if len(codeRule.AutoFixers()) == 0 {
		t.Fatal("expected code-injection autofixer")
	}
	if len(envPathRule.AutoFixers()) == 0 {
		t.Fatal("expected envpath-injection autofixer")
	}

	if err := codeRule.FixStep(step); err != nil {
		t.Fatalf("code FixStep() error = %v", err)
	}
	if err := envPathRule.FixStep(step); err != nil {
		t.Fatalf("envpath FixStep() error = %v", err)
	}

	if got := step.Env.Vars["pr_body"].Value.Value; got != "/tmp/from-user" {
		t.Fatalf("existing PR_BODY env var was overwritten: %q", got)
	}
	added := step.Env.Vars["pr_body_2"]
	if added == nil || added.Value == nil {
		t.Fatalf("expected PR_BODY_2 env var for colliding expression, got %#v", step.Env.Vars)
	}
	if got := added.Value.Value; got != "${{ github.event.pull_request.body }}" {
		t.Fatalf("PR_BODY_2 value = %q, want pull request body expression", got)
	}

	// code-injection rewrote the expression to `$PR_BODY`, which expands to
	// the user-supplied "/tmp/from-user" — not the attacker body. The
	// envpath-injection autofix must NOT rewrite that `$PR_BODY` to
	// `$(realpath "$PR_BODY_2")`, because doing so would (a) re-inject the
	// attacker-controlled value via PR_BODY_2 and (b) silently clobber any
	// unrelated `$PR_BODY` references the user has on GITHUB_PATH lines.
	// This is the regression flagged by codex in PR #514 review.
	want := `echo "$PR_BODY" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestEnvPathInjectionCritical_FixStep_LeavesUnrelatedBaseEnvVarReference asserts
// that when the base env var name (e.g., PR_BODY) is occupied by an unrelated
// user value and the autofix suffixes the chosen name (PR_BODY_2), an existing
// `$PR_BODY` reference on another GITHUB_PATH line is NOT rewritten to the
// attacker-controlled `$PR_BODY_2`. This is the regression originally flagged
// by codex in PR #514 review.
func TestEnvPathInjectionCritical_FixStep_LeavesUnrelatedBaseEnvVarReference(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`echo "/some/$PR_BODY" >> "$GITHUB_PATH"
echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
	)
	step.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "PR_BODY"},
			Value: &ast.String{Value: "/tmp/from-user"},
		},
	}}

	envPathRule := EnvPathInjectionCriticalRule()

	if err := envPathRule.VisitWorkflowPre(workflow); err != nil {
		t.Fatalf("envpath VisitWorkflowPre() error = %v", err)
	}
	if err := envPathRule.VisitJobPre(job); err != nil {
		t.Fatalf("envpath VisitJobPre() error = %v", err)
	}
	if len(envPathRule.AutoFixers()) == 0 {
		t.Fatal("expected envpath-injection autofixer")
	}
	if err := envPathRule.FixStep(step); err != nil {
		t.Fatalf("envpath FixStep() error = %v", err)
	}

	if got := step.Env.Vars["pr_body"].Value.Value; got != "/tmp/from-user" {
		t.Fatalf("existing PR_BODY env var was overwritten: %q", got)
	}
	added := step.Env.Vars["pr_body_2"]
	if added == nil || added.Value == nil {
		t.Fatalf("expected PR_BODY_2 env var for colliding expression, got %#v", step.Env.Vars)
	}

	want := `echo "/some/$PR_BODY" >> "$GITHUB_PATH"
echo "$(realpath "$PR_BODY_2")" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestEnvPathInjectionCritical_FixStep_PreservesBracedEnvRef asserts the
// user's braced shell form `${PR_BODY}` is left untouched by the autofix
// (no rewrite to `$(realpath "")` or any other shape). With the collision
// check, the autofix now suffixes its chosen name to PR_BODY_2 instead of
// shadowing the user's `${PR_BODY}` reference.
func TestEnvPathInjectionCritical_FixStep_PreservesBracedEnvRef(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`echo "${PR_BODY}/bin" >> "$GITHUB_PATH"
echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
	)

	envPathRule := EnvPathInjectionCriticalRule()

	if err := envPathRule.VisitWorkflowPre(workflow); err != nil {
		t.Fatalf("envpath VisitWorkflowPre() error = %v", err)
	}
	if err := envPathRule.VisitJobPre(job); err != nil {
		t.Fatalf("envpath VisitJobPre() error = %v", err)
	}
	if len(envPathRule.AutoFixers()) == 0 {
		t.Fatal("expected envpath-injection autofixer")
	}
	if err := envPathRule.FixStep(step); err != nil {
		t.Fatalf("envpath FixStep() error = %v", err)
	}

	want := `echo "${PR_BODY}/bin" >> "$GITHUB_PATH"
echo "$(realpath "$PR_BODY_2")" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
	if strings.Contains(got, `realpath ""`) {
		t.Errorf(`fixed run script contains broken empty path realpath "": %q`, got)
	}
}

// TestEnvPathInjectionCritical_FixStep_AvoidsScriptDefinedShellName asserts
// that when the script already assigns or references a shell variable named
// like the autofix's would-be env var, the autofix suffixes the env var
// name instead of shadowing the user's shell variable. This is the
// regression flagged by codex on PR #514: collision detection previously
// only inspected `step.Env.Vars`, not shell vars used in the run script.
func TestEnvPathInjectionCritical_FixStep_AvoidsScriptDefinedShellName(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`PR_BODY=/safe
echo "$PR_BODY" >> "$GITHUB_PATH"
echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
	)

	envPathRule := EnvPathInjectionCriticalRule()

	if err := envPathRule.VisitWorkflowPre(workflow); err != nil {
		t.Fatalf("envpath VisitWorkflowPre() error = %v", err)
	}
	if err := envPathRule.VisitJobPre(job); err != nil {
		t.Fatalf("envpath VisitJobPre() error = %v", err)
	}
	if len(envPathRule.AutoFixers()) == 0 {
		t.Fatal("expected envpath-injection autofixer")
	}
	if err := envPathRule.FixStep(step); err != nil {
		t.Fatalf("envpath FixStep() error = %v", err)
	}

	// The autofix must NOT create a `PR_BODY` env var, because the script
	// already uses `PR_BODY` as a shell variable; doing so would shadow
	// the user's safe `$PR_BODY` with the attacker-controlled body value.
	if added := step.Env.Vars["pr_body"]; added != nil {
		t.Fatalf("autofix wrongly created PR_BODY env var (would shadow shell var): %+v", added.Value)
	}
	added := step.Env.Vars["pr_body_2"]
	if added == nil || added.Value == nil {
		t.Fatalf("expected suffixed PR_BODY_2 env var, got %#v", step.Env.Vars)
	}
	if got := added.Value.Value; got != "${{ github.event.pull_request.body }}" {
		t.Errorf("PR_BODY_2 value = %q, want pull request body expression", got)
	}

	want := `PR_BODY=/safe
echo "$PR_BODY" >> "$GITHUB_PATH"
echo "$(realpath "$PR_BODY_2")" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestScriptUsesShellName_StripsGitHubExpressions pins that the matcher
// does not false-positive on identifiers that appear only inside a
// `${{ ... }}` GitHub Actions expression (which gets rewritten by the
// autofix anyway). Without stripping, every chosen name would collide
// with itself when the expression references the same path component.
func TestScriptUsesShellName_StripsGitHubExpressions(t *testing.T) {
	script := `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`
	// `body` appears inside the `${{ ... }}` block; it must not match.
	if scriptUsesShellName(script, "body") {
		t.Errorf("scriptUsesShellName matched a name that only appears inside ${{ ... }}")
	}
	if scriptUsesShellName(script, "PR_BODY") {
		t.Errorf("scriptUsesShellName matched a name absent from the script")
	}
}

// TestScriptUsesShellName_ParameterExpansions pins that all bash
// parameter-expansion shapes referencing the name are detected — the
// regression flagged by codex on PR #514 where `${PR_BODY:-/safe}`
// slipped past the matcher because it only accepted the exact
// `${PR_BODY}` form.
func TestScriptUsesShellName_ParameterExpansions(t *testing.T) {
	cases := []struct {
		name   string
		script string
	}{
		{"plain", `echo "$PR_BODY"`},
		{"braced", `echo "${PR_BODY}"`},
		{"default if unset", `echo "${PR_BODY:-/safe}"`},
		{"alt if set", `echo "${PR_BODY:+set}"`},
		{"assign default", `echo "${PR_BODY:=/safe}"`},
		{"error if unset", `echo "${PR_BODY:?missing}"`},
		{"substring", `echo "${PR_BODY:0:5}"`},
		{"length", `echo "${#PR_BODY}"`},
		{"strip prefix", `echo "${PR_BODY#pre}"`},
		{"strip longest prefix", `echo "${PR_BODY##pre}"`},
		{"strip suffix", `echo "${PR_BODY%suf}"`},
		{"strip longest suffix", `echo "${PR_BODY%%suf}"`},
		{"substitution", `echo "${PR_BODY/foo/bar}"`},
		{"global substitution", `echo "${PR_BODY//foo/bar}"`},
		{"uppercase", `echo "${PR_BODY^^}"`},
		{"lowercase", `echo "${PR_BODY,,}"`},
		{"indirect", `echo "${!PR_BODY}"`},
		{"assignment", `PR_BODY=/safe`},
		{"export assignment", `export PR_BODY=/safe`},
		{"local assignment", `f() { local PR_BODY=/safe; }`},
		{"read", `read PR_BODY`}, // bash assigns via read
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !scriptUsesShellName(tc.script, "PR_BODY") {
				t.Errorf("scriptUsesShellName missed PR_BODY in %q", tc.script)
			}
		})
	}

	// Negative: PR_BODY not used at all
	if scriptUsesShellName(`echo "$OTHER"`, "PR_BODY") {
		t.Errorf("scriptUsesShellName false-positive on absent name")
	}
}

// TestReplaceShellEnvVarRef_BracedReplacementIsLiteral pins the contract
// that `replacement` is treated as a literal string (no `$name` submatch
// expansion), so `$(realpath "$PR_BODY")` survives intact.
func TestReplaceShellEnvVarRef_BracedReplacementIsLiteral(t *testing.T) {
	got := replaceShellEnvVarRef(`echo "${PR_BODY}/bin"`, "PR_BODY", `$(realpath "$PR_BODY")`)
	want := `echo "$(realpath "$PR_BODY")/bin"`
	if got != want {
		t.Errorf("braced ref: got %q, want %q", got, want)
	}
	got = replaceShellEnvVarRef(`echo "$PR_BODY/bin"`, "PR_BODY", `$(realpath "$PR_BODY")`)
	want = `echo "$(realpath "$PR_BODY")/bin"`
	if got != want {
		t.Errorf("plain ref: got %q, want %q", got, want)
	}
}

func TestEnvPathInjectionCritical_ErrorMessage(t *testing.T) {
	t.Parallel()
	rule := EnvPathInjectionCriticalRule()

	// Create workflow with privileged trigger
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request_target"},
			},
		},
	}

	// Create job with vulnerable GITHUB_PATH write
	job := &ast.Job{
		Steps: []*ast.Step{
			{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
		},
	}

	// Visit workflow and job
	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)

	errors := rule.Errors()
	if len(errors) == 0 {
		t.Fatal("expected errors but got none")
	}

	// Check error message contains key information
	errMsg := errors[0].Description
	if !strings.Contains(errMsg, "PATH injection (critical)") {
		t.Errorf("error message should contain 'PATH injection (critical)', got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "github.event.pull_request.body") {
		t.Errorf("error message should contain the untrusted path, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "GITHUB_PATH") {
		t.Errorf("error message should mention GITHUB_PATH, got: %s", errMsg)
	}
}

func envPathInjectionCriticalWorkflowWithRun(run string) (*ast.Workflow, *ast.Job, *ast.Step) {
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request_target"},
			},
		},
	}
	step := &ast.Step{
		Exec: &ast.ExecRun{
			Run: &ast.String{
				Value: run,
				Pos:   &ast.Position{Line: 1, Col: 1},
			},
		},
	}
	job := &ast.Job{Steps: []*ast.Step{step}}
	return workflow, job, step
}
