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
		// Bare declarations (no =VALUE) bind the name and on Linux runners
		// shadow the env var for the rest of the scope, so the autofix
		// must treat them as a collision. mvdan.cc/sh parses these as
		// DeclClause -> Assign(Name=NAME, Value=nil); the matcher must
		// catch them. Reported by codex on PR #514.
		{"bare local in function", `f() { local PR_BODY; }`},
		{"bare declare in function", `f() { declare PR_BODY; }`},
		{"bare typeset in function", `f() { typeset PR_BODY; }`},
		{"bare export", `export PR_BODY`},
		{"bare readonly", `readonly PR_BODY`},
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

// TestEnvPathInjectionCritical_FixStep_AvoidsBareLocalDeclaration covers
// the codex-flagged regression on PR #514: a function-scoped bare
// declaration like `local PR_BODY` (no =value) binds the name and
// shadows any env var with the same name inside the function, so the
// autofix must not pick the bare base name. `mvdan.cc/sh` parses the
// declaration as DeclClause -> Assign(Name=NAME, Value=nil), which the
// AST walker treats as a usage; this test pins that integration path.
func TestEnvPathInjectionCritical_FixStep_AvoidsBareLocalDeclaration(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`f() {
  local PR_BODY
  echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"
}
f`,
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

	if step.Env != nil {
		if added := step.Env.Vars["pr_body"]; added != nil {
			t.Fatalf("autofix wrongly added PR_BODY env (would be shadowed by `local PR_BODY`): %+v", added.Value)
		}
		if step.Env.Vars["pr_body_2"] == nil {
			t.Fatalf("expected suffixed PR_BODY_2 env var, got %#v", step.Env.Vars)
		}
	}

	want := `f() {
  local PR_BODY
  echo "$(realpath "$PR_BODY_2")" >> "$GITHUB_PATH"
}
f`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestEnvPathInjectionCritical_FixStep_AvoidsJobEnvCollision asserts that a
// job-level env entry with a colliding name forces the autofix to suffix
// instead of adding a step-level entry that would shadow the inherited
// value for the remainder of the step. This is the regression flagged by
// codex on PR #514: the previous `_PATH` suffix made this collision
// improbable, but with the bare `PR_BODY` name it is now likely.
func TestEnvPathInjectionCritical_FixStep_AvoidsJobEnvCollision(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
	)
	// Job-level env has PR_BODY with a different value — the autofix
	// must not shadow it at step level.
	job.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "PR_BODY"},
			Value: &ast.String{Value: "/safe/from-job"},
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

	if step.Env != nil {
		if added := step.Env.Vars["pr_body"]; added != nil {
			t.Fatalf("autofix wrongly added a step-level PR_BODY env var (shadows job env): %+v", added.Value)
		}
		added := step.Env.Vars["pr_body_2"]
		if added == nil || added.Value == nil {
			t.Fatalf("expected suffixed PR_BODY_2 env var, got %#v", step.Env.Vars)
		}
		if got := added.Value.Value; got != "${{ github.event.pull_request.body }}" {
			t.Errorf("PR_BODY_2 value = %q, want pull request body expression", got)
		}
	}

	want := `echo "$(realpath "$PR_BODY_2")" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestEnvPathInjectionCritical_FixStep_AvoidsWorkflowEnvCollision is the
// workflow-level analog of the job-level test above: workflow.env vars
// are inherited by every job's every step, so they must also block the
// chosen autofix env var name.
func TestEnvPathInjectionCritical_FixStep_AvoidsWorkflowEnvCollision(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
	)
	workflow.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "PR_BODY"},
			Value: &ast.String{Value: "/safe/from-workflow"},
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

	if step.Env != nil {
		if added := step.Env.Vars["pr_body"]; added != nil {
			t.Fatalf("autofix wrongly added a step-level PR_BODY env var (shadows workflow env): %+v", added.Value)
		}
		if step.Env.Vars["pr_body_2"] == nil {
			t.Fatalf("expected suffixed PR_BODY_2 env var, got %#v", step.Env.Vars)
		}
	}

	want := `echo "$(realpath "$PR_BODY_2")" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestEnvPathInjectionCritical_FixStep_ReusesInheritedEnvWhenMatching asserts
// that an inherited env var with the SAME expression value is reused
// (no new step-level entry is added) instead of being suffixed. This
// keeps the autofix idempotent and avoids needless step-level duplication.
func TestEnvPathInjectionCritical_FixStep_ReusesInheritedEnvWhenMatching(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
	)
	job.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "PR_BODY"},
			Value: &ast.String{Value: "${{ github.event.pull_request.body }}"},
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

	if step.Env != nil && step.Env.Vars["pr_body"] != nil {
		t.Errorf("autofix added redundant step-level PR_BODY when job env matches: %+v", step.Env.Vars["pr_body"].Value)
	}
	want := `echo "$(realpath "$PR_BODY")" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestEnvPathInjectionCritical_FixStep_PreservesInheritedEnvCasing asserts
// that when a job- or workflow-level env defines the same expression
// under different casing (e.g., lowercase `pr_body`), the autofix reuses
// the inherited variable's ACTUAL casing rather than emitting a
// case-mismatched `$PR_BODY`. Linux runners use case-sensitive shell
// env names, so an uppercase rewrite against a lowercase env entry
// would resolve to an unset variable. Flagged by codex on PR #514.
func TestEnvPathInjectionCritical_FixStep_PreservesInheritedEnvCasing(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
	)
	// Inherited workflow env uses lowercase casing but the same
	// expression value. The autofix must reuse `pr_body`, not `PR_BODY`.
	workflow.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "pr_body"},
			Value: &ast.String{Value: "${{ github.event.pull_request.body }}"},
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

	// No new step-level env should be added because the inherited
	// (lowercase) variable already holds the right expression.
	if step.Env != nil && step.Env.Vars["pr_body"] != nil {
		t.Errorf("autofix added redundant step-level pr_body: %+v", step.Env.Vars["pr_body"].Value)
	}
	want := `echo "$(realpath "$pr_body")" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q (must preserve inherited casing for case-sensitive Linux shell)", got, want)
	}
}

// TestEnvPathInjectionCritical_FixStep_WrapsAllRefsOnSingleLine asserts that
// when a single GITHUB_PATH line contains BOTH the untrusted `${{ expr }}`
// AND a separate `$NAME` reference to the chosen env var (e.g., via an
// inherited env block that already binds the same expression), every
// reference on the line gets wrapped with realpath — not just the first.
// Regression flagged by codex on PR #514: the previous `strings.Contains`
// guard short-circuited the entire line once the expression-derived
// occurrence was wrapped, leaving the user's other `$PR_BODY` token
// unwrapped and still expanding to the attacker body.
func TestEnvPathInjectionCritical_FixStep_WrapsAllRefsOnSingleLine(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`printf '%s\n%s\n' "${{ github.event.pull_request.body }}" "$PR_BODY" >> "$GITHUB_PATH"`,
	)
	// Inherited job env binds the same expression to PR_BODY, so
	// envVarNameForExpression reuses PR_BODY (no suffix). With reuse,
	// the script's `$PR_BODY` reference reads the inherited body too,
	// and the second pass must wrap it just like the lifted occurrence.
	job.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "PR_BODY"},
			Value: &ast.String{Value: "${{ github.event.pull_request.body }}"},
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

	want := `printf '%s\n%s\n' "$(realpath "$PR_BODY")" "$(realpath "$PR_BODY")" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestEnvPathInjectionCritical_FixStep_ReusesWhitespaceVariantInheritedEnv
// pins the codex-flagged regression on PR #514: inherited env values that
// contain the same GitHub expression with different whitespace must be reused
// so existing `$NAME` GITHUB_PATH writes are wrapped instead of left raw.
func TestEnvPathInjectionCritical_FixStep_ReusesWhitespaceVariantInheritedEnv(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`echo "$PR_BODY" >> "$GITHUB_PATH"
echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
	)
	job.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "PR_BODY"},
			Value: &ast.String{Value: "${{github.event.pull_request.body}}"},
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

	if step.Env != nil && step.Env.Vars["pr_body_2"] != nil {
		t.Errorf("autofix wrongly suffixed equivalent inherited expression: %+v", step.Env.Vars["pr_body_2"].Value)
	}
	want := `echo "$(realpath "$PR_BODY")" >> "$GITHUB_PATH"
echo "$(realpath "$PR_BODY")" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestEnvPathInjectionCritical_FixStep_ReadPromptArgDoesNotShadowInheritedEnv
// pins the codex-flagged regression on PR #514: `read -p PR_BODY ANSWER`
// uses PR_BODY as the prompt argument, not as a variable name. It must not
// force suffixing when earlier PATH writes still read the inherited PR_BODY.
func TestEnvPathInjectionCritical_FixStep_ReadPromptArgDoesNotShadowInheritedEnv(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`echo "$PR_BODY" >> "$GITHUB_PATH"
read -p PR_BODY ANSWER
echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
	)
	job.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "PR_BODY"},
			Value: &ast.String{Value: "${{ github.event.pull_request.body }}"},
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

	if step.Env != nil && step.Env.Vars["pr_body_2"] != nil {
		t.Errorf("autofix wrongly suffixed read prompt argument: %+v", step.Env.Vars["pr_body_2"].Value)
	}
	want := `echo "$(realpath "$PR_BODY")" >> "$GITHUB_PATH"
read -p PR_BODY ANSWER
echo "$(realpath "$PR_BODY")" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestEnvPathInjectionCritical_FixStep_MapfileDelimiterDoesNotShadowInheritedEnv
// pins the codex-flagged regression on PR #514: `mapfile -d PR_BODY ARR`
// uses PR_BODY as the delimiter argument, not as the array variable name.
func TestEnvPathInjectionCritical_FixStep_MapfileDelimiterDoesNotShadowInheritedEnv(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`echo "$PR_BODY" >> "$GITHUB_PATH"
mapfile -d PR_BODY ARR
echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
	)
	job.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "PR_BODY"},
			Value: &ast.String{Value: "${{ github.event.pull_request.body }}"},
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

	if step.Env != nil && step.Env.Vars["pr_body_2"] != nil {
		t.Errorf("autofix wrongly suffixed mapfile delimiter argument: %+v", step.Env.Vars["pr_body_2"].Value)
	}
	want := `echo "$(realpath "$PR_BODY")" >> "$GITHUB_PATH"
mapfile -d PR_BODY ARR
echo "$(realpath "$PR_BODY")" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestEnvPathInjectionCritical_FixStep_WrapsParameterExpansionOnGitHubPath
// is the end-to-end analog of WrapsAllExpansionShapes: when the chosen
// helper name is reused from inherited env, a GITHUB_PATH line that mixes
// `${{ expr }}` with a parameter-expansion form like `${PR_BODY:-/safe}`
// must have BOTH references wrapped. Otherwise the expansion expands at
// runtime to the attacker body (PR_BODY now holds it) and is written
// raw to GITHUB_PATH. Regression flagged by codex on PR #514.
func TestEnvPathInjectionCritical_FixStep_WrapsParameterExpansionOnGitHubPath(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`printf '%s\n%s\n' "${{ github.event.pull_request.body }}" "${PR_BODY:-/safe}" >> "$GITHUB_PATH"`,
	)
	// Inherited job env binds the same expression so envVarNameForExpression
	// reuses PR_BODY (no suffix). The parameter expansion on the same line
	// reads that env var and is just as dangerous as the bare reference.
	job.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "PR_BODY"},
			Value: &ast.String{Value: "${{ github.event.pull_request.body }}"},
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

	want := `printf '%s\n%s\n' "$(realpath "$PR_BODY")" "$(realpath "${PR_BODY:-/safe}")" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestEnvPathInjectionCritical_FixStep_AssignmentAfterPathWrites pins
// the codex-flagged ordering bug on PR #514: when the inherited env
// declares the same expression and the script assigns the same name
// AFTER all `$GITHUB_PATH` writes (so the writes still read the
// inherited untrusted value), the autofix must REUSE the inherited
// name so the second pass can wrap the earlier `$NAME` references.
// A naive "any assignment forces a suffix" check (the previous
// scriptAssignsShellName behavior) would have suffixed to PR_BODY_2
// and left the earlier raw `$PR_BODY` PATH entry unfixed.
func TestEnvPathInjectionCritical_FixStep_AssignmentAfterPathWrites(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`echo "$PR_BODY" >> "$GITHUB_PATH"
echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"
PR_BODY=/safe`,
	)
	job.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "PR_BODY"},
			Value: &ast.String{Value: "${{ github.event.pull_request.body }}"},
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

	// No suffix: the assignment is after the PATH writes, so reusing
	// PR_BODY is safe. Both PATH-write lines should be wrapped.
	if step.Env != nil && step.Env.Vars["pr_body_2"] != nil {
		t.Errorf("autofix wrongly suffixed when assignment is after PATH writes: %+v", step.Env.Vars["pr_body_2"].Value)
	}
	want := `echo "$(realpath "$PR_BODY")" >> "$GITHUB_PATH"
echo "$(realpath "$PR_BODY")" >> "$GITHUB_PATH"
PR_BODY=/safe`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestEnvPathInjectionCritical_FixStep_MixedInheritedWritesAroundShadow
// pins the order-aware inherited-env case where a matching inherited
// PR_BODY is still tainted before a script assignment, but shadowed after it.
// The autofix must suffix expression rewrites after the assignment while
// still wrapping earlier `$PR_BODY` GITHUB_PATH writes that read the inherited
// value. Otherwise suffixing leaves the earlier PATH write vulnerable.
func TestEnvPathInjectionCritical_FixStep_MixedInheritedWritesAroundShadow(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`echo "$PR_BODY" >> "$GITHUB_PATH"
PR_BODY=/safe
echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
	)
	job.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "PR_BODY"},
			Value: &ast.String{Value: "${{ github.event.pull_request.body }}"},
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

	added := step.Env.Vars["pr_body_2"]
	if added == nil || added.Value == nil {
		t.Fatalf("expected suffixed PR_BODY_2 env var, got %#v", step.Env.Vars)
	}
	if got := added.Value.Value; got != "${{ github.event.pull_request.body }}" {
		t.Errorf("PR_BODY_2 value = %q, want pull request body expression", got)
	}

	want := `echo "$(realpath "$PR_BODY")" >> "$GITHUB_PATH"
PR_BODY=/safe
echo "$(realpath "$PR_BODY_2")" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestEnvPathInjectionCritical_FixStep_MixedInheritedWritesAroundShadowSameLine
// covers the same order-aware inherited-env case when the pre-shadow PATH
// write, shadowing assignment, and post-shadow PATH write share one physical
// shell line. Line-level ordering is not precise enough here.
func TestEnvPathInjectionCritical_FixStep_MixedInheritedWritesAroundShadowSameLine(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`echo "$PR_BODY" >> "$GITHUB_PATH"; PR_BODY=/safe; echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
	)
	job.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "PR_BODY"},
			Value: &ast.String{Value: "${{ github.event.pull_request.body }}"},
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

	added := step.Env.Vars["pr_body_2"]
	if added == nil || added.Value == nil {
		t.Fatalf("expected suffixed PR_BODY_2 env var, got %#v", step.Env.Vars)
	}

	want := `echo "$(realpath "$PR_BODY")" >> "$GITHUB_PATH"; PR_BODY=/safe; echo "$(realpath "$PR_BODY_2")" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestEnvPathInjectionCritical_FixStep_MixedStepEnvWritesAroundShadow
// mirrors the inherited-env shadow case for step-level env vars. A matching
// step env PR_BODY is tainted before a script assignment, but shadowed after
// it, so expression rewrites after the assignment need a suffixed helper while
// earlier `$PR_BODY` PATH writes still need wrapping.
func TestEnvPathInjectionCritical_FixStep_MixedStepEnvWritesAroundShadow(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`echo "$PR_BODY" >> "$GITHUB_PATH"; PR_BODY=/safe; echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
	)
	step.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "PR_BODY"},
			Value: &ast.String{Value: "${{ github.event.pull_request.body }}"},
		},
	}}

	envPathRule := EnvPathInjectionCriticalRule()

	if err := envPathRule.VisitWorkflowPre(workflow); err != nil {
		t.Fatalf("envpath VisitWorkflowPre() error = %v", err)
	}
	exprs := envPathRule.extractAndParseExpressions(step.Exec.(*ast.ExecRun).Run)
	if len(exprs) != 1 {
		t.Fatalf("expected one parsed expression, got %d", len(exprs))
	}
	envPathRule.stepsWithUntrusted = []*stepWithEnvPathInjection{
		{
			step: step,
			job:  job,
			untrustedExprs: []envPathUntrustedExprInfo{
				{
					expr:  exprs[0],
					paths: []string{"github.event.pull_request.body"},
					line:  step.Exec.(*ast.ExecRun).Run.Value,
				},
			},
		},
	}
	if err := envPathRule.FixStep(step); err != nil {
		t.Fatalf("envpath FixStep() error = %v", err)
	}

	if got := step.Env.Vars["pr_body"].Value.Value; got != "${{ github.event.pull_request.body }}" {
		t.Fatalf("existing PR_BODY step env was overwritten: %q", got)
	}
	added := step.Env.Vars["pr_body_2"]
	if added == nil || added.Value == nil {
		t.Fatalf("expected suffixed PR_BODY_2 env var, got %#v", step.Env.Vars)
	}
	if got := added.Value.Value; got != "${{ github.event.pull_request.body }}" {
		t.Errorf("PR_BODY_2 value = %q, want pull request body expression", got)
	}

	want := `echo "$(realpath "$PR_BODY")" >> "$GITHUB_PATH"; PR_BODY=/safe; echo "$(realpath "$PR_BODY_2")" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestEnvPathInjectionCritical_FixStep_IgnoresUnrelatedExpressionAfterShadow
// pins the codex-flagged regression on PR #514: inherited env reuse must
// consider only the expression being rewritten. A later unrelated GitHub
// expression after `PR_BODY=/safe` must not force suffixing for an earlier
// PATH write that still reads the inherited PR_BODY value.
func TestEnvPathInjectionCritical_FixStep_IgnoresUnrelatedExpressionAfterShadow(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`printf '%s\n%s\n' "$PR_BODY" "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"
PR_BODY=/safe
echo "${{ matrix.path }}"`,
	)
	job.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "PR_BODY"},
			Value: &ast.String{Value: "${{ github.event.pull_request.body }}"},
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

	if step.Env != nil && step.Env.Vars["pr_body_2"] != nil {
		t.Errorf("autofix wrongly suffixed due to unrelated later expression: %+v", step.Env.Vars["pr_body_2"].Value)
	}
	want := `printf '%s\n%s\n' "$(realpath "$PR_BODY")" "$(realpath "$PR_BODY")" >> "$GITHUB_PATH"
PR_BODY=/safe
echo "${{ matrix.path }}"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestAssignmentShadowsUntrustedExpression pins the ordering semantics
// directly: only assignments that PRECEDE the target `${{ ... }}`
// expression count as shadowing. Unrelated expressions elsewhere in the
// script must not force suffixing. Reported by codex on PR #514.
func TestAssignmentShadowsUntrustedExpression(t *testing.T) {
	cases := []struct {
		name    string
		script  string
		exprRaw string
		want    bool
	}{
		{
			name: "assignment before target expression",
			script: `PR_BODY=/safe
echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
			exprRaw: "github.event.pull_request.body",
			want:    true,
		},
		{
			name: "assignment after target expression",
			script: `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"
PR_BODY=/safe`,
			exprRaw: "github.event.pull_request.body",
			want:    false,
		},
		{
			name: "no assignment",
			script: `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"
echo "$PR_BODY"`,
			exprRaw: "github.event.pull_request.body",
			want:    false,
		},
		{
			name: "no expression",
			script: `PR_BODY=/safe
echo "$PR_BODY"`,
			exprRaw: "github.event.pull_request.body",
			want:    false,
		},
		{
			name: "target expression after assignment",
			script: `echo "${{ first.expr }}"
PR_BODY=/safe
echo "${{ second.expr }}" >> "$GITHUB_PATH"`,
			exprRaw: "second.expr",
			want:    true,
		},
		{
			name: "only unrelated expression after assignment",
			script: `echo "${{ github.event.pull_request.body }}"
PR_BODY=/safe
echo "${{ matrix.path }}"`,
			exprRaw: "github.event.pull_request.body",
			want:    false,
		},
		{
			name: "same expression after assignment outside path write",
			script: `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"
PR_BODY=/safe
echo "${{ github.event.pull_request.body }}"`,
			exprRaw: "github.event.pull_request.body",
			want:    false,
		},
		{
			name: "read builtin before expression",
			script: `read PR_BODY
echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
			exprRaw: "github.event.pull_request.body",
			want:    true,
		},
		{
			name: "read builtin after expression",
			script: `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"
read PR_BODY`,
			exprRaw: "github.event.pull_request.body",
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := assignmentShadowsUntrustedExpression(tc.script, "PR_BODY", tc.exprRaw); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestScriptAssignsShellName pins that the inherited-env reuse gate
// distinguishes assignment from reference. References must NOT block
// reuse (they read the inherited value, which the autofix wants to
// wrap); only assignments shadow the inherited env at runtime and
// thus force a suffix. Reported by codex on PR #514.
func TestScriptAssignsShellName(t *testing.T) {
	assigns := []struct {
		name    string
		script  string
		varName string
	}{
		{"plain assignment", `PR_BODY=/safe`, ""},
		{"export assignment", `export PR_BODY=/safe`, ""},
		{"local assignment in fn", `f() { local PR_BODY=/safe; }`, ""},
		{"bare local in fn", `f() { local PR_BODY; }`, ""},
		{"bare declare in fn", `f() { declare PR_BODY; }`, ""},
		{"bare readonly", `readonly PR_BODY`, ""},
		{"read builtin", `read PR_BODY`, ""},
		{"read prompt then name", `read -p "prompt" PR_BODY`, ""},
		{"read combined prompt then name", `read -rp "prompt" PR_BODY`, ""},
		{"read array option", `read -a PR_BODY`, ""},
		{"read inline array option", `read -aPR_BODY`, ""},
		{"read default reply no options", `read`, "REPLY"},
		{"read default reply flag only", `read -r`, "REPLY"},
		{"read default reply", `read -p "prompt"`, "REPLY"},
		{"mapfile builtin", `mapfile PR_BODY`, ""},
		{"mapfile delimiter then array", `mapfile -d ":" PR_BODY`, ""},
		{"mapfile combined trim delimiter then array", `mapfile -td ":" PR_BODY`, ""},
		{"mapfile default array no options", `mapfile`, "MAPFILE"},
		{"mapfile default array flag only", `mapfile -t`, "MAPFILE"},
		{"mapfile default array", `mapfile -d ":"`, "MAPFILE"},
		{"readarray count then array", `readarray -n 1 PR_BODY`, ""},
		{"readarray default array no options", `readarray`, "MAPFILE"},
		{"readarray default array flag only", `readarray -t`, "MAPFILE"},
		{"readarray default array", `readarray -n 1`, "MAPFILE"},
	}
	for _, tc := range assigns {
		t.Run("assigns/"+tc.name, func(t *testing.T) {
			varName := tc.varName
			if varName == "" {
				varName = "PR_BODY"
			}
			if !scriptAssignsShellName(tc.script, varName) {
				t.Errorf("scriptAssignsShellName missed assignment to %s in %q", varName, tc.script)
			}
		})
	}

	referencesOnly := []struct {
		name    string
		script  string
		varName string
	}{
		{"plain ref", `echo "$PR_BODY"`, ""},
		{"braced ref", `echo "${PR_BODY}"`, ""},
		{"default if unset", `echo "${PR_BODY:-/safe}"`, ""},
		{"alt if set", `echo "${PR_BODY:+set}"`, ""},
		{"strip prefix", `echo "${PR_BODY#pre}"`, ""},
		{"uppercase", `echo "${PR_BODY^^}"`, ""},
		{"length", `echo "${#PR_BODY}"`, ""},
		{"indirect", `echo "${!PR_BODY}"`, ""},
		{"read prompt arg", `read -p PR_BODY ANSWER`, ""},
		{"read inline prompt arg", `read -pPR_BODY ANSWER`, ""},
		{"read combined prompt arg", `read -rp PR_BODY ANSWER`, ""},
		{"read fd arg", `read -u PR_BODY ANSWER`, ""},
		{"read array ignores trailing name", `read -a ARR PR_BODY`, ""},
		{"read inline array ignores trailing name", `read -aARR PR_BODY`, ""},
		{"read explicit name avoids reply", `read PR_BODY`, "REPLY"},
		{"mapfile delimiter arg", `mapfile -d PR_BODY ARR`, ""},
		{"mapfile inline delimiter arg", `mapfile -dPR_BODY ARR`, ""},
		{"mapfile combined trim delimiter arg", `mapfile -td PR_BODY ARR`, ""},
		{"mapfile count arg", `mapfile -n PR_BODY ARR`, ""},
		{"mapfile origin arg", `mapfile -O PR_BODY ARR`, ""},
		{"mapfile skip arg", `mapfile -s PR_BODY ARR`, ""},
		{"mapfile fd arg", `mapfile -u PR_BODY ARR`, ""},
		{"mapfile callback arg", `mapfile -C PR_BODY ARR`, ""},
		{"mapfile quantum arg", `mapfile -c PR_BODY ARR`, ""},
		{"mapfile ignores extra operand", `mapfile ARR PR_BODY`, ""},
		{"mapfile double dash ignores extra operand", `mapfile -- ARR PR_BODY`, ""},
		{"mapfile explicit array avoids default", `mapfile ARR`, "MAPFILE"},
		{"readarray delimiter arg", `readarray -d PR_BODY ARR`, ""},
		{"readarray ignores extra operand", `readarray ARR PR_BODY`, ""},
		{"readarray explicit array avoids default", `readarray ARR`, "MAPFILE"},
	}
	for _, tc := range referencesOnly {
		t.Run("references/"+tc.name, func(t *testing.T) {
			varName := tc.varName
			if varName == "" {
				varName = "PR_BODY"
			}
			if scriptAssignsShellName(tc.script, varName) {
				t.Errorf("scriptAssignsShellName false-positive for %s on %q", varName, tc.script)
			}
		})
	}
}

// TestEnvPathInjectionCritical_FixStep_ScriptShadowsInheritedEnv pins
// the codex-flagged regression on PR #514: when a job- or workflow-level
// env defines the same expression under the helper name AND the script
// also assigns the same shell name locally, the autofix must suffix
// rather than reuse — otherwise the rewritten `$(realpath "$PR_BODY")`
// reads the script's local `PR_BODY=/safe` (which shadows the inherited
// env at runtime) and silently changes the user's intent from
// "write the body" to "write /safe".
func TestEnvPathInjectionCritical_FixStep_ScriptShadowsInheritedEnv(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`PR_BODY=/safe
echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
	)
	// Job env declares the same expression under PR_BODY. The autofix
	// would normally reuse this name, but the script's `PR_BODY=/safe`
	// shadows the inherited value at runtime, so reuse would mis-resolve.
	job.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "PR_BODY"},
			Value: &ast.String{Value: "${{ github.event.pull_request.body }}"},
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

	// Step env must add a SUFFIXED entry (PR_BODY_2) so the rewrite
	// reads the autofix-introduced env var, not the script's shadowed
	// PR_BODY. The inherited job env is left intact.
	if step.Env != nil {
		if added := step.Env.Vars["pr_body"]; added != nil {
			t.Fatalf("autofix wrongly created step-level PR_BODY (would be shadowed by script): %+v", added.Value)
		}
		added := step.Env.Vars["pr_body_2"]
		if added == nil || added.Value == nil {
			t.Fatalf("expected suffixed PR_BODY_2 env var, got %#v", step.Env.Vars)
		}
		if got := added.Value.Value; got != "${{ github.event.pull_request.body }}" {
			t.Errorf("PR_BODY_2 value = %q, want pull request body expression", got)
		}
	}

	want := `PR_BODY=/safe
echo "$(realpath "$PR_BODY_2")" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestEnvPathInjectionCritical_FixStep_ScriptShadowsLowercaseInheritedEnv
// pins that the inherited-env reuse path's shadowing check uses the
// inherited entry's ACTUAL casing rather than the upper-case candidate.
// When workflow env declares `pr_body: ${{ expr }}` (lowercase) and the
// script assigns `pr_body=/safe`, checking shadow against the upper-case
// `PR_BODY` candidate misses the lowercase assignment (bash names are
// case-sensitive), reuse fires, and the rewrite resolves the shadowed
// `/safe` value instead of the inherited untrusted expression.
// Codex PR #514 regression.
func TestEnvPathInjectionCritical_FixStep_ScriptShadowsLowercaseInheritedEnv(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`pr_body=/safe
echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
	)
	workflow.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "pr_body"},
			Value: &ast.String{Value: "${{ github.event.pull_request.body }}"},
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

	if step.Env != nil {
		if added := step.Env.Vars["pr_body"]; added != nil {
			t.Fatalf("autofix wrongly created step-level pr_body (would be shadowed by script): %+v", added.Value)
		}
		added := step.Env.Vars["pr_body_2"]
		if added == nil || added.Value == nil {
			t.Fatalf("expected suffixed PR_BODY_2 env var, got %#v", step.Env.Vars)
		}
	}

	want := `pr_body=/safe
echo "$(realpath "$PR_BODY_2")" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestEnvPathInjectionCritical_FixStep_LeftoverGitHubExpressionInLine
// is the end-to-end regression for the codex sanitize-before-parse
// concern: an inherited-env reuse path where the GITHUB_PATH line
// contains the tainted `${{ ... }}`, a parameter expansion of the
// reused name, AND an unrelated `${{ ... }}`. The unrelated expression
// must NOT defeat the bash parse used for the second wrap pass —
// without sanitize-before-parse the line would fall through to the
// regex fallback and leave the expansion form unwrapped.
func TestEnvPathInjectionCritical_FixStep_LeftoverGitHubExpressionInLine(t *testing.T) {
	workflow, job, step := envPathInjectionCriticalWorkflowWithRun(
		`printf '%s\n%s\n%s\n' "${{ github.event.pull_request.body }}" "${PR_BODY:-/safe}" "${{ matrix.path }}" >> "$GITHUB_PATH"`,
	)
	job.Env = &ast.Env{Vars: map[string]*ast.EnvVar{
		"pr_body": {
			Name:  &ast.String{Value: "PR_BODY"},
			Value: &ast.String{Value: "${{ github.event.pull_request.body }}"},
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

	want := `printf '%s\n%s\n%s\n' "$(realpath "$PR_BODY")" "$(realpath "${PR_BODY:-/safe}")" "${{ matrix.path }}" >> "$GITHUB_PATH"`
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != want {
		t.Errorf("fixed run script = %q, want %q", got, want)
	}
}

// TestReplaceShellEnvVarRef_WrapsAllExpansionShapes asserts that every
// bash parameter-expansion form referencing the env var name gets wrapped
// with `$(realpath "<source>")`, preserving the original expansion shape
// so the runtime semantics (default / case op / substitution / etc.)
// stay intact. The previous regex only matched `$NAME` and exact
// `${NAME}`, leaving `${NAME:-/safe}` and friends unwrapped — the
// regression flagged by codex on PR #514.
func TestReplaceShellEnvVarRef_WrapsAllExpansionShapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", `echo "$PR_BODY/bin"`, `echo "$(realpath "$PR_BODY")/bin"`},
		{"braced", `echo "${PR_BODY}/bin"`, `echo "$(realpath "${PR_BODY}")/bin"`},
		{"default if unset", `echo "${PR_BODY:-/safe}"`, `echo "$(realpath "${PR_BODY:-/safe}")"`},
		{"alt if set", `echo "${PR_BODY:+set}"`, `echo "$(realpath "${PR_BODY:+set}")"`},
		{"error if unset", `echo "${PR_BODY:?missing}"`, `echo "$(realpath "${PR_BODY:?missing}")"`},
		{"strip prefix", `echo "${PR_BODY#pre}"`, `echo "$(realpath "${PR_BODY#pre}")"`},
		{"strip longest prefix", `echo "${PR_BODY##pre}"`, `echo "$(realpath "${PR_BODY##pre}")"`},
		{"strip suffix", `echo "${PR_BODY%suf}"`, `echo "$(realpath "${PR_BODY%suf}")"`},
		{"substitution", `echo "${PR_BODY/foo/bar}"`, `echo "$(realpath "${PR_BODY/foo/bar}")"`},
		{"uppercase", `echo "${PR_BODY^^}"`, `echo "$(realpath "${PR_BODY^^}")"`},
		{"lowercase", `echo "${PR_BODY,,}"`, `echo "$(realpath "${PR_BODY,,}")"`},
		{"indirect", `echo "${!PR_BODY}"`, `echo "$(realpath "${!PR_BODY}")"`},
		{"length", `echo "${#PR_BODY}"`, `echo "$(realpath "${#PR_BODY}")"`},
		{"multiple on one line",
			`printf '%s\n%s\n' "$PR_BODY" "${PR_BODY:-/safe}"`,
			`printf '%s\n%s\n' "$(realpath "$PR_BODY")" "$(realpath "${PR_BODY:-/safe}")"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := replaceShellEnvVarRef(tc.in, "PR_BODY")
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestReplaceShellEnvVarRef_HandlesLineWithLeftoverGitHubExpression
// asserts that a line still containing a non-tainted `${{ ... }}`
// (e.g., `${{ matrix.path }}`) does NOT defeat parsing and therefore
// does not silently fall back to the regex-only path that misses
// parameter expansions. Regression flagged by codex on PR #514: a
// line like
// `printf '%s\n%s\n%s\n' "$PR_BODY" "${PR_BODY:-/safe}" "${{ matrix.path }}"`
// previously failed the bash parse (because `${{ ... }}` is not valid
// bash), tripped the regex fallback, and left `${PR_BODY:-/safe}`
// unwrapped.
func TestReplaceShellEnvVarRef_HandlesLineWithLeftoverGitHubExpression(t *testing.T) {
	in := `printf '%s\n%s\n%s\n' "$PR_BODY" "${PR_BODY:-/safe}" "${{ matrix.path }}"`
	want := `printf '%s\n%s\n%s\n' "$(realpath "$PR_BODY")" "$(realpath "${PR_BODY:-/safe}")" "${{ matrix.path }}"`
	got := replaceShellEnvVarRef(in, "PR_BODY")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// The untouched `${{ matrix.path }}` must round-trip exactly —
	// sanitize/desanitize is byte-for-byte for unrelated expressions.
	if !strings.Contains(got, `"${{ matrix.path }}"`) {
		t.Errorf("output dropped or mangled `${{ matrix.path }}`: %q", got)
	}
}

// TestReplaceShellEnvVarRef_LeavesUnrelatedNames pins that references
// to OTHER variable names on the line are not rewritten when the
// caller asks for a specific envVarName.
func TestReplaceShellEnvVarRef_LeavesUnrelatedNames(t *testing.T) {
	got := replaceShellEnvVarRef(`echo "$PR_BODY $OTHER"`, "PR_BODY")
	want := `echo "$(realpath "$PR_BODY") $OTHER"`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestReplaceShellEnvVarRef_IgnoresSingleQuotedLiteral confirms that
// `$PR_BODY` inside single quotes is left alone — bash does not expand
// it, so wrapping would be incorrect.
func TestReplaceShellEnvVarRef_IgnoresSingleQuotedLiteral(t *testing.T) {
	in := `echo 'has $PR_BODY here'`
	got := replaceShellEnvVarRef(in, "PR_BODY")
	if got != in {
		t.Errorf("got %q, want unchanged %q", got, in)
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
