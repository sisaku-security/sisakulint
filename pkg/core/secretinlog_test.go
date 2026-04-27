package core

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/shell"
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

func TestSecretInLog_FindEchoLeaks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		script   string
		tainted  map[string]shell.Entry
		wantHits []struct {
			varName string
			command string
		}
	}{
		{
			name: "echo of tainted var",
			script: `echo "Key: $PRIVATE_KEY"
`,
			tainted: map[string]shell.Entry{"PRIVATE_KEY": {Sources: []string{"shellvar:GCP_KEY"}, Offset: -1}},
			wantHits: []struct {
				varName string
				command string
			}{{"PRIVATE_KEY", "echo"}},
		},
		{
			name: "printf of tainted var",
			script: `printf "%s\n" "$TOKEN"
`,
			tainted: map[string]shell.Entry{"TOKEN": {Sources: []string{"secrets.API"}, Offset: -1}},
			wantHits: []struct {
				varName string
				command string
			}{{"TOKEN", "printf"}},
		},
		{
			name: "echo of untainted var",
			script: `echo "$MSG"
`,
			tainted:  map[string]shell.Entry{"TOKEN": {Sources: []string{"secrets.API"}, Offset: -1}},
			wantHits: nil,
		},
		{
			name: "add-mask suppresses echo",
			script: `echo "::add-mask::$TOKEN"
echo "Value: $TOKEN"
`,
			tainted:  map[string]shell.Entry{"TOKEN": {Sources: []string{"secrets.API"}, Offset: -1}},
			wantHits: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rule := NewSecretInLogRule()
			file := parseShellForTest(t, tc.script)
			runStr := &ast.String{Value: tc.script, Pos: &ast.Position{Line: 1, Col: 1}}
			// findEchoLeaks は scope-aware に *shell.ScopedTaint を受ける。
			// テスト用 seed (tc.tainted) を初期 taint として PropagateTaint で
			// スコープ付き taint set を構築する。
			scoped := shell.PropagateTaint(file, tc.tainted)
			got := rule.findEchoLeaks(file, scoped, tc.script, runStr)
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
		{
			// FP: echo が sink より後のアサインで taint される変数を参照している場合、
			// echo 実行時点では変数は空なので漏洩なし。order-aware taint で排除する。
			name:       "FP: echo before assignment is not a leak",
			envVars:    map[string]string{"SECRET_ENV": "${{ secrets.API_KEY }}"},
			runScript:  "echo \"$DERIVED\"\nDERIVED=$(echo \"$SECRET_ENV\" | jq -r .key)",
			wantErrors: 0,
		},
		{
			// FP: 直接の env var も、sink より後のアサインで taint が確定する派生変数は漏洩なし。
			name:       "FP: chained assignment after sink is not a leak",
			envVars:    map[string]string{"TOKEN": "${{ secrets.TOKEN }}"},
			runScript:  "echo \"$B\"\nA=\"$TOKEN\"\nB=\"$A\"",
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

// TestSecretInLog_FunctionLocalScope_DetectsLeak は関数本体内で local 宣言された
// 変数を echo すると leak として検出されることを検証する (#447 FN 修正)。
func TestSecretInLog_FunctionLocalScope_DetectsLeak(t *testing.T) {
	t.Parallel()

	rule := NewSecretInLogRule()

	envVars := map[string]*ast.EnvVar{
		"secret": {
			Name:  &ast.String{Value: "SECRET"},
			Value: &ast.String{Value: "${{ secrets.GH_TOKEN }}"},
		},
	}
	step := &ast.Step{
		Env: &ast.Env{Vars: envVars},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: `leak() {
  local SECRET_LOCAL="$SECRET"
  echo "$SECRET_LOCAL"
}
leak`, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}
	job := &ast.Job{Steps: []*ast.Step{step}}

	if err := rule.VisitJobPre(job); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	if got := len(rule.Errors()); got == 0 {
		t.Fatalf("expected leak detection for SECRET_LOCAL inside function body, got 0 errors")
	}
}

// TestSecretInLog_SubshellLocalAssignment_NotLeakedInParent は subshell 内の
// 上書きが親スコープの sink 検出に影響しないことを検証する (#447 FP/FN 防止)。
func TestSecretInLog_SubshellLocalAssignment_NotLeakedInParent(t *testing.T) {
	t.Parallel()

	rule := NewSecretInLogRule()

	envVars := map[string]*ast.EnvVar{
		"secret": {
			Name:  &ast.String{Value: "SECRET"},
			Value: &ast.String{Value: "${{ secrets.GH_TOKEN }}"},
		},
	}
	step := &ast.Step{
		Env: &ast.Env{Vars: envVars},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: `( SECRET="dummy" )
echo "$SECRET"`, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}
	job := &ast.Job{Steps: []*ast.Step{step}}

	if err := rule.VisitJobPre(job); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	if got := len(rule.Errors()); got == 0 {
		t.Fatalf("expected leak detection for parent SECRET (subshell override should not affect parent)")
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

func TestSecretInLog_HasAddMaskFor_BoundaryBug(t *testing.T) {
	t.Parallel()
	script := `echo "::add-mask::$TOKEN_EXTRA"
echo "$TOKEN"`
	if hasAddMaskFor(script, "TOKEN") {
		t.Error("hasAddMaskFor must not match TOKEN when only TOKEN_EXTRA is masked")
	}
	if !hasAddMaskFor(script, "TOKEN_EXTRA") {
		t.Error("hasAddMaskFor must match exact var TOKEN_EXTRA")
	}
}

func TestSecretInLog_CollectSecretEnvVars_MultipleSecrets(t *testing.T) {
	t.Parallel()
	env := &ast.Env{Vars: map[string]*ast.EnvVar{
		"combo": {
			Name:  &ast.String{Value: "COMBO"},
			Value: &ast.String{Value: "${{ secrets.A }}-${{ secrets.B }}"},
		},
	}}
	rule := NewSecretInLogRule()
	got := rule.collectSecretEnvVars(env)
	if got["COMBO"] != "secrets.A,secrets.B" {
		t.Errorf("expected both secrets in origin, got %q", got["COMBO"])
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

func TestSecretInLog_FixStep_SkipsWhenAlreadyMasked(t *testing.T) {
	t.Parallel()
	script := "PRIVATE_KEY=$(jq -r .p <<< \"$KEY\")\necho \"::add-mask::$PRIVATE_KEY\"\necho \"$PRIVATE_KEY\""
	step := &ast.Step{
		Exec: &ast.ExecRun{Run: &ast.String{Value: script, Pos: &ast.Position{Line: 1, Col: 1}}},
	}
	// leakOffset は 3 行目の `$PRIVATE_KEY` sink 位置を指す想定。
	// 2 行目の add-mask はこのオフセットより前にあるため skip されるべき。
	sinkIdx := strings.Index(script, "\necho \"$PRIVATE_KEY\"") + 1
	f := &secretInLogFixer{
		step:       step,
		varName:    "PRIVATE_KEY",
		origin:     "shellvar:KEY",
		leakOffset: sinkIdx,
		ruleName:   "secret-in-log",
	}
	if err := f.FixStep(step); err != nil {
		t.Fatalf("FixStep: %v", err)
	}
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != script {
		t.Errorf("FixStep should be a no-op when add-mask already present; script changed to %q", got)
	}
}

// B3/T1: 複数の tainted 変数が同一 step 内で同時に echo される場合、
// それぞれのアサイン直後に add-mask が正しく挿入され、hasAddMaskFor による二重挿入防止が機能することを検証する。
func TestSecretInLog_AutoFix_MultipleVarsSimultaneousLeak(t *testing.T) {
	t.Parallel()

	original := "A=$(echo \"$SECRET_A\" | base64 -d)\n" +
		"B=$(echo \"$SECRET_B\" | jq -r '.v')\n" +
		"echo \"a=$A b=$B\""

	step := &ast.Step{
		Env: &ast.Env{Vars: map[string]*ast.EnvVar{
			"secret_a": {
				Name:  &ast.String{Value: "SECRET_A"},
				Value: &ast.String{Value: "${{ secrets.A }}"},
			},
			"secret_b": {
				Name:  &ast.String{Value: "SECRET_B"},
				Value: &ast.String{Value: "${{ secrets.B }}"},
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

	if got := len(rule.Errors()); got != 2 {
		t.Fatalf("errors = %d, want 2. details=%v", got, rule.Errors())
	}

	for _, f := range rule.AutoFixers() {
		if err := f.Fix(); err != nil {
			t.Fatalf("Fix: %v", err)
		}
	}

	got := step.Exec.(*ast.ExecRun).Run.Value
	// A, B それぞれのアサイン直後に add-mask が入るはず。
	if !strings.Contains(got, "A=$(echo \"$SECRET_A\" | base64 -d)\necho \"::add-mask::$A\"") {
		t.Errorf("expected add-mask for $A placed after its assignment, got:\n%s", got)
	}
	if !strings.Contains(got, "B=$(echo \"$SECRET_B\" | jq -r '.v')\necho \"::add-mask::$B\"") {
		t.Errorf("expected add-mask for $B placed after its assignment, got:\n%s", got)
	}

	// Fix 適用後に再度走査し、二重挿入ループや残留 leak が無いことを確認する。
	postRule := NewSecretInLogRule()
	postStep := &ast.Step{
		Env:  step.Env,
		Exec: &ast.ExecRun{Run: &ast.String{Value: got, Pos: &ast.Position{Line: 1, Col: 1}}},
	}
	if err := postRule.VisitJobPre(&ast.Job{Steps: []*ast.Step{postStep}}); err != nil {
		t.Fatalf("post VisitJobPre: %v", err)
	}
	if n := len(postRule.Errors()); n != 0 {
		t.Errorf("after fix, expected 0 leaks remaining, got %d: %v", n, postRule.Errors())
	}
	// 変数 A と B の add-mask 行がちょうど 1 回ずつであることを確認（二重挿入ではない）。
	if c := strings.Count(got, "::add-mask::$A\""); c != 1 {
		t.Errorf("expected exactly 1 add-mask for $A, got %d", c)
	}
	if c := strings.Count(got, "::add-mask::$B\""); c != 1 {
		t.Errorf("expected exactly 1 add-mask for $B, got %d", c)
	}
}

// T2: printf のフォーマット文字列そのものに tainted 変数が入るケースを検出できるか検証。
func TestSecretInLog_Printf_FormatStringLeak(t *testing.T) {
	t.Parallel()

	// フォーマット文字列 ("$TOKEN") 内で tainted 変数が展開される。
	script := "printf \"$TOKEN\"\n"
	step := &ast.Step{
		Env: &ast.Env{Vars: map[string]*ast.EnvVar{
			"token": {
				Name:  &ast.String{Value: "TOKEN"},
				Value: &ast.String{Value: "${{ secrets.API }}"},
			},
		}},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: script, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}
	rule := NewSecretInLogRule()
	if err := rule.VisitJobPre(&ast.Job{Steps: []*ast.Step{step}}); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	if got := len(rule.Errors()); got != 1 {
		t.Errorf("printf with tainted format string should leak once, got %d: %v", got, rule.Errors())
	}
}

// T3: workflow / job / step の 3 階層 env で同じ変数名 TOKEN が異なる secret を指すケース。
// step env が最後に merge されるため、step env の origin で上書きされる仕様を確定化する。
func TestSecretInLog_ThreeLevelEnv_OverrideSameName(t *testing.T) {
	t.Parallel()

	script := "echo \"$TOKEN\""

	mkEnv := func(secretName string) *ast.Env {
		return &ast.Env{Vars: map[string]*ast.EnvVar{
			"token": {
				Name:  &ast.String{Value: "TOKEN"},
				Value: &ast.String{Value: "${{ secrets." + secretName + " }}"},
			},
		}}
	}

	step := &ast.Step{
		Env: mkEnv("STEP_TOKEN"),
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: script, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}
	job := &ast.Job{
		Env:   mkEnv("JOB_TOKEN"),
		Steps: []*ast.Step{step},
	}
	workflow := &ast.Workflow{
		Env:  mkEnv("WF_TOKEN"),
		Jobs: map[string]*ast.Job{"leak": job},
	}

	rule := NewSecretInLogRule()
	if err := rule.VisitWorkflowPre(workflow); err != nil {
		t.Fatalf("VisitWorkflowPre: %v", err)
	}
	if err := rule.VisitJobPre(job); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	errs := rule.Errors()
	if len(errs) != 1 {
		t.Fatalf("expected exactly 1 leak, got %d: %v", len(errs), errs)
	}
	// メッセージ末尾は step env の secret 名を origin として含むはず（3 階層で最後に merge される）。
	if !strings.Contains(errs[0].Description, "secrets.STEP_TOKEN") {
		t.Errorf("expected origin to be overridden by step env (secrets.STEP_TOKEN), got: %s", errs[0].Description)
	}
}

// Finding 3: ::add-mask:: が sink より後に置かれているケースは「保護」扱いしない。
// GitHub Actions の add-mask は発行後のログにしか適用されないため、
// 先に echo した値はマスクされずに残る。
func TestSecretInLog_FindEchoLeaks_MaskAfterSinkIsIneffective(t *testing.T) {
	t.Parallel()
	// 1 行目の echo でリーク → 2 行目の mask ではもう手遅れ。
	script := "echo \"$TOKEN\"\necho \"::add-mask::$TOKEN\"\n"
	step := &ast.Step{
		Env: &ast.Env{Vars: map[string]*ast.EnvVar{
			"token": {
				Name:  &ast.String{Value: "TOKEN"},
				Value: &ast.String{Value: "${{ secrets.API }}"},
			},
		}},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: script, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}
	rule := NewSecretInLogRule()
	if err := rule.VisitJobPre(&ast.Job{Steps: []*ast.Step{step}}); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	if got := len(rule.Errors()); got != 1 {
		t.Errorf("mask-after-sink must not suppress the leak; got %d errors: %v", got, rule.Errors())
	}
}

// Finding 3: sink より前にある add-mask は正しく保護とみなす（従来挙動の回帰テスト）。
func TestSecretInLog_FindEchoLeaks_MaskBeforeSinkIsEffective(t *testing.T) {
	t.Parallel()
	script := "echo \"::add-mask::$TOKEN\"\necho \"$TOKEN\"\n"
	step := &ast.Step{
		Env: &ast.Env{Vars: map[string]*ast.EnvVar{
			"token": {
				Name:  &ast.String{Value: "TOKEN"},
				Value: &ast.String{Value: "${{ secrets.API }}"},
			},
		}},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: script, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}
	rule := NewSecretInLogRule()
	if err := rule.VisitJobPre(&ast.Job{Steps: []*ast.Step{step}}); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	if got := len(rule.Errors()); got != 0 {
		t.Errorf("mask-before-sink must suppress the leak; got %d errors: %v", got, rule.Errors())
	}
}

// Finding 4: `KEY=$(...); echo "$KEY"` のようにアサインと sink が同一行にある複文では
// insertAfterAssignment は安全に挿入できないため (script, false) を返し、
// FixStep はスクリプトを書き換えずに警告のみを残す。
func TestSecretInLog_AutoFix_SameLineSinkIsSafelyNoOp(t *testing.T) {
	t.Parallel()
	original := "KEY=$(echo \"$GCP_KEY\" | jq -r '.k'); echo \"$KEY\""
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
	if got := len(rule.Errors()); got != 1 {
		t.Errorf("expected 1 leak for same-line sink, got %d: %v", got, rule.Errors())
	}
	for _, f := range rule.AutoFixers() {
		if err := f.Fix(); err != nil {
			t.Fatalf("Fix: %v", err)
		}
	}
	got := step.Exec.(*ast.ExecRun).Run.Value
	if got != original {
		t.Errorf("same-line sink must not be modified by auto-fix (unsafe); got: %q", got)
	}
}

// Finding 4: insertAfterAssignment 単体テスト。改行のないスクリプトでは false を返す。
func TestSecretInLog_InsertAfterAssignment_SameLineReturnsFalse(t *testing.T) {
	t.Parallel()
	_, ok := insertAfterAssignment("KEY=$(echo foo); echo \"$KEY\"", "KEY", `echo "::add-mask::$KEY"`)
	if ok {
		t.Error("insertAfterAssignment must return false when the assignment has no trailing newline (same-line sink)")
	}
}

// Finding 6: `echo "$T" >> "$GITHUB_OUTPUT"` や `> file.txt` など stdout をファイルへ
// リダイレクトしている echo/printf はビルドログに出ないため検出対象外とする。
func TestSecretInLog_StdoutRedirectToFile_NotFlagged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		runScript string
	}{
		{
			name:      "GITHUB_OUTPUT append",
			runScript: "echo \"secret=$TOKEN\" >> \"$GITHUB_OUTPUT\"",
		},
		{
			name:      "file overwrite",
			runScript: "echo \"$TOKEN\" > secret.txt",
		},
		{
			name:      "file append",
			runScript: "echo \"$TOKEN\" >> secret.txt",
		},
		{
			name:      "printf to file",
			runScript: "printf '%s' \"$TOKEN\" > out.txt",
		},
		{
			name:      "explicit fd1 redirect",
			runScript: "echo \"$TOKEN\" 1> out.txt",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			step := &ast.Step{
				Env: &ast.Env{Vars: map[string]*ast.EnvVar{
					"token": {
						Name:  &ast.String{Value: "TOKEN"},
						Value: &ast.String{Value: "${{ secrets.API }}"},
					},
				}},
				Exec: &ast.ExecRun{
					Run: &ast.String{Value: tc.runScript, Pos: &ast.Position{Line: 1, Col: 1}},
				},
			}
			rule := NewSecretInLogRule()
			if err := rule.VisitJobPre(&ast.Job{Steps: []*ast.Step{step}}); err != nil {
				t.Fatalf("VisitJobPre: %v", err)
			}
			if got := len(rule.Errors()); got != 0 {
				t.Errorf("script %q: stdout redirected to file must not leak; got %d errors: %v",
					tc.runScript, got, rule.Errors())
			}
		})
	}
}

// Finding 6: `>&2` や `/dev/stderr` は GitHub Actions のビルドログに引き続き出力されるため、
// redirect による suppress の対象外とする（leak として検出されるべき）。
func TestSecretInLog_StderrRedirect_StillFlagged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		runScript string
	}{
		{
			name:      "redirect to /dev/stderr",
			runScript: "echo \"$TOKEN\" > /dev/stderr",
		},
		{
			name:      "no redirect",
			runScript: "echo \"$TOKEN\"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			step := &ast.Step{
				Env: &ast.Env{Vars: map[string]*ast.EnvVar{
					"token": {
						Name:  &ast.String{Value: "TOKEN"},
						Value: &ast.String{Value: "${{ secrets.API }}"},
					},
				}},
				Exec: &ast.ExecRun{
					Run: &ast.String{Value: tc.runScript, Pos: &ast.Position{Line: 1, Col: 1}},
				},
			}
			rule := NewSecretInLogRule()
			if err := rule.VisitJobPre(&ast.Job{Steps: []*ast.Step{step}}); err != nil {
				t.Fatalf("VisitJobPre: %v", err)
			}
			if got := len(rule.Errors()); got != 1 {
				t.Errorf("script %q: stderr must still leak; got %d errors: %v",
					tc.runScript, got, rule.Errors())
			}
		})
	}
}

// Issue #436: sink 拡張 — tee / cat / dd / here-string / heredoc / >&2 を追加検出対象にする。
func TestSecretInLog_SinkExpansion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		runScript  string
		wantErrors int
	}{
		// >&2 (DplOut) — stderr はログに出力されるため検出対象。
		{
			name:       "echo redirect to stderr via DplOut",
			runScript:  "echo \"$TOKEN\" >&2",
			wantErrors: 1,
		},
		{
			name:       "printf redirect to stderr via DplOut",
			runScript:  "printf '%s' \"$TOKEN\" >&2",
			wantErrors: 1,
		},
		// here-string — cat/tee/dd が受け取り stdout に出すため検出対象。
		{
			name:       "cat with here-string",
			runScript:  "cat <<< \"$TOKEN\"",
			wantErrors: 1,
		},
		{
			name:       "tee with here-string to /dev/stderr",
			runScript:  "tee /dev/stderr <<< \"$TOKEN\"",
			wantErrors: 1,
		},
		{
			name:       "dd with here-string",
			runScript:  "dd <<< \"$TOKEN\"",
			wantErrors: 1,
		},
		// heredoc — 本文内で taint 変数参照がある場合は stdout に出るため検出対象。
		{
			name:       "cat with heredoc referencing tainted var",
			runScript:  "cat <<EOF\nkey=$TOKEN\nEOF",
			wantErrors: 1,
		},
		// 安全: stdout をファイルに逸らしている場合は検出しない。
		{
			name:       "cat here-string with stdout redirected to file",
			runScript:  "cat <<< \"$TOKEN\" > out.txt",
			wantErrors: 0,
		},
		{
			name:       "tee with here-string into file only (goes to stdout too, still flagged)",
			runScript:  "tee file.txt <<< \"$TOKEN\"",
			wantErrors: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			step := &ast.Step{
				Env: &ast.Env{Vars: map[string]*ast.EnvVar{
					"token": {
						Name:  &ast.String{Value: "TOKEN"},
						Value: &ast.String{Value: "${{ secrets.API }}"},
					},
				}},
				Exec: &ast.ExecRun{
					Run: &ast.String{Value: tc.runScript, Pos: &ast.Position{Line: 1, Col: 1}},
				},
			}
			rule := NewSecretInLogRule()
			if err := rule.VisitJobPre(&ast.Job{Steps: []*ast.Step{step}}); err != nil {
				t.Fatalf("VisitJobPre: %v", err)
			}
			if got := len(rule.Errors()); got != tc.wantErrors {
				t.Errorf("script %q: got %d errors, want %d. details=%v",
					tc.runScript, got, tc.wantErrors, rule.Errors())
			}
		})
	}
}

// Finding 6: `printf -v VAR ...` は stdout を出さず指定変数に格納するため検出対象外。
func TestSecretInLog_PrintfDashV_NotFlagged(t *testing.T) {
	t.Parallel()
	script := "printf -v OUT '%s' \"$TOKEN\""
	step := &ast.Step{
		Env: &ast.Env{Vars: map[string]*ast.EnvVar{
			"token": {
				Name:  &ast.String{Value: "TOKEN"},
				Value: &ast.String{Value: "${{ secrets.API }}"},
			},
		}},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: script, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}
	rule := NewSecretInLogRule()
	if err := rule.VisitJobPre(&ast.Job{Steps: []*ast.Step{step}}); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	if got := len(rule.Errors()); got != 0 {
		t.Errorf("printf -v captures to variable and must not leak; got %d errors: %v", got, rule.Errors())
	}
}

// T4: shebang のみで他の行がないスクリプトに対する auto-fix 挙動の確認。
// shellvar 経路は対象アサインが無いため fallthrough し、shebang 直後（2 行目）に add-mask が入る。
func TestSecretInLog_AutoFix_ShebangOnlyScript(t *testing.T) {
	t.Parallel()

	// shebang 直後に tainted 環境変数を echo する最小ケース。
	// TOKEN は env 由来 (origin: secrets.API) なので、shellvar 経路を通らず冒頭挿入パスに入る。
	// shebang がある場合は shebang の直後（= 2 行目）に add-mask が挿入される。
	original := "#!/usr/bin/env bash\necho \"$TOKEN\""
	step := &ast.Step{
		Env: &ast.Env{Vars: map[string]*ast.EnvVar{
			"token": {
				Name:  &ast.String{Value: "TOKEN"},
				Value: &ast.String{Value: "${{ secrets.API }}"},
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
	for _, f := range rule.AutoFixers() {
		if err := f.Fix(); err != nil {
			t.Fatalf("Fix: %v", err)
		}
	}

	got := step.Exec.(*ast.ExecRun).Run.Value
	want := "#!/usr/bin/env bash\necho \"::add-mask::$TOKEN\"\necho \"$TOKEN\""
	if got != want {
		t.Errorf("shebang-only auto-fix: got %q, want %q", got, want)
	}
}

// Issue #437: cross-step taint — $GITHUB_ENV 経由で前 step からの taint を後続 step が引き継ぐ。
// 以降のテストは "前 step で tainted な値を $GITHUB_ENV に書き込み、後続 step で echo する"
// ケースが検出されることを保証するためのもの。

// mkRunStepForTest は env/run を受け取って最小の *ast.Step を組み立てるテストヘルパ。
// envVars の key は小文字化された map key（ast 仕様どおり）、Name.Value に実際の env var 名を入れる。
func mkRunStepForTest(t *testing.T, envVars map[string]string, script string) *ast.Step {
	t.Helper()
	var env *ast.Env
	if len(envVars) > 0 {
		vars := map[string]*ast.EnvVar{}
		for name, val := range envVars {
			vars[strings.ToLower(name)] = &ast.EnvVar{
				Name:  &ast.String{Value: name},
				Value: &ast.String{Value: val},
			}
		}
		env = &ast.Env{Vars: vars}
	}
	return &ast.Step{
		Env: env,
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: script, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}
}

func TestSecretInLog_CrossStep_BasicEnvWrite(t *testing.T) {
	t.Parallel()

	// step1: tainted な derived 値を $GITHUB_ENV へ書き込む
	// step2: 引き継がれた env var $TOKEN を echo → leak として検出されるべき
	step1 := mkRunStepForTest(t,
		map[string]string{"SECRET_JSON": "${{ secrets.S }}"},
		"DERIVED=$(echo \"$SECRET_JSON\" | jq -r '.key')\necho \"TOKEN=$DERIVED\" >> $GITHUB_ENV",
	)
	step2 := mkRunStepForTest(t, nil, "echo \"$TOKEN\"")
	job := &ast.Job{Steps: []*ast.Step{step1, step2}}

	rule := NewSecretInLogRule()
	if err := rule.VisitJobPre(job); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	if got := len(rule.Errors()); got != 1 {
		t.Fatalf("expected 1 cross-step leak, got %d: %v", got, rule.Errors())
	}
	// 検出メッセージは後続 step 側の sink 位置に対して出るはず。
	if msg := rule.Errors()[0].Description; !strings.Contains(msg, "TOKEN") {
		t.Errorf("leak message should mention $TOKEN, got: %s", msg)
	}
}

func TestSecretInLog_CrossStep_QuotedGithubEnvVariants(t *testing.T) {
	t.Parallel()

	// `$GITHUB_ENV` の書き方ブレ (`"$GITHUB_ENV"`, `${GITHUB_ENV}`) に対応する。
	cases := []struct {
		name   string
		script string
	}{
		{name: "quoted", script: "DERIVED=$(echo \"$SECRET_JSON\" | jq -r '.k')\necho \"TOKEN=$DERIVED\" >> \"$GITHUB_ENV\""},
		{name: "braced", script: "DERIVED=$(echo \"$SECRET_JSON\" | jq -r '.k')\necho \"TOKEN=$DERIVED\" >> ${GITHUB_ENV}"},
		{name: "quoted-braced", script: "DERIVED=$(echo \"$SECRET_JSON\" | jq -r '.k')\necho \"TOKEN=$DERIVED\" >> \"${GITHUB_ENV}\""},
		{name: "overwrite single >", script: "DERIVED=$(echo \"$SECRET_JSON\" | jq -r '.k')\necho \"TOKEN=$DERIVED\" > $GITHUB_ENV"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			step1 := mkRunStepForTest(t,
				map[string]string{"SECRET_JSON": "${{ secrets.S }}"},
				tc.script,
			)
			step2 := mkRunStepForTest(t, nil, "echo \"$TOKEN\"")
			job := &ast.Job{Steps: []*ast.Step{step1, step2}}

			rule := NewSecretInLogRule()
			if err := rule.VisitJobPre(job); err != nil {
				t.Fatalf("VisitJobPre: %v", err)
			}
			if got := len(rule.Errors()); got != 1 {
				t.Errorf("%s: expected 1 cross-step leak, got %d: %v", tc.name, got, rule.Errors())
			}
		})
	}
}

func TestSecretInLog_CrossStep_HeredocEnvWrite(t *testing.T) {
	t.Parallel()

	step1 := mkRunStepForTest(t,
		map[string]string{"SECRET_JSON": "${{ secrets.S }}"},
		"DERIVED=$(echo \"$SECRET_JSON\" | jq -r '.k')\ncat <<EOF >> $GITHUB_ENV\nTOKEN=$DERIVED\nEOF",
	)
	step2 := mkRunStepForTest(t, nil, "echo \"$TOKEN\"")
	job := &ast.Job{Steps: []*ast.Step{step1, step2}}

	rule := NewSecretInLogRule()
	if err := rule.VisitJobPre(job); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	if got := len(rule.Errors()); got != 1 {
		t.Errorf("heredoc cross-step: expected 1 leak, got %d: %v", got, rule.Errors())
	}
}

func TestSecretInLog_CrossStep_EnvWriteWithoutTaintIsIgnored(t *testing.T) {
	t.Parallel()

	// $GITHUB_ENV に書き込んでいるが値が tainted でないため、後続 step の echo は leak ではない。
	step1 := mkRunStepForTest(t, nil,
		"VALUE=\"hello\"\necho \"GREETING=$VALUE\" >> $GITHUB_ENV",
	)
	step2 := mkRunStepForTest(t, nil, "echo \"$GREETING\"")
	job := &ast.Job{Steps: []*ast.Step{step1, step2}}

	rule := NewSecretInLogRule()
	if err := rule.VisitJobPre(job); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	if got := len(rule.Errors()); got != 0 {
		t.Errorf("non-tainted env write must not propagate; got %d errors: %v", got, rule.Errors())
	}
}

func TestSecretInLog_CrossStep_ChainedSteps(t *testing.T) {
	t.Parallel()

	// step1 で TOKEN に書き出し、step2 でさらに DERIVED2 を作り $GITHUB_ENV へ、step3 で echo。
	step1 := mkRunStepForTest(t,
		map[string]string{"SECRET_JSON": "${{ secrets.S }}"},
		"D=$(echo \"$SECRET_JSON\" | jq -r .k)\necho \"TOKEN=$D\" >> $GITHUB_ENV",
	)
	step2 := mkRunStepForTest(t, nil,
		"D2=\"$TOKEN-suffix\"\necho \"TOKEN2=$D2\" >> $GITHUB_ENV",
	)
	step3 := mkRunStepForTest(t, nil, "echo \"$TOKEN2\"")
	job := &ast.Job{Steps: []*ast.Step{step1, step2, step3}}

	rule := NewSecretInLogRule()
	if err := rule.VisitJobPre(job); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	// step3 で $TOKEN2 が leak 1 件として検出されるはず。
	if got := len(rule.Errors()); got != 1 {
		t.Errorf("chained cross-step: expected 1 leak on step3, got %d: %v", got, rule.Errors())
	}
}

func TestSecretInLog_CrossStep_TaintDoesNotCrossJob(t *testing.T) {
	t.Parallel()

	// job A で $GITHUB_ENV に書き込まれた taint は job B には伝播しない。
	// （実装上は VisitJobPre 呼び出しごとに crossStepEnv がリセットされる前提）。
	stepA := mkRunStepForTest(t,
		map[string]string{"SECRET_JSON": "${{ secrets.S }}"},
		"D=$(echo \"$SECRET_JSON\" | jq -r .k)\necho \"TOKEN=$D\" >> $GITHUB_ENV",
	)
	stepB := mkRunStepForTest(t, nil, "echo \"$TOKEN\"")
	jobA := &ast.Job{Steps: []*ast.Step{stepA}}
	jobB := &ast.Job{Steps: []*ast.Step{stepB}}

	rule := NewSecretInLogRule()
	if err := rule.VisitJobPre(jobA); err != nil {
		t.Fatalf("VisitJobPre(A): %v", err)
	}
	if err := rule.VisitJobPre(jobB); err != nil {
		t.Fatalf("VisitJobPre(B): %v", err)
	}
	// jobB 側では未知変数なので leak は発生しないはず。
	// jobA 側は $GITHUB_ENV への書き込みのみで echo sink は無いので leak 0。
	if got := len(rule.Errors()); got != 0 {
		t.Errorf("cross-job propagation must not happen; got %d leaks: %v", got, rule.Errors())
	}
}

func TestSecretInLog_CrossStep_GithubOutputDoesNotPropagate(t *testing.T) {
	t.Parallel()

	// $GITHUB_OUTPUT は後続 step の env var にはならないため、cross-step taint の対象外。
	step1 := mkRunStepForTest(t,
		map[string]string{"SECRET_JSON": "${{ secrets.S }}"},
		"D=$(echo \"$SECRET_JSON\" | jq -r .k)\necho \"token=$D\" >> $GITHUB_OUTPUT",
	)
	step2 := mkRunStepForTest(t, nil, "echo \"$TOKEN\"")
	job := &ast.Job{Steps: []*ast.Step{step1, step2}}

	rule := NewSecretInLogRule()
	if err := rule.VisitJobPre(job); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	if got := len(rule.Errors()); got != 0 {
		t.Errorf("GITHUB_OUTPUT write must not propagate as env taint; got %d: %v", got, rule.Errors())
	}
}

func TestSecretInLog_CrossStep_StepEnvOverridesCrossStep(t *testing.T) {
	t.Parallel()

	// step1 で TOKEN=tainted を GITHUB_ENV に書く。
	// step2 は step-level env で TOKEN を untrusted ではない値に上書きする想定なので、
	// step2 の origin は step env 側が使われる。ここでは step2 env 自身も secrets 参照を含むため
	// leak は発生するが、origin が step env 側の secret 名であることを確認する。
	step1 := mkRunStepForTest(t,
		map[string]string{"SECRET_JSON": "${{ secrets.UPSTREAM }}"},
		"D=$(echo \"$SECRET_JSON\" | jq -r .k)\necho \"TOKEN=$D\" >> $GITHUB_ENV",
	)
	step2 := mkRunStepForTest(t,
		map[string]string{"TOKEN": "${{ secrets.STEP_LEVEL }}"},
		"echo \"$TOKEN\"",
	)
	job := &ast.Job{Steps: []*ast.Step{step1, step2}}

	rule := NewSecretInLogRule()
	if err := rule.VisitJobPre(job); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	errs := rule.Errors()
	if len(errs) != 1 {
		t.Fatalf("expected exactly 1 leak in step2, got %d: %v", len(errs), errs)
	}
	if !strings.Contains(errs[0].Description, "secrets.STEP_LEVEL") {
		t.Errorf("expected step-env origin (secrets.STEP_LEVEL) to win over cross-step origin, got: %s", errs[0].Description)
	}
}

// tee / dd の heredoc 経由で $GITHUB_ENV に書き込むケースでも cross-step 伝播する。
func TestSecretInLog_CrossStep_TeeHeredocEnvWrite(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		script string
	}{
		{
			name:   "tee heredoc with append redirect",
			script: "DERIVED=$(echo \"$SECRET_JSON\" | jq -r '.k')\ntee <<EOF >> $GITHUB_ENV\nTOKEN=$DERIVED\nEOF",
		},
		{
			name:   "dd heredoc with append redirect",
			script: "DERIVED=$(echo \"$SECRET_JSON\" | jq -r '.k')\ndd <<EOF >> $GITHUB_ENV\nTOKEN=$DERIVED\nEOF",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			step1 := mkRunStepForTest(t,
				map[string]string{"SECRET_JSON": "${{ secrets.S }}"},
				tc.script,
			)
			step2 := mkRunStepForTest(t, nil, "echo \"$TOKEN\"")
			job := &ast.Job{Steps: []*ast.Step{step1, step2}}

			rule := NewSecretInLogRule()
			if err := rule.VisitJobPre(job); err != nil {
				t.Fatalf("VisitJobPre: %v", err)
			}
			if got := len(rule.Errors()); got != 1 {
				t.Errorf("%s: expected 1 cross-step leak via %s heredoc, got %d: %v", tc.name, tc.name, got, rule.Errors())
			}
		})
	}
}

// echo の短いオプション (`-n`, `-e`, `-E`) が先頭にある場合でも cross-step 伝播を検出する。
// printf のフォーマット指定子 (`%s\n`) 先頭も対象。
func TestSecretInLog_CrossStep_LeadingOptionBeforeNameEquals(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		script string
	}{
		{
			name:   "echo -n",
			script: "DERIVED=$(echo \"$SECRET_JSON\" | jq -r '.k')\necho -n \"TOKEN=$DERIVED\" >> $GITHUB_ENV",
		},
		{
			name:   "echo -e",
			script: "DERIVED=$(echo \"$SECRET_JSON\" | jq -r '.k')\necho -e \"TOKEN=$DERIVED\" >> $GITHUB_ENV",
		},
		{
			name:   "echo -nE combined",
			script: "DERIVED=$(echo \"$SECRET_JSON\" | jq -r '.k')\necho -nE \"TOKEN=$DERIVED\" >> $GITHUB_ENV",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			step1 := mkRunStepForTest(t,
				map[string]string{"SECRET_JSON": "${{ secrets.S }}"},
				tc.script,
			)
			step2 := mkRunStepForTest(t, nil, "echo \"$TOKEN\"")
			job := &ast.Job{Steps: []*ast.Step{step1, step2}}

			rule := NewSecretInLogRule()
			if err := rule.VisitJobPre(job); err != nil {
				t.Fatalf("VisitJobPre: %v", err)
			}
			if got := len(rule.Errors()); got != 1 {
				t.Errorf("%s: expected 1 cross-step leak, got %d: %v", tc.name, got, rule.Errors())
			}
		})
	}
}

// runBPatternStep は #446 リグレッションテスト共通のセットアップ。
// step.Env に TOKEN: ${{ secrets.GCP_KEY }} を設定し、与えられた script を実行する
// 単一ステップの Job を VisitJobPre する。
func runBPatternStep(t *testing.T, script string) []*LintingError {
	t.Helper()
	rule := NewSecretInLogRule()
	step := &ast.Step{
		Env: &ast.Env{Vars: map[string]*ast.EnvVar{
			"TOKEN": {
				Name:  &ast.String{Value: "TOKEN"},
				Value: &ast.String{Value: "${{ secrets.GCP_KEY }}"},
			},
		}},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: script, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}
	if err := rule.VisitJobPre(&ast.Job{Steps: []*ast.Step{step}}); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	return rule.Errors()
}

func TestSecretInLog_CommentLineNotFalseDetected(t *testing.T) {
	t.Parallel()
	errs := runBPatternStep(t, `# X="$TOKEN"
echo "no leak"`)
	if len(errs) != 0 {
		t.Errorf("expected 0 errors (comment is not real assignment), got %d: %v", len(errs), errs)
	}
}

func TestSecretInLog_HeredocBodyNotFalseDetected(t *testing.T) {
	t.Parallel()
	// true <<EOF discards the body (true is not a cat/tee/dd sink). If
	// propagateTaint mistakenly treated `X=$TOKEN` inside the heredoc body as
	// a real assignment (regex-era FP), then the subsequent `echo "$X"` would
	// be flagged as a leak. With AST-based parsing, X is never assigned, so
	// no leak should be reported.
	errs := runBPatternStep(t, `true <<EOF
X=$TOKEN
EOF
echo "$X"`)
	if len(errs) != 0 {
		t.Errorf("expected 0 errors (heredoc body is not assignment), got %d: %v", len(errs), errs)
	}
}

func TestSecretInLog_OneLinerMultipleAssignments(t *testing.T) {
	t.Parallel()
	errs := runBPatternStep(t, `X=1; Y="$TOKEN"; echo "$Y"`)
	if len(errs) == 0 {
		t.Errorf("expected leak detection on $Y from one-liner assignment, got 0 errors")
	}
}

func TestSecretInLog_LineContinuationDoesNotBreakDetection(t *testing.T) {
	t.Parallel()
	// The backslash continuation must live INSIDE the quoted assignment value
	// so the assignment itself spans two lines (rather than scoping URL to a
	// following command's environment via the `VAR=val command` form).
	errs := runBPatternStep(t, "URL=\"$TOKEN \\\n   suffix\"\necho \"$URL\"")
	if len(errs) == 0 {
		t.Errorf("expected leak detection on $URL from line-continued assignment, got 0 errors")
	}
}

// TestOffsetToPosition_ColumnValue は offsetToPosition の Line/Col 計算と
// Literal block 補正、out-of-range フォールバックを直接 assert する。
//
// script のオフセット境界:
//   "echo $TOKEN\n  echo $SECRET\n"
//        ^5             ^19
//   - line 1: `echo $TOKEN` (offset 0..10), '\n' at 11
//   - line 2: `  echo $SECRET` (offset 12..25), '\n' at 26
func TestOffsetToPosition_ColumnValue(t *testing.T) {
	t.Parallel()

	const script = "echo $TOKEN\n  echo $SECRET\n"
	tokenDollar := strings.Index(script, "$TOKEN")   // expect 5
	secretDollar := strings.Index(script, "$SECRET") // expect 19
	if tokenDollar != 5 || secretDollar != 19 {
		t.Fatalf("setup error: tokenDollar=%d, secretDollar=%d", tokenDollar, secretDollar)
	}

	type want struct {
		Line int
		Col  int
	}
	cases := []struct {
		name   string
		runStr *ast.String
		offset int
		want   want
	}{
		{
			name:   "first_line_no_literal",
			runStr: &ast.String{Pos: &ast.Position{Line: 10, Col: 0}, Literal: false},
			offset: tokenDollar,
			want:   want{Line: 10, Col: 6}, // col = 5 + 1
		},
		{
			name:   "second_line_no_literal",
			runStr: &ast.String{Pos: &ast.Position{Line: 10, Col: 0}, Literal: false},
			offset: secretDollar,
			want:   want{Line: 11, Col: 8}, // 19 - 11 - 1 = 7, +1 = 8
		},
		{
			name:   "second_line_literal_block",
			runStr: &ast.String{Pos: &ast.Position{Line: 10, Col: 0}, Literal: true},
			offset: secretDollar,
			want:   want{Line: 12, Col: 8}, // Literal => Line += 1
		},
		{
			name:   "negative_offset_clamped_to_zero",
			runStr: &ast.String{Pos: &ast.Position{Line: 10, Col: 0}, Literal: false},
			offset: -1,
			want:   want{Line: 10, Col: 1}, // forced to 0, col = 0 + 1
		},
		{
			name:   "out_of_range_offset_clamped_to_zero",
			runStr: &ast.String{Pos: &ast.Position{Line: 10, Col: 0}, Literal: false},
			offset: len(script) + 5,
			want:   want{Line: 10, Col: 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := offsetToPosition(tc.runStr, script, tc.offset)
			if got.Line != tc.want.Line || got.Col != tc.want.Col {
				t.Errorf("got Line=%d Col=%d, want Line=%d Col=%d",
					got.Line, got.Col, tc.want.Line, tc.want.Col)
			}
		})
	}
}

// TestSecretInLog_PositionalArgFromShellVar_DetectsLeak は #448 で関数引数経由
// の secret 漏洩 (echo "$1") が検出されることを確認する。
func TestSecretInLog_PositionalArgFromShellVar_DetectsLeak(t *testing.T) {
	t.Parallel()

	runScript := "TOKEN=$(echo \"$KEY\" | jq -r '.token')\nleak() { echo \"$1\"; }\nleak \"$TOKEN\"\n"
	step := &ast.Step{
		Env: &ast.Env{Vars: map[string]*ast.EnvVar{
			"key": {
				Name:  &ast.String{Value: "KEY"},
				Value: &ast.String{Value: "${{ secrets.GH_TOKEN }}"},
			},
		}},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: runScript, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}
	rule := NewSecretInLogRule()
	if err := rule.VisitJobPre(&ast.Job{Steps: []*ast.Step{step}}); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	errs := rule.Errors()
	if len(errs) != 1 {
		t.Fatalf("got %d errors; want 1; errors: %v", len(errs), errs)
	}
	msg := errs[0].Description
	if !strings.Contains(msg, "$1") {
		t.Errorf("error message %q should mention positional arg $1", msg)
	}
	if !strings.Contains(msg, "shellvar:TOKEN") {
		t.Errorf("error message %q should mention origin shellvar:TOKEN", msg)
	}
}

// TestSecretInLog_PositionalArgFromShellVar_AutofixMasksUpstream は
// positional 引数 ($1) のリークに対して autofix が **upstream 変数 (TOKEN) を
// マスクする** ことを検証する (positional の "$1" を直接マスクしない)。
func TestSecretInLog_PositionalArgFromShellVar_AutofixMasksUpstream(t *testing.T) {
	t.Parallel()

	runScript := "TOKEN=$(echo \"$KEY\" | jq -r '.token')\nleak() { echo \"$1\"; }\nleak \"$TOKEN\"\n"
	step := &ast.Step{
		Env: &ast.Env{Vars: map[string]*ast.EnvVar{
			"key": {
				Name:  &ast.String{Value: "KEY"},
				Value: &ast.String{Value: "${{ secrets.GH_TOKEN }}"},
			},
		}},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: runScript, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}
	rule := NewSecretInLogRule()
	if err := rule.VisitJobPre(&ast.Job{Steps: []*ast.Step{step}}); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	for _, f := range rule.AutoFixers() {
		if err := f.Fix(); err != nil {
			t.Fatalf("Fix: %v", err)
		}
	}

	exec, ok := step.Exec.(*ast.ExecRun)
	if !ok || exec.Run == nil {
		t.Fatal("step.Exec is not ExecRun")
	}
	got := exec.Run.Value
	wantInsert := `echo "::add-mask::$TOKEN"`
	if !strings.Contains(got, wantInsert) {
		t.Errorf("script after autofix does not contain %q; got:\n%s", wantInsert, got)
	}
	tokenLineIdx := strings.Index(got, "TOKEN=$(")
	maskLineIdx := strings.Index(got, wantInsert)
	if tokenLineIdx < 0 || maskLineIdx < 0 || maskLineIdx <= tokenLineIdx {
		t.Errorf("expected mask to be inserted after TOKEN= line; got:\n%s", got)
	}
	// positional "$1" を直接マスクする誤った insert がないこと
	if strings.Contains(got, `echo "::add-mask::$1"`) {
		t.Errorf("script should NOT contain '::add-mask::$1' (positional); got:\n%s", got)
	}
}
