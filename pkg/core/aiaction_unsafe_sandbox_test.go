package core

import (
	"strings"
	"testing"
)

func TestAIActionUnsafeSandbox_DetectsUnsafeStrategy(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnsafeSandboxRule()

	workflow := `
on:
  issues:
    types: [opened]
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@v1
        with:
          safety-strategy: unsafe
`
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	ruleErrors := rule.Errors()
	if len(ruleErrors) == 0 {
		t.Fatal("expected error for safety-strategy: unsafe, got none")
	}
	if !strings.Contains(ruleErrors[0].Description, "safety-strategy") {
		t.Errorf("expected error to mention safety-strategy, got: %s", ruleErrors[0].Description)
	}
	if ruleErrors[0].Type != "ai-action-unsafe-sandbox" {
		t.Errorf("expected error type ai-action-unsafe-sandbox, got: %s", ruleErrors[0].Type)
	}
}

// #648: danger-full-access は safety-strategy の値ではない。codex-action が
// safety-strategy に定義している値は drop-sudo / unprivileged-user / read-only /
// unsafe の 4 つで、danger-full-access は sandbox 入力（およびその後継の
// permission-profile）の値である。到達しえない値を報告してはならない。
func TestAIActionUnsafeSandbox_IgnoresDangerFullAccessOnSafetyStrategy(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnsafeSandboxRule()

	workflow := `
on:
  push:
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@v1
        with:
          safety-strategy: danger-full-access
`
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	ruleErrors := rule.Errors()
	if len(ruleErrors) != 0 {
		t.Fatalf("expected no errors for safety-strategy: danger-full-access, got %d: %v", len(ruleErrors), ruleErrors)
	}
}

// #648: codex-action は composite action で、宣言した "safety-strategy" だけを
// inputs['safety-strategy'] として読む。アンダースコア区切りの綴りは action に
// 届かず、ステップは既定の drop-sudo で動くため、報告すると偽陽性になる。
func TestAIActionUnsafeSandbox_IgnoresUnderscoreSafetyStrategyKey(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnsafeSandboxRule()

	workflow := `
on:
  push:
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@v1
        with:
          safety_strategy: unsafe
`
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	ruleErrors := rule.Errors()
	if len(ruleErrors) != 0 {
		t.Fatalf("expected no errors for an undeclared safety_strategy input, got %d: %v", len(ruleErrors), ruleErrors)
	}
}

// #648: sandbox と permission-profile は codex-action の入力で、どちらも
// サンドボックスを無効化できる。以前はどちらも読まれていなかった。
func TestAIActionUnsafeSandbox_ChecksCodexSandboxInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		uses        string
		with        string
		wantFinding bool
		wantInMsg   []string
	}{
		{
			name:        "sandbox danger-full-access is reported",
			uses:        "openai/codex-action@v1",
			with:        "sandbox: danger-full-access",
			wantFinding: true,
			wantInMsg:   []string{"sandbox", "danger-full-access"},
		},
		{
			name:        "permission-profile danger-full-access is reported",
			uses:        "openai/codex-action@v1",
			with:        `permission-profile: ":danger-full-access"`,
			wantFinding: true,
			wantInMsg:   []string{"permission-profile", ":danger-full-access"},
		},
		{
			name: "sandbox workspace-write is not reported",
			uses: "openai/codex-action@v1",
			with: "sandbox: workspace-write",
		},
		{
			name: "sandbox read-only is not reported",
			uses: "openai/codex-action@v1",
			with: "sandbox: read-only",
		},
		{
			name: "permission-profile workspace is not reported",
			uses: "openai/codex-action@v1",
			with: `permission-profile: ":workspace"`,
		},
		{
			name: "permission-profile read-only is not reported",
			uses: "openai/codex-action@v1",
			with: `permission-profile: ":read-only"`,
		},
		{
			// sandbox_mode は Codex CLI の設定キーで、codex-args 経由で渡す。
			name: "sandbox_mode is not an input and is not reported",
			uses: "openai/codex-action@v1",
			with: "sandbox_mode: danger-full-access",
		},
		{
			name: "sandbox-mode is not an input and is not reported",
			uses: "openai/codex-action@v1",
			with: "sandbox-mode: danger-full-access",
		},
		{
			// sandbox を宣言しているのは codex-action だけなので、他の AI アクションで
			// 同じキーが書かれても、そのアクションは読まない。
			name: "sandbox is only read on codex-action",
			uses: "anthropics/claude-code-action@v1",
			with: "sandbox: danger-full-access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := NewAIActionUnsafeSandboxRule()

			workflow := `
on:
  issues:
    types: [opened]
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: ` + tt.uses + `
        with:
          ` + tt.with + `
`
			parsed, errs := Parse([]byte(workflow))
			if len(errs) > 0 {
				t.Fatalf("failed to parse workflow: %v", errs)
			}

			v := NewSyntaxTreeVisitor()
			v.AddVisitor(rule)
			if err := v.VisitTree(parsed); err != nil {
				t.Fatalf("failed to visit tree: %v", err)
			}

			ruleErrors := rule.Errors()
			if !tt.wantFinding {
				if len(ruleErrors) != 0 {
					t.Fatalf("expected no errors for %q, got %d: %v", tt.with, len(ruleErrors), ruleErrors)
				}
				return
			}
			if len(ruleErrors) == 0 {
				t.Fatalf("expected an error for %q, got none", tt.with)
			}
			for _, want := range tt.wantInMsg {
				if !strings.Contains(ruleErrors[0].Description, want) {
					t.Errorf("expected error to mention %q, got: %s", want, ruleErrors[0].Description)
				}
			}
		})
	}
}

func TestAIActionUnsafeSandbox_DetectsDangerouslySkipPermissions(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnsafeSandboxRule()

	workflow := `
on:
  issues:
    types: [opened]
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --dangerouslySkipPermissions --allowedTools "Bash,Read"
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	ruleErrors := rule.Errors()
	if len(ruleErrors) == 0 {
		t.Fatal("expected error for --dangerouslySkipPermissions, got none")
	}
	if !strings.Contains(ruleErrors[0].Description, "dangerouslySkipPermissions") {
		t.Errorf("expected error to mention dangerouslySkipPermissions, got: %s", ruleErrors[0].Description)
	}
}

func TestAIActionUnsafeSandbox_AllowsSafeStrategies(t *testing.T) {
	t.Parallel()

	safeValues := []string{"drop-sudo", "unprivileged-user", "read-only"}
	for _, val := range safeValues {
		t.Run(val, func(t *testing.T) {
			t.Parallel()
			rule := NewAIActionUnsafeSandboxRule()

			workflow := `
on:
  push:
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@v1
        with:
          safety-strategy: ` + val + `
`
			parsed, errs := Parse([]byte(workflow))
			if len(errs) > 0 {
				t.Fatalf("failed to parse workflow: %v", errs)
			}

			v := NewSyntaxTreeVisitor()
			v.AddVisitor(rule)
			if err := v.VisitTree(parsed); err != nil {
				t.Fatalf("failed to visit tree: %v", err)
			}

			ruleErrors := rule.Errors()
			if len(ruleErrors) != 0 {
				t.Fatalf("expected no errors for safe strategy %q, got %d: %v", val, len(ruleErrors), ruleErrors)
			}
		})
	}
}

func TestAIActionUnsafeSandbox_IgnoresNonAIAction(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnsafeSandboxRule()

	workflow := `
on:
  push:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          safety-strategy: unsafe
`
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	ruleErrors := rule.Errors()
	if len(ruleErrors) != 0 {
		t.Fatalf("expected no errors for non-AI action, got %d", len(ruleErrors))
	}
}

func TestAIActionUnsafeSandbox_NoSandboxInputIsOK(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnsafeSandboxRule()

	workflow := `
on:
  push:
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@v1
        with:
          model: o3-mini
`
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	ruleErrors := rule.Errors()
	if len(ruleErrors) != 0 {
		t.Fatalf("expected no errors when safety-strategy is not set, got %d: %v", len(ruleErrors), ruleErrors)
	}
}
