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
