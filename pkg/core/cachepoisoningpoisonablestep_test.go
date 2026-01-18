package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestNewCachePoisoningPoisonableStepRule(t *testing.T) {
	rule := NewCachePoisoningPoisonableStepRule()

	if rule.RuleName != "cache-poisoning-poisonable-step" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "cache-poisoning-poisonable-step")
	}
	if rule.RuleDesc == "" {
		t.Error("RuleDesc should not be empty")
	}
}

func TestIsPoisonableLocalScript(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   bool
	}{
		{
			name:   "direct local script",
			script: "./build.sh",
			want:   true,
		},
		{
			name:   "bash local script",
			script: "bash ./test.sh",
			want:   true,
		},
		{
			name:   "sh local script",
			script: "sh ./script.sh",
			want:   true,
		},
		{
			name:   "python local script",
			script: "python ./setup.py",
			want:   true,
		},
		{
			name:   "node local script",
			script: "node ./index.js",
			want:   true,
		},
		{
			name:   "multiline with local script",
			script: "echo 'Hello'\n./run.sh\necho 'Done'",
			want:   true,
		},
		{
			name:   "command with local path argument",
			script: "test -f ./some/file",
			want:   true,
		},
		{
			name:   "external command only",
			script: "echo 'Hello World'",
			want:   false,
		},
		{
			name:   "empty script",
			script: "",
			want:   false,
		},
		{
			name:   "comment only",
			script: "# ./build.sh",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPoisonableLocalScript(tt.script)
			if got != tt.want {
				t.Errorf("isPoisonableLocalScript(%q) = %v, want %v", tt.script, got, tt.want)
			}
		})
	}
}

func TestIsPoisonableBuildCommand(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   bool
	}{
		{
			name:   "npm install",
			script: "npm install",
			want:   true,
		},
		{
			name:   "npm ci",
			script: "npm ci",
			want:   true,
		},
		{
			name:   "npm run build",
			script: "npm run build",
			want:   true,
		},
		{
			name:   "yarn",
			script: "yarn",
			want:   true,
		},
		{
			name:   "yarn install",
			script: "yarn install",
			want:   true,
		},
		{
			name:   "pnpm install",
			script: "pnpm install",
			want:   true,
		},
		{
			name:   "pip install",
			script: "pip install -r requirements.txt",
			want:   true,
		},
		{
			name:   "pip3 install",
			script: "pip3 install .",
			want:   true,
		},
		{
			name:   "python -m pip install",
			script: "python -m pip install .",
			want:   true,
		},
		{
			name:   "make",
			script: "make",
			want:   true,
		},
		{
			name:   "make build",
			script: "make build",
			want:   true,
		},
		{
			name:   "cmake",
			script: "cmake .",
			want:   true,
		},
		{
			name:   "./configure",
			script: "./configure && make",
			want:   true,
		},
		{
			name:   "go build",
			script: "go build ./...",
			want:   true,
		},
		{
			name:   "cargo build",
			script: "cargo build --release",
			want:   true,
		},
		{
			name:   "mvn",
			script: "mvn package",
			want:   true,
		},
		{
			name:   "gradle",
			script: "gradle build",
			want:   true,
		},
		{
			name:   "bundle install",
			script: "bundle install",
			want:   true,
		},
		{
			name:   "composer install",
			script: "composer install",
			want:   true,
		},
		{
			name:   "poetry install",
			script: "poetry install",
			want:   true,
		},
		{
			name:   "multiline with build command",
			script: "echo 'Installing dependencies'\nnpm install\necho 'Done'",
			want:   true,
		},
		{
			name:   "echo command",
			script: "echo 'Hello'",
			want:   false,
		},
		{
			name:   "ls command",
			script: "ls -la",
			want:   false,
		},
		{
			name:   "empty script",
			script: "",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPoisonableBuildCommand(tt.script)
			if got != tt.want {
				t.Errorf("isPoisonableBuildCommand(%q) = %v, want %v", tt.script, got, tt.want)
			}
		})
	}
}

func TestIsPoisonableLocalAction(t *testing.T) {
	tests := []struct {
		name string
		uses string
		want bool
	}{
		{
			name: "local action",
			uses: "./.github/actions/my-action",
			want: true,
		},
		{
			name: "local action simple",
			uses: "./action",
			want: true,
		},
		{
			name: "external action",
			uses: "actions/checkout@v4",
			want: false,
		},
		{
			name: "external action with org",
			uses: "my-org/my-action@v1",
			want: false,
		},
		{
			name: "empty",
			uses: "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPoisonableLocalAction(tt.uses)
			if got != tt.want {
				t.Errorf("isPoisonableLocalAction(%q) = %v, want %v", tt.uses, got, tt.want)
			}
		})
	}
}

func TestIsPoisonableGitHubScript(t *testing.T) {
	tests := []struct {
		name   string
		uses   string
		inputs map[string]*ast.Input
		want   bool
	}{
		{
			name: "github-script with require",
			uses: "actions/github-script@v7",
			inputs: map[string]*ast.Input{
				"script": {
					Value: &ast.String{Value: "const script = require('./scripts/test.js')"},
				},
			},
			want: true,
		},
		{
			name: "github-script with import",
			uses: "actions/github-script@v7",
			inputs: map[string]*ast.Input{
				"script": {
					Value: &ast.String{Value: "const { foo } = await import('./lib/foo.mjs')"},
				},
			},
			want: true,
		},
		{
			name: "github-script with workspace import",
			uses: "actions/github-script@v7",
			inputs: map[string]*ast.Input{
				"script": {
					Value: &ast.String{Value: "const script = require('${{ github.workspace }}/scripts/test.js')"},
				},
			},
			want: true,
		},
		{
			name: "github-script without local import",
			uses: "actions/github-script@v7",
			inputs: map[string]*ast.Input{
				"script": {
					Value: &ast.String{Value: "console.log('Hello')"},
				},
			},
			want: false,
		},
		{
			name: "github-script with external require",
			uses: "actions/github-script@v7",
			inputs: map[string]*ast.Input{
				"script": {
					Value: &ast.String{Value: "const fs = require('fs')"},
				},
			},
			want: false,
		},
		{
			name:   "github-script without script input",
			uses:   "actions/github-script@v7",
			inputs: map[string]*ast.Input{},
			want:   false,
		},
		{
			name: "non github-script action",
			uses: "actions/checkout@v4",
			inputs: map[string]*ast.Input{
				"script": {
					Value: &ast.String{Value: "const script = require('./test.js')"},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPoisonableGitHubScript(tt.uses, tt.inputs)
			if got != tt.want {
				t.Errorf("isPoisonableGitHubScript(%q, inputs) = %v, want %v", tt.uses, got, tt.want)
			}
		})
	}
}

func TestCachePoisoningPoisonableStepRule_DetectsLocalScript(t *testing.T) {
	rule := NewCachePoisoningPoisonableStepRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request_target"},
			},
		},
	}

	job := &ast.Job{
		ID: &ast.String{Value: "test"},
	}

	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}

	runStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: "./build.sh"},
		},
	}

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)
	_ = rule.VisitStep(checkoutStep)
	_ = rule.VisitStep(runStep)

	errs := rule.Errors()
	if len(errs) == 0 {
		t.Error("Expected error for local script after unsafe checkout, got none")
	} else {
		if !containsSubstr(errs[0].Description, "local script execution") {
			t.Errorf("Expected error about local script execution, got: %s", errs[0].Description)
		}
	}
}

func TestCachePoisoningPoisonableStepRule_DetectsBuildCommand(t *testing.T) {
	rule := NewCachePoisoningPoisonableStepRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request_target"},
			},
		},
	}

	job := &ast.Job{
		ID: &ast.String{Value: "test"},
	}

	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}

	runStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: "npm install"},
		},
	}

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)
	_ = rule.VisitStep(checkoutStep)
	_ = rule.VisitStep(runStep)

	errs := rule.Errors()
	if len(errs) == 0 {
		t.Error("Expected error for build command after unsafe checkout, got none")
	} else {
		if !containsSubstr(errs[0].Description, "build command") {
			t.Errorf("Expected error about build command, got: %s", errs[0].Description)
		}
	}
}

func TestCachePoisoningPoisonableStepRule_DetectsLocalAction(t *testing.T) {
	rule := NewCachePoisoningPoisonableStepRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "issue_comment"},
			},
		},
	}

	job := &ast.Job{
		ID: &ast.String{Value: "test"},
	}

	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.event.pull_request.head.sha }}"}},
			},
		},
	}

	localActionStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "./.github/actions/build"},
		},
	}

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)
	_ = rule.VisitStep(checkoutStep)
	_ = rule.VisitStep(localActionStep)

	errs := rule.Errors()
	if len(errs) == 0 {
		t.Error("Expected error for local action after unsafe checkout, got none")
	} else {
		if !containsSubstr(errs[0].Description, "local action") {
			t.Errorf("Expected error about local action, got: %s", errs[0].Description)
		}
	}
}

func TestCachePoisoningPoisonableStepRule_DetectsGitHubScript(t *testing.T) {
	rule := NewCachePoisoningPoisonableStepRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "workflow_run"},
			},
		},
	}

	job := &ast.Job{
		ID: &ast.String{Value: "test"},
	}

	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}

	githubScriptStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/github-script@v7"},
			Inputs: map[string]*ast.Input{
				"script": {Value: &ast.String{Value: "const script = require('./scripts/test.js')"}},
			},
		},
	}

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)
	_ = rule.VisitStep(checkoutStep)
	_ = rule.VisitStep(githubScriptStep)

	errs := rule.Errors()
	if len(errs) == 0 {
		t.Error("Expected error for github-script with local import after unsafe checkout, got none")
	} else {
		if !containsSubstr(errs[0].Description, "github-script with local import") {
			t.Errorf("Expected error about github-script with local import, got: %s", errs[0].Description)
		}
	}
}

func TestCachePoisoningPoisonableStepRule_NoErrorWithSafeTrigger(t *testing.T) {
	rule := NewCachePoisoningPoisonableStepRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request"},
			},
		},
	}

	job := &ast.Job{
		ID: &ast.String{Value: "test"},
	}

	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}

	runStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: "./build.sh"},
		},
	}

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)
	_ = rule.VisitStep(checkoutStep)
	_ = rule.VisitStep(runStep)

	errs := rule.Errors()
	if len(errs) != 0 {
		t.Errorf("Expected no errors with safe trigger, got %d: %v", len(errs), errs)
	}
}

func TestCachePoisoningPoisonableStepRule_NoErrorWithoutUnsafeCheckout(t *testing.T) {
	rule := NewCachePoisoningPoisonableStepRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request_target"},
			},
		},
	}

	job := &ast.Job{
		ID: &ast.String{Value: "test"},
	}

	// Safe checkout (no ref specified)
	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses:   &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{},
		},
	}

	runStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: "./build.sh"},
		},
	}

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)
	_ = rule.VisitStep(checkoutStep)
	_ = rule.VisitStep(runStep)

	errs := rule.Errors()
	if len(errs) != 0 {
		t.Errorf("Expected no errors without unsafe checkout, got %d: %v", len(errs), errs)
	}
}

func TestCachePoisoningPoisonableStepRule_NoErrorForExternalAction(t *testing.T) {
	rule := NewCachePoisoningPoisonableStepRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request_target"},
			},
		},
	}

	job := &ast.Job{
		ID: &ast.String{Value: "test"},
	}

	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}

	// External action (not local)
	externalActionStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/setup-node@v4"},
		},
	}

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)
	_ = rule.VisitStep(checkoutStep)
	_ = rule.VisitStep(externalActionStep)

	errs := rule.Errors()
	if len(errs) != 0 {
		t.Errorf("Expected no errors for external action, got %d: %v", len(errs), errs)
	}
}

func TestCachePoisoningPoisonableStepRule_NoErrorForSafeCommand(t *testing.T) {
	rule := NewCachePoisoningPoisonableStepRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request_target"},
			},
		},
	}

	job := &ast.Job{
		ID: &ast.String{Value: "test"},
	}

	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}

	// Safe command (just echo)
	runStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: "echo 'Hello World'"},
		},
	}

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)
	_ = rule.VisitStep(checkoutStep)
	_ = rule.VisitStep(runStep)

	errs := rule.Errors()
	if len(errs) != 0 {
		t.Errorf("Expected no errors for safe command, got %d: %v", len(errs), errs)
	}
}

func TestCachePoisoningPoisonableStepRule_JobIsolation(t *testing.T) {
	rule := NewCachePoisoningPoisonableStepRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request_target"},
			},
		},
	}

	job1 := &ast.Job{
		ID: &ast.String{Value: "job1"},
	}

	// Job 1: unsafe checkout only
	checkoutStep1 := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}

	job2 := &ast.Job{
		ID: &ast.String{Value: "job2"},
	}

	// Job 2: no checkout, just run script
	runStep2 := &ast.Step{
		Pos: &ast.Position{Line: 20, Col: 1},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: "./build.sh"},
		},
	}

	_ = rule.VisitWorkflowPre(workflow)

	// Process job 1
	_ = rule.VisitJobPre(job1)
	_ = rule.VisitStep(checkoutStep1)
	_ = rule.VisitJobPost(job1)

	// Process job 2
	_ = rule.VisitJobPre(job2)
	_ = rule.VisitStep(runStep2)
	_ = rule.VisitJobPost(job2)

	errs := rule.Errors()
	if len(errs) != 0 {
		t.Errorf("Expected no errors due to job isolation, got %d: %v", len(errs), errs)
	}
}

func TestCachePoisoningPoisonableStepRule_AutoFixerRegisteredOnce(t *testing.T) {
	rule := NewCachePoisoningPoisonableStepRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request_target"},
			},
		},
	}

	job := &ast.Job{
		ID: &ast.String{Value: "test"},
	}

	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}

	runStep1 := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: "./build.sh"},
		},
	}

	runStep2 := &ast.Step{
		Pos: &ast.Position{Line: 20, Col: 1},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: "npm install"},
		},
	}

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)
	_ = rule.VisitStep(checkoutStep)
	_ = rule.VisitStep(runStep1)
	_ = rule.VisitStep(runStep2)

	// Should have 2 errors but only 1 auto-fixer
	errs := rule.Errors()
	if len(errs) != 2 {
		t.Errorf("Expected 2 errors, got %d", len(errs))
	}

	autoFixers := rule.autoFixers
	if len(autoFixers) != 1 {
		t.Errorf("Expected 1 auto-fixer (registered once), got %d", len(autoFixers))
	}
}

func TestCachePoisoningPoisonableStepRule_MultipleUnsafeTriggers(t *testing.T) {
	rule := NewCachePoisoningPoisonableStepRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request_target"},
			},
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "issue_comment"},
			},
		},
	}

	job := &ast.Job{
		ID: &ast.String{Value: "test"},
	}

	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}

	runStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: "./build.sh"},
		},
	}

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)
	_ = rule.VisitStep(checkoutStep)
	_ = rule.VisitStep(runStep)

	errs := rule.Errors()
	if len(errs) == 0 {
		t.Error("Expected error, got none")
	} else {
		// Error message should contain both triggers
		if !containsSubstr(errs[0].Description, "pull_request_target") || !containsSubstr(errs[0].Description, "issue_comment") {
			t.Errorf("Expected error message to contain both triggers, got: %s", errs[0].Description)
		}
	}
}

func containsSubstr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && indexOfSubstr(s, substr) >= 0))
}

func indexOfSubstr(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
