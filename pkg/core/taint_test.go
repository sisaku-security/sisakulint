package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestTaintTracker_NewTaintTracker(t *testing.T) {
	t.Parallel()

	tracker := NewTaintTracker()
	if tracker == nil {
		t.Fatal("NewTaintTracker returned nil")
	}
	if tracker.taintedOutputs == nil {
		t.Error("taintedOutputs map should be initialized")
	}
}

func TestTaintTracker_AnalyzeStep_DirectUntrustedOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		stepID         string
		script         string
		expectedOutput string
		expectedTaint  []string
	}{
		{
			name:           "echo with github.event.comment.body",
			stepID:         "get-ref",
			script:         `echo "ref=${{ github.event.comment.body }}" >> $GITHUB_OUTPUT`,
			expectedOutput: "ref",
			expectedTaint:  []string{"github.event.comment.body"},
		},
		{
			name:           "echo with github.head_ref",
			stepID:         "comment-branch",
			script:         `echo "head_ref=${{ github.head_ref }}" >> $GITHUB_OUTPUT`,
			expectedOutput: "head_ref",
			expectedTaint:  []string{"github.head_ref"},
		},
		{
			name:           "echo with github.event.issue.title",
			stepID:         "extract-data",
			script:         `echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT`,
			expectedOutput: "title",
			expectedTaint:  []string{"github.event.issue.title"},
		},
		{
			name:           "multiple outputs in single script",
			stepID:         "multi-output",
			script:         "echo \"title=${{ github.event.issue.title }}\" >> $GITHUB_OUTPUT\necho \"body=${{ github.event.issue.body }}\" >> $GITHUB_OUTPUT",
			expectedOutput: "title", // First output
			expectedTaint:  []string{"github.event.issue.title"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tracker := NewTaintTracker()

			step := &ast.Step{
				ID: &ast.String{Value: tt.stepID},
				Exec: &ast.ExecRun{
					Run: &ast.String{Value: tt.script},
				},
			}

			tracker.AnalyzeStep(step)

			// Check if output is tracked as tainted
			outputs, exists := tracker.taintedOutputs[tt.stepID]
			if !exists {
				t.Fatalf("step %s should have tainted outputs", tt.stepID)
			}

			sources, outputExists := outputs[tt.expectedOutput]
			if !outputExists {
				t.Fatalf("output %s should be tainted", tt.expectedOutput)
			}

			if len(sources) == 0 {
				t.Errorf("taint sources should not be empty")
			}

			// Check if expected taint source is present
			found := false
			for _, source := range sources {
				for _, expected := range tt.expectedTaint {
					if source == expected {
						found = true
						break
					}
				}
			}
			if !found {
				t.Errorf("expected taint source %v not found in %v", tt.expectedTaint, sources)
			}
		})
	}
}

func TestTaintTracker_AnalyzeStep_SafeOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		stepID string
		script string
	}{
		{
			name:   "github.sha is safe",
			stepID: "get-sha",
			script: `echo "sha=${{ github.sha }}" >> $GITHUB_OUTPUT`,
		},
		{
			name:   "static value is safe",
			stepID: "get-version",
			script: `echo "version=1.2.3" >> $GITHUB_OUTPUT`,
		},
		{
			name:   "github.repository is safe",
			stepID: "get-repo",
			script: `echo "repo=${{ github.repository }}" >> $GITHUB_OUTPUT`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tracker := NewTaintTracker()

			step := &ast.Step{
				ID: &ast.String{Value: tt.stepID},
				Exec: &ast.ExecRun{
					Run: &ast.String{Value: tt.script},
				},
			}

			tracker.AnalyzeStep(step)

			// Safe outputs should not be tracked as tainted
			if outputs, exists := tracker.taintedOutputs[tt.stepID]; exists {
				for outputName := range outputs {
					t.Errorf("output %s should not be tainted for safe input", outputName)
				}
			}
		})
	}
}

func TestTaintTracker_IsTainted(t *testing.T) {
	t.Parallel()

	tracker := NewTaintTracker()

	// Manually add tainted output for testing
	tracker.taintedOutputs["get-ref"] = map[string][]string{
		"ref": {"github.event.comment.body"},
	}
	tracker.taintedOutputs["extract-data"] = map[string][]string{
		"title": {"github.event.issue.title"},
		"body":  {"github.event.issue.body"},
	}

	tests := []struct {
		name            string
		exprStr         string
		expectTainted   bool
		expectedSources []string
	}{
		{
			name:            "tainted step output reference",
			exprStr:         "steps.get-ref.outputs.ref",
			expectTainted:   true,
			expectedSources: []string{"github.event.comment.body"},
		},
		{
			name:            "tainted step output with different output name",
			exprStr:         "steps.extract-data.outputs.title",
			expectTainted:   true,
			expectedSources: []string{"github.event.issue.title"},
		},
		{
			name:          "non-tainted step output",
			exprStr:       "steps.unknown-step.outputs.value",
			expectTainted: false,
		},
		{
			name:          "non-step expression",
			exprStr:       "github.sha",
			expectTainted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tainted, sources := tracker.IsTaintedExpr(tt.exprStr)

			if tainted != tt.expectTainted {
				t.Errorf("IsTainted(%s) = %v, want %v", tt.exprStr, tainted, tt.expectTainted)
			}

			if tt.expectTainted && len(sources) == 0 {
				t.Errorf("expected sources for tainted expression, got none")
			}

			if tt.expectTainted {
				for _, expected := range tt.expectedSources {
					found := false
					for _, source := range sources {
						if source == expected {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected source %s not found in %v", expected, sources)
					}
				}
			}
		})
	}
}

func TestTaintTracker_HeredocPattern(t *testing.T) {
	t.Parallel()

	tracker := NewTaintTracker()

	step := &ast.Step{
		ID: &ast.String{Value: "get-data"},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: `cat <<EOF >> $GITHUB_OUTPUT
user_input=${{ github.event.comment.body }}
EOF`},
		},
	}

	tracker.AnalyzeStep(step)

	outputs, exists := tracker.taintedOutputs["get-data"]
	if !exists {
		t.Fatal("step get-data should have tainted outputs")
	}

	if _, outputExists := outputs["user_input"]; !outputExists {
		t.Error("output user_input should be tainted")
	}
}

func TestTaintTracker_VariablePropagation(t *testing.T) {
	t.Parallel()

	tracker := NewTaintTracker()

	// Pattern: INPUT="${{ untrusted }}" then echo "output=$INPUT" >> $GITHUB_OUTPUT
	step := &ast.Step{
		ID: &ast.String{Value: "process"},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: `INPUT="${{ github.event.issue.title }}"
echo "processed=$INPUT" >> $GITHUB_OUTPUT`},
		},
	}

	tracker.AnalyzeStep(step)

	outputs, exists := tracker.taintedOutputs["process"]
	if !exists {
		t.Fatal("step process should have tainted outputs")
	}

	if _, outputExists := outputs["processed"]; !outputExists {
		t.Error("output processed should be tainted (via variable propagation)")
	}
}

func TestTaintTracker_NoStepID(t *testing.T) {
	t.Parallel()

	tracker := NewTaintTracker()

	// Step without ID should be skipped
	step := &ast.Step{
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: `echo "ref=${{ github.event.comment.body }}" >> $GITHUB_OUTPUT`},
		},
	}

	tracker.AnalyzeStep(step)

	if len(tracker.taintedOutputs) != 0 {
		t.Error("step without ID should not create tainted outputs")
	}
}

func TestTaintTracker_NonRunStep(t *testing.T) {
	t.Parallel()

	tracker := NewTaintTracker()

	// Unknown action step should not be marked as tainted
	step := &ast.Step{
		ID: &ast.String{Value: "checkout"},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
		},
	}

	tracker.AnalyzeStep(step)

	// Unknown actions should not create tainted outputs
	if len(tracker.taintedOutputs) != 0 {
		t.Error("unknown action step should not create tainted outputs")
	}
}

// Phase 2 Tests

func TestTaintTracker_StepOutputToStepOutput(t *testing.T) {
	t.Parallel()

	// Test Phase 2: step output to step output propagation
	// Step A writes untrusted input to output
	// Step B reads from Step A's output via env and writes to its own output
	// Step B's output should also be tainted

	tracker := NewTaintTracker()

	// Step A: Write untrusted input to output
	stepA := &ast.Step{
		ID: &ast.String{Value: "step-a"},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: `echo "val=${{ github.head_ref }}" >> $GITHUB_OUTPUT`},
		},
	}
	tracker.AnalyzeStep(stepA)

	// Verify Step A's output is tainted
	if outputs, exists := tracker.taintedOutputs["step-a"]; !exists {
		t.Fatal("step-a should have tainted outputs")
	} else if _, outputExists := outputs["val"]; !outputExists {
		t.Fatal("step-a output 'val' should be tainted")
	}

	// Step B: Read from Step A's output via env and write to own output
	stepB := &ast.Step{
		ID: &ast.String{Value: "step-b"},
		Env: &ast.Env{
			Vars: map[string]*ast.EnvVar{
				"input": {
					Name:  &ast.String{Value: "INPUT"},
					Value: &ast.String{Value: "${{ steps.step-a.outputs.val }}"},
				},
			},
		},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: `echo "derived=$INPUT" >> $GITHUB_OUTPUT`},
		},
	}
	tracker.AnalyzeStep(stepB)

	// Verify Step B's output is also tainted (via Step A)
	outputs, exists := tracker.taintedOutputs["step-b"]
	if !exists {
		t.Fatal("step-b should have tainted outputs (via step-a)")
	}

	sources, outputExists := outputs["derived"]
	if !outputExists {
		t.Fatal("step-b output 'derived' should be tainted")
	}

	// The taint source should trace back to the original untrusted input
	if len(sources) == 0 {
		t.Error("expected taint sources for step-b output")
	}
	t.Logf("Step B taint sources: %v", sources)
}

func TestTaintTracker_MultiHopPropagation(t *testing.T) {
	t.Parallel()

	// Test multi-hop propagation: A -> B -> C
	tracker := NewTaintTracker()

	// Step A: Write untrusted input
	stepA := &ast.Step{
		ID: &ast.String{Value: "step-a"},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: `echo "val=${{ github.event.comment.body }}" >> $GITHUB_OUTPUT`},
		},
	}
	tracker.AnalyzeStep(stepA)

	// Step B: Read from A, write to own output
	stepB := &ast.Step{
		ID: &ast.String{Value: "step-b"},
		Env: &ast.Env{
			Vars: map[string]*ast.EnvVar{
				"input_a": {
					Name:  &ast.String{Value: "INPUT_A"},
					Value: &ast.String{Value: "${{ steps.step-a.outputs.val }}"},
				},
			},
		},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: `echo "intermediate=$INPUT_A" >> $GITHUB_OUTPUT`},
		},
	}
	tracker.AnalyzeStep(stepB)

	// Step C: Read from B, write to own output
	stepC := &ast.Step{
		ID: &ast.String{Value: "step-c"},
		Env: &ast.Env{
			Vars: map[string]*ast.EnvVar{
				"input_b": {
					Name:  &ast.String{Value: "INPUT_B"},
					Value: &ast.String{Value: "${{ steps.step-b.outputs.intermediate }}"},
				},
			},
		},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: `echo "final=$INPUT_B" >> $GITHUB_OUTPUT`},
		},
	}
	tracker.AnalyzeStep(stepC)

	// Verify all three steps have tainted outputs
	for _, stepID := range []string{"step-a", "step-b", "step-c"} {
		if _, exists := tracker.taintedOutputs[stepID]; !exists {
			t.Errorf("step %s should have tainted outputs", stepID)
		}
	}

	// Verify step-c's output traces back to original source
	if outputs, exists := tracker.taintedOutputs["step-c"]; exists {
		if sources, outputExists := outputs["final"]; outputExists {
			t.Logf("Step C taint sources: %v", sources)
		} else {
			t.Error("step-c should have 'final' output tainted")
		}
	}
}

func TestTaintTracker_EnvVarFromTaintedStepOutput(t *testing.T) {
	t.Parallel()

	tracker := NewTaintTracker()

	// Pre-populate a tainted output (simulating a previous step)
	tracker.taintedOutputs["previous-step"] = map[string][]string{
		"user_data": {"github.event.issue.body"},
	}

	// Step that uses tainted output in env
	step := &ast.Step{
		ID: &ast.String{Value: "current-step"},
		Env: &ast.Env{
			Vars: map[string]*ast.EnvVar{
				"data": {
					Name:  &ast.String{Value: "DATA"},
					Value: &ast.String{Value: "${{ steps.previous-step.outputs.user_data }}"},
				},
			},
		},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: `echo "processed=$DATA" >> $GITHUB_OUTPUT`},
		},
	}
	tracker.AnalyzeStep(step)

	// Verify the output is tainted
	outputs, exists := tracker.taintedOutputs["current-step"]
	if !exists {
		t.Fatal("current-step should have tainted outputs")
	}

	sources, outputExists := outputs["processed"]
	if !outputExists {
		t.Fatal("output 'processed' should be tainted")
	}

	// Verify taint traces back to original source
	found := false
	for _, source := range sources {
		if source == "github.event.issue.body" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("taint should trace back to github.event.issue.body, got: %v", sources)
	}
}

// Phase 3 Tests

func TestTaintTracker_KnownTaintedAction(t *testing.T) {
	t.Parallel()

	tracker := NewTaintTracker()

	// Test gotson/pull-request-comment-branch action (GHSL-2024-325)
	step := &ast.Step{
		ID: &ast.String{Value: "comment-branch"},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "gotson/pull-request-comment-branch@v1"},
		},
	}
	tracker.AnalyzeStep(step)

	// Verify outputs are marked as tainted
	outputs, exists := tracker.taintedOutputs["comment-branch"]
	if !exists {
		t.Fatal("known tainted action should have tainted outputs")
	}

	// Check for expected tainted outputs
	expectedOutputs := []string{"head_ref", "head_sha", "base_ref", "base_sha"}
	for _, outputName := range expectedOutputs {
		if _, outputExists := outputs[outputName]; !outputExists {
			t.Errorf("output %s should be tainted for gotson/pull-request-comment-branch", outputName)
		}
	}

	t.Logf("Tainted outputs: %v", outputs)
}

func TestTaintTracker_KnownTaintedActionWithVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		uses       string
		expectTaint bool
	}{
		{
			name:       "action with v1 tag",
			uses:       "gotson/pull-request-comment-branch@v1",
			expectTaint: true,
		},
		{
			name:       "action with v2 tag",
			uses:       "gotson/pull-request-comment-branch@v2",
			expectTaint: true,
		},
		{
			name:       "action with main branch",
			uses:       "gotson/pull-request-comment-branch@main",
			expectTaint: true,
		},
		{
			name:       "action with commit SHA",
			uses:       "gotson/pull-request-comment-branch@abc1234567890",
			expectTaint: true,
		},
		{
			name:       "unknown action",
			uses:       "unknown/action@v1",
			expectTaint: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tracker := NewTaintTracker()
			step := &ast.Step{
				ID: &ast.String{Value: "test-step"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: tt.uses},
				},
			}
			tracker.AnalyzeStep(step)

			hasTaint := len(tracker.taintedOutputs["test-step"]) > 0
			if hasTaint != tt.expectTaint {
				t.Errorf("uses=%s: hasTaint=%v, want=%v", tt.uses, hasTaint, tt.expectTaint)
			}
		})
	}
}

func TestTaintTracker_KnownTaintedActionIntegration(t *testing.T) {
	t.Parallel()

	// Full integration test: action -> env -> run
	// This simulates the GHSL-2024-325 vulnerability pattern
	tracker := NewTaintTracker()

	// Step 1: Use gotson/pull-request-comment-branch
	step1 := &ast.Step{
		ID: &ast.String{Value: "comment-branch"},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "gotson/pull-request-comment-branch@v1"},
		},
	}
	tracker.AnalyzeStep(step1)

	// Step 2: Use the action's output in env
	step2 := &ast.Step{
		ID: &ast.String{Value: "push-step"},
		Env: &ast.Env{
			Vars: map[string]*ast.EnvVar{
				"branch_name": {
					Name:  &ast.String{Value: "BRANCH_NAME"},
					Value: &ast.String{Value: "${{ steps.comment-branch.outputs.head_ref }}"},
				},
			},
		},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: `git push origin HEAD:${BRANCH_NAME}`},
		},
	}
	tracker.AnalyzeStep(step2)

	// Verify the action's output is detected as tainted
	tainted, sources := tracker.IsTaintedExpr("steps.comment-branch.outputs.head_ref")
	if !tainted {
		t.Error("steps.comment-branch.outputs.head_ref should be tainted")
	}
	t.Logf("Taint sources for head_ref: %v", sources)
}
