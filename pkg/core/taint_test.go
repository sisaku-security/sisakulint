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

	// Action step (not run:) should be handled differently
	step := &ast.Step{
		ID: &ast.String{Value: "checkout"},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
		},
	}

	tracker.AnalyzeStep(step)

	// Action steps don't write to $GITHUB_OUTPUT directly in Phase 1
	if len(tracker.taintedOutputs) != 0 {
		t.Error("action step should not create tainted outputs in Phase 1")
	}
}
