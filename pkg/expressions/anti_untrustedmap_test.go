package expressions

import (
	"testing"
)

func TestCreateUntrustedInputsWithTaintedReusableWorkflowInputs(t *testing.T) {
	tests := []struct {
		name           string
		taintedInputs  []string
		wantInputsRoot bool
		wantChildren   []string
	}{
		{
			name:           "no tainted inputs",
			taintedInputs:  []string{},
			wantInputsRoot: false,
			wantChildren:   nil,
		},
		{
			name:           "single tainted input",
			taintedInputs:  []string{"title"},
			wantInputsRoot: true,
			wantChildren:   []string{"title"},
		},
		{
			name:           "multiple tainted inputs",
			taintedInputs:  []string{"title", "body", "ref"},
			wantInputsRoot: true,
			wantChildren:   []string{"title", "body", "ref"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roots := CreateUntrustedInputsWithTaintedReusableWorkflowInputs(tt.taintedInputs)

			// Check that github root is still present
			if _, ok := roots["github"]; !ok {
				t.Error("github root should still be present")
			}

			// Check inputs root
			inputsRoot, hasInputs := roots["inputs"]
			if tt.wantInputsRoot != hasInputs {
				t.Errorf("inputs root presence = %v, want %v", hasInputs, tt.wantInputsRoot)
			}

			if hasInputs && inputsRoot != nil {
				for _, child := range tt.wantChildren {
					if _, ok := inputsRoot.Children[child]; !ok {
						t.Errorf("inputs root should have child %q", child)
					}
				}
				if len(inputsRoot.Children) != len(tt.wantChildren) {
					t.Errorf("inputs root has %d children, want %d", len(inputsRoot.Children), len(tt.wantChildren))
				}
			}
		})
	}
}

func TestCreateUntrustedInputsForReusableWorkflow(t *testing.T) {
	tests := []struct {
		name         string
		inputNames   []string
		wantWildcard bool
		wantChildren []string
	}{
		{
			name:         "no input names - should use wildcard",
			inputNames:   []string{},
			wantWildcard: true,
			wantChildren: nil,
		},
		{
			name:         "nil input names - should use wildcard",
			inputNames:   nil,
			wantWildcard: true,
			wantChildren: nil,
		},
		{
			name:         "single input name",
			inputNames:   []string{"message"},
			wantWildcard: false,
			wantChildren: []string{"message"},
		},
		{
			name:         "multiple input names",
			inputNames:   []string{"title", "body", "environment"},
			wantWildcard: false,
			wantChildren: []string{"title", "body", "environment"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roots := CreateUntrustedInputsForReusableWorkflow(tt.inputNames)

			// Check that github root is still present
			if _, ok := roots["github"]; !ok {
				t.Error("github root should still be present")
			}

			// Check inputs root
			inputsRoot, hasInputs := roots["inputs"]
			if !hasInputs {
				t.Error("inputs root should be present")
				return
			}

			if tt.wantWildcard {
				if _, ok := inputsRoot.Children["*"]; !ok {
					t.Error("inputs root should have wildcard child")
				}
			} else {
				for _, child := range tt.wantChildren {
					if _, ok := inputsRoot.Children[child]; !ok {
						t.Errorf("inputs root should have child %q", child)
					}
				}
				if len(inputsRoot.Children) != len(tt.wantChildren) {
					t.Errorf("inputs root has %d children, want %d", len(inputsRoot.Children), len(tt.wantChildren))
				}
			}
		})
	}
}

func TestContextPropertyMap_String(t *testing.T) {
	tests := []struct {
		name string
		m    *ContextPropertyMap
		want string
	}{
		{
			name: "simple root",
			m:    NewContextPropertyMap("github"),
			want: "github",
		},
		{
			name: "nested property",
			m: func() *ContextPropertyMap {
				root := NewContextPropertyMap("github",
					NewContextPropertyMap("event",
						NewContextPropertyMap("pull_request"),
					),
				)
				return root.Children["event"].Children["pull_request"]
			}(),
			want: "github.event.pull_request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.m.String(); got != tt.want {
				t.Errorf("ContextPropertyMap.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
