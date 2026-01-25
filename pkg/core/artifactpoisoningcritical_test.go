package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// TestArtifactPoisoningRule tests the ArtifactPoisoningRule constructor function.
func TestArtifactPoisoningRule(t *testing.T) {
	rule := ArtifactPoisoningRule()

	if rule.RuleName != "artifact-poisoning-critical" {
		t.Errorf("Expected RuleName to be 'artifact-poisoning-critical', got '%s'", rule.RuleName)
	}

	expectedDesc := "Detects unsafe artifact downloads that may allow artifact poisoning attacks. Artifacts should be extracted to a temporary folder to prevent overwriting existing files and should be treated as untrusted content."
	if rule.RuleDesc != expectedDesc {
		t.Errorf("Expected RuleDesc to be '%s', got '%s'", expectedDesc, rule.RuleDesc)
	}
}

// TestIsUnsafePath tests the isUnsafePath function with various path inputs
func TestIsUnsafePath(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantUnsafe bool
	}{
		// Unsafe paths
		{name: "empty path", path: "", wantUnsafe: true},
		{name: "whitespace only", path: "   ", wantUnsafe: true},
		{name: "current directory", path: ".", wantUnsafe: true},
		{name: "current directory with slash", path: "./", wantUnsafe: true},
		{name: "relative path", path: "./artifacts", wantUnsafe: true},
		{name: "parent relative path", path: "../artifacts", wantUnsafe: true},
		{name: "github.workspace", path: "${{ github.workspace }}/artifacts", wantUnsafe: true},
		{name: "GITHUB_WORKSPACE env", path: "$GITHUB_WORKSPACE/artifacts", wantUnsafe: true},
		{name: "simple directory name", path: "artifacts", wantUnsafe: true},
		{name: "nested directory", path: "build/artifacts", wantUnsafe: true},

		// Safe paths - runner.temp (cross-platform recommended)
		{name: "runner.temp basic", path: "${{ runner.temp }}/artifacts", wantUnsafe: false},
		{name: "runner.temp nested", path: "${{ runner.temp }}/build/artifacts", wantUnsafe: false},
		{name: "RUNNER_TEMP env var", path: "$RUNNER_TEMP/artifacts", wantUnsafe: false},
		{name: "RUNNER_TEMP nested", path: "$RUNNER_TEMP/build/artifacts", wantUnsafe: false},
		{name: "runner.temp with spaces", path: "  ${{ runner.temp }}/artifacts  ", wantUnsafe: false},

		// Safe paths - /tmp only (system temporary directory)
		{name: "/tmp absolute path", path: "/tmp/artifacts", wantUnsafe: false},
		{name: "/tmp root", path: "/tmp", wantUnsafe: false},
		{name: "/tmp with nested dirs", path: "/tmp/build/artifacts", wantUnsafe: false},

		// Unsafe paths - other absolute paths (too broad without OS context)
		{name: "/var absolute path", path: "/var/temp/artifacts", wantUnsafe: true},
		{name: "/var/folders macOS", path: "/var/folders/tmp/artifacts", wantUnsafe: true},
		{name: "/home absolute path", path: "/home/runner/artifacts", wantUnsafe: true},
		{name: "workspace-like absolute path", path: "/home/runner/work/repo/artifacts", wantUnsafe: true},

		// Unsafe paths - Windows absolute paths (cannot validate safely without OS context)
		{name: "Windows C drive backslash", path: "C:\\Temp\\artifacts", wantUnsafe: true},
		{name: "Windows C drive forward slash", path: "C:/Temp/artifacts", wantUnsafe: true},
		{name: "Windows D drive backslash", path: "D:\\temp\\build", wantUnsafe: true},
		{name: "Windows D drive forward slash", path: "D:/temp/build", wantUnsafe: true},
		{name: "Windows lowercase c drive", path: "c:\\temp", wantUnsafe: true},
		{name: "Windows lowercase d drive", path: "d:/temp", wantUnsafe: true},
		{name: "Windows Z drive", path: "Z:\\artifacts", wantUnsafe: true},
		{name: "Windows workspace-like path", path: "C:\\actions-runner\\_work\\repo\\artifacts", wantUnsafe: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUnsafePath(tt.path)
			if got != tt.wantUnsafe {
				t.Errorf("isUnsafePath(%q) = %v, want %v", tt.path, got, tt.wantUnsafe)
			}
		})
	}
}

func TestArtifactPoisoning_VisitStep(t *testing.T) {
	tests := []struct {
		name       string
		step       *ast.Step
		wantErrors int
	}{
		{
			name: "download-artifact without path - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "download-artifact with nil inputs - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: nil,
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "download-artifact with empty path - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: ""},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "download-artifact with safe path - no error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "${{ runner.temp }}/artifacts"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0,
		},
		{
			name: "download-artifact with current directory path - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "."},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "download-artifact with current directory slash path - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "./"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "download-artifact with relative path - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "./artifacts"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "download-artifact with parent relative path - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "../artifacts"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "download-artifact with github.workspace path - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "${{ github.workspace }}/artifacts"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "download-artifact with GITHUB_WORKSPACE env var - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "$GITHUB_WORKSPACE/artifacts"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "download-artifact with /tmp path - no error (safe absolute path)",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "/tmp/artifacts"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0,
		},
		{
			name: "download-artifact with RUNNER_TEMP env var - no error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "$RUNNER_TEMP/artifacts"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0,
		},
		{
			name: "download-artifact with whitespace path - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "  "},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "download-artifact v3 without path - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/download-artifact@v3"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "non-download-artifact action - no error",
			step: &ast.Step{
				ID: &ast.String{Value: "checkout"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/checkout@v4"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0,
		},
		{
			name: "upload-artifact action - no error",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/upload-artifact@v4"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0,
		},
		{
			name: "run step - no error",
			step: &ast.Step{
				ID: &ast.String{Value: "test"},
				Exec: &ast.ExecRun{
					Run: &ast.String{Value: "echo test"},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0,
		},
		{
			name: "download-artifact with commit SHA without path - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/download-artifact@6b208ae046db98c579e8a3aa621ab581ff575935"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "download-artifact with name input but no path - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"name": {
							Name:  &ast.String{Value: "name"},
							Value: &ast.String{Value: "my-artifact"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ArtifactPoisoningRule()

			// Simulate a job with checkout to enable artifact poisoning detection
			jobWithCheckout := &ast.Job{
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecAction{
							Uses: &ast.String{Value: "actions/checkout@v4"},
						},
					},
					tt.step,
				},
			}

			// Initialize job context
			err := rule.VisitJobPre(jobWithCheckout)
			if err != nil {
				t.Fatalf("VisitJobPre() unexpected error: %v", err)
			}

			err = rule.VisitStep(tt.step)
			if err != nil {
				t.Errorf("VisitStep() unexpected error: %v", err)
			}

			errors := rule.Errors()
			if len(errors) != tt.wantErrors {
				t.Errorf("VisitStep() got %d errors, want %d errors", len(errors), tt.wantErrors)
				for i, e := range errors {
					t.Logf("Error %d: %s", i, e.Description)
				}
			}
		})
	}
}

// TestArtifactPoisoning_JobWithoutCheckout tests that the rule does not flag
// artifact downloads in jobs that don't check out the repository (false positive fix).
func TestArtifactPoisoning_JobWithoutCheckout(t *testing.T) {
	rule := ArtifactPoisoningRule()

	// Job without checkout step (e.g., publish job)
	downloadStep := &ast.Step{
		ID: &ast.String{Value: "download"},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/download-artifact@v4"},
			Inputs: map[string]*ast.Input{
				"path": {
					Name:  &ast.String{Value: "path"},
					Value: &ast.String{Value: "dist/"}, // Workspace path, but job has no checkout
				},
			},
		},
		Pos: &ast.Position{Line: 10, Col: 5},
	}

	jobWithoutCheckout := &ast.Job{
		Steps: []*ast.Step{
			downloadStep,
			{
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "pypa/gh-action-pypi-publish@release/v1"},
				},
			},
		},
	}

	// Initialize job context (no checkout)
	err := rule.VisitJobPre(jobWithoutCheckout)
	if err != nil {
		t.Fatalf("VisitJobPre() unexpected error: %v", err)
	}

	// Should not trigger error because job has no checkout
	err = rule.VisitStep(downloadStep)
	if err != nil {
		t.Errorf("VisitStep() unexpected error: %v", err)
	}

	errors := rule.Errors()
	if len(errors) != 0 {
		t.Errorf("VisitStep() for job without checkout got %d errors, want 0 errors. This is a false positive.", len(errors))
		for i, e := range errors {
			t.Logf("Error %d: %s", i, e.Description)
		}
	}
}

func TestArtifactPoisoning_FixStep(t *testing.T) {
	tests := []struct {
		name      string
		step      *ast.Step
		wantPath  string
		wantError bool
	}{
		{
			name: "fix step without inputs",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: nil,
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantPath:  "${{ runner.temp }}/artifacts",
			wantError: false,
		},
		{
			name: "fix step with empty inputs",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantPath:  "${{ runner.temp }}/artifacts",
			wantError: false,
		},
		{
			name: "fix step with existing inputs",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"name": {
							Name:  &ast.String{Value: "name"},
							Value: &ast.String{Value: "my-artifact"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantPath:  "${{ runner.temp }}/artifacts",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ArtifactPoisoningRule()
			err := rule.FixStep(tt.step)

			if (err != nil) != tt.wantError {
				t.Errorf("FixStep() error = %v, wantError %v", err, tt.wantError)
				return
			}

			action := tt.step.Exec.(*ast.ExecAction)
			if action.Inputs == nil {
				t.Fatal("FixStep() did not initialize Inputs map")
			}

			pathInput, ok := action.Inputs["path"]
			if !ok {
				t.Fatal("FixStep() did not add path input")
			}

			if pathInput.Value.Value != tt.wantPath {
				t.Errorf("FixStep() path = %v, want %v", pathInput.Value.Value, tt.wantPath)
			}

			if pathInput.Name.Value != "path" {
				t.Errorf("FixStep() path name = %v, want 'path'", pathInput.Name.Value)
			}
		})
	}
}

func TestArtifactPoisoning_Integration(t *testing.T) {
	tests := []struct {
		name           string
		step           *ast.Step
		wantErrors     int
		wantAutoFixers int
	}{
		{
			name: "missing path creates error and autofixer",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors:     1,
			wantAutoFixers: 1,
		},
		{
			name: "safe download creates no error or autofixer",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "${{ runner.temp }}/artifacts"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors:     0,
			wantAutoFixers: 0,
		},
		{
			name: "unsafe path (current dir) creates error but NO autofixer",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "."},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors:     1,
			wantAutoFixers: 0, // No auto-fix for existing unsafe paths
		},
		{
			name: "unsafe path (relative) creates error but NO autofixer",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "./artifacts"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors:     1,
			wantAutoFixers: 0, // No auto-fix for existing unsafe paths
		},
		{
			name: "unsafe path (workspace) creates error but NO autofixer",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "${{ github.workspace }}/artifacts"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors:     1,
			wantAutoFixers: 0, // No auto-fix for existing unsafe paths
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ArtifactPoisoningRule()

			// Simulate a job with checkout to enable artifact poisoning detection
			jobWithCheckout := &ast.Job{
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecAction{
							Uses: &ast.String{Value: "actions/checkout@v4"},
						},
					},
					tt.step,
				},
			}

			// Initialize job context
			err := rule.VisitJobPre(jobWithCheckout)
			if err != nil {
				t.Fatalf("VisitJobPre() unexpected error: %v", err)
			}

			err = rule.VisitStep(tt.step)
			if err != nil {
				t.Errorf("VisitStep() unexpected error: %v", err)
			}

			errors := rule.Errors()
			if len(errors) != tt.wantErrors {
				t.Errorf("VisitStep() got %d errors, want %d errors", len(errors), tt.wantErrors)
			}

			autoFixers := rule.AutoFixers()
			if len(autoFixers) != tt.wantAutoFixers {
				t.Errorf("VisitStep() got %d autofixers, want %d autofixers", len(autoFixers), tt.wantAutoFixers)
			}

			// If we have autofixers, apply them and verify
			if len(autoFixers) > 0 {
				for _, fixer := range autoFixers {
					if err := fixer.Fix(); err != nil {
						t.Errorf("AutoFixer.Fix() error = %v", err)
					}
				}

				// Verify the fix was applied
				action := tt.step.Exec.(*ast.ExecAction)
				if action.Inputs["path"] == nil {
					t.Error("AutoFixer did not add path input")
				} else if action.Inputs["path"].Value.Value != "${{ runner.temp }}/artifacts" {
					t.Errorf("AutoFixer path = %v, want '${{ runner.temp }}/artifacts'", action.Inputs["path"].Value.Value)
				}
			}
		})
	}
}
