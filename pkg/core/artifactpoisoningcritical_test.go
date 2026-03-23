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

func TestDetectRunnerOS(t *testing.T) {
	tests := []struct {
		name   string
		runner *ast.Runner
		wantOS string
	}{
		// nil runner
		{name: "nil runner", runner: nil, wantOS: "unknown"},
		// expression (e.g. ${{ matrix.os }})
		{
			name: "expression label",
			runner: &ast.Runner{
				LabelsExpr: &ast.String{Value: "${{ matrix.os }}"},
			},
			wantOS: "unknown",
		},
		// plain scalar stored in LabelsExpr by the parser (no ${{ }})
		{
			name:   "LabelsExpr ubuntu-latest plain string",
			runner: &ast.Runner{LabelsExpr: &ast.String{Value: "ubuntu-latest"}},
			wantOS: "linux",
		},
		{
			name:   "LabelsExpr windows-latest plain string",
			runner: &ast.Runner{LabelsExpr: &ast.String{Value: "windows-latest"}},
			wantOS: "windows",
		},
		{
			name:   "LabelsExpr macos-latest plain string",
			runner: &ast.Runner{LabelsExpr: &ast.String{Value: "macos-latest"}},
			wantOS: "macos",
		},
		{
			name:   "LabelsExpr unknown plain string",
			runner: &ast.Runner{LabelsExpr: &ast.String{Value: "some-custom-runner"}},
			wantOS: "unknown",
		},
		// Linux
		{
			name:   "ubuntu-latest",
			runner: &ast.Runner{Labels: []*ast.String{{Value: "ubuntu-latest"}}},
			wantOS: "linux",
		},
		{
			name:   "ubuntu-22.04",
			runner: &ast.Runner{Labels: []*ast.String{{Value: "ubuntu-22.04"}}},
			wantOS: "linux",
		},
		{
			name:   "linux label",
			runner: &ast.Runner{Labels: []*ast.String{{Value: "linux"}}},
			wantOS: "linux",
		},
		{
			name: "self-hosted linux array",
			runner: &ast.Runner{Labels: []*ast.String{
				{Value: "self-hosted"},
				{Value: "linux"},
			}},
			wantOS: "linux",
		},
		// Windows
		{
			name:   "windows-latest",
			runner: &ast.Runner{Labels: []*ast.String{{Value: "windows-latest"}}},
			wantOS: "windows",
		},
		{
			name:   "windows-2022",
			runner: &ast.Runner{Labels: []*ast.String{{Value: "windows-2022"}}},
			wantOS: "windows",
		},
		{
			name:   "windows label",
			runner: &ast.Runner{Labels: []*ast.String{{Value: "windows"}}},
			wantOS: "windows",
		},
		// macOS
		{
			name:   "macos-latest",
			runner: &ast.Runner{Labels: []*ast.String{{Value: "macos-latest"}}},
			wantOS: "macos",
		},
		{
			name:   "macos-14",
			runner: &ast.Runner{Labels: []*ast.String{{Value: "macos-14"}}},
			wantOS: "macos",
		},
		{
			name:   "macos label",
			runner: &ast.Runner{Labels: []*ast.String{{Value: "macos"}}},
			wantOS: "macos",
		},
		{
			name:   "mac label",
			runner: &ast.Runner{Labels: []*ast.String{{Value: "mac"}}},
			wantOS: "macos",
		},
		// mixed case - strings.ToLower + EqualFold should handle these
		{
			name:   "mixed case Ubuntu-Latest",
			runner: &ast.Runner{Labels: []*ast.String{{Value: "Ubuntu-Latest"}}},
			wantOS: "linux",
		},
		{
			name:   "uppercase WINDOWS-2022",
			runner: &ast.Runner{Labels: []*ast.String{{Value: "WINDOWS-2022"}}},
			wantOS: "windows",
		},
		{
			name:   "mixed case MacOS-Latest",
			runner: &ast.Runner{Labels: []*ast.String{{Value: "MacOS-Latest"}}},
			wantOS: "macos",
		},
		// bare distro names (no version suffix)
		{
			name:   "bare ubuntu label",
			runner: &ast.Runner{Labels: []*ast.String{{Value: "ubuntu"}}},
			wantOS: "linux",
		},
		{
			name:   "bare Ubuntu label (uppercase)",
			runner: &ast.Runner{Labels: []*ast.String{{Value: "Ubuntu"}}},
			wantOS: "linux",
		},
		// unknown
		{
			name:   "self-hosted only",
			runner: &ast.Runner{Labels: []*ast.String{{Value: "self-hosted"}}},
			wantOS: "unknown",
		},
		{
			name:   "empty labels",
			runner: &ast.Runner{Labels: []*ast.String{}},
			wantOS: "unknown",
		},
		{
			name:   "nil label element",
			runner: &ast.Runner{Labels: []*ast.String{nil, {Value: "ubuntu-latest"}}},
			wantOS: "linux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectRunnerOS(tt.runner)
			if got != tt.wantOS {
				t.Errorf("detectRunnerOS() = %q, want %q", got, tt.wantOS)
			}
		})
	}
}

func TestIsUnsafePath(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		runnerOS   string
		wantUnsafe bool
	}{
		// Unsafe paths (OS-independent)
		{name: "empty path", path: "", runnerOS: "linux", wantUnsafe: true},
		{name: "whitespace only", path: "   ", runnerOS: "linux", wantUnsafe: true},
		{name: "current directory", path: ".", runnerOS: "linux", wantUnsafe: true},
		{name: "current directory with slash", path: "./", runnerOS: "linux", wantUnsafe: true},
		{name: "relative path", path: "./artifacts", runnerOS: "linux", wantUnsafe: true},
		{name: "parent relative path", path: "../artifacts", runnerOS: "linux", wantUnsafe: true},
		{name: "github.workspace", path: "${{ github.workspace }}/artifacts", runnerOS: "linux", wantUnsafe: true},
		{name: "GITHUB_WORKSPACE env", path: "$GITHUB_WORKSPACE/artifacts", runnerOS: "linux", wantUnsafe: true},
		{name: "simple directory name", path: "artifacts", runnerOS: "linux", wantUnsafe: true},
		{name: "nested directory", path: "build/artifacts", runnerOS: "linux", wantUnsafe: true},

		// Safe paths - runner.temp (OS-independent)
		{name: "runner.temp basic", path: "${{ runner.temp }}/artifacts", runnerOS: "linux", wantUnsafe: false},
		{name: "runner.temp nested", path: "${{ runner.temp }}/build/artifacts", runnerOS: "linux", wantUnsafe: false},
		{name: "RUNNER_TEMP env var", path: "$RUNNER_TEMP/artifacts", runnerOS: "linux", wantUnsafe: false},
		{name: "RUNNER_TEMP nested", path: "$RUNNER_TEMP/build/artifacts", runnerOS: "linux", wantUnsafe: false},
		{name: "runner.temp with spaces", path: "  ${{ runner.temp }}/artifacts  ", runnerOS: "linux", wantUnsafe: false},
		{name: "runner.temp on windows", path: "${{ runner.temp }}/artifacts", runnerOS: "windows", wantUnsafe: false},
		{name: "runner.temp on unknown", path: "${{ runner.temp }}/artifacts", runnerOS: "unknown", wantUnsafe: false},
		// runner.temp strict matching - path traversal and similar-named vars are unsafe
		{name: "runner.temp path traversal", path: "${{ runner.temp }}/../_work/repo", runnerOS: "linux", wantUnsafe: true},
		{name: "runner.tempDir is not runner.temp", path: "${{ runner.tempDir }}/artifacts", runnerOS: "linux", wantUnsafe: true},
		{name: "RUNNER_TEMP path traversal", path: "$RUNNER_TEMP/../_work/repo", runnerOS: "linux", wantUnsafe: true},

		// /tmp - safe on linux/macos/unknown, unsafe on windows
		{name: "/tmp on linux", path: "/tmp/artifacts", runnerOS: "linux", wantUnsafe: false},
		{name: "/tmp root on linux", path: "/tmp", runnerOS: "linux", wantUnsafe: false},
		{name: "/tmp nested on linux", path: "/tmp/build/artifacts", runnerOS: "linux", wantUnsafe: false},
		{name: "/tmp on macos", path: "/tmp/artifacts", runnerOS: "macos", wantUnsafe: false},
		{name: "/tmp on unknown", path: "/tmp/artifacts", runnerOS: "unknown", wantUnsafe: false},
		{name: "/tmp on windows", path: "/tmp/artifacts", runnerOS: "windows", wantUnsafe: true},

		// Unix absolute paths (/var etc) - safe on linux/macos, unsafe on windows/unknown
		{name: "/var on linux", path: "/var/temp/artifacts", runnerOS: "linux", wantUnsafe: false},
		{name: "/var/folders on macos", path: "/var/folders/tmp/artifacts", runnerOS: "macos", wantUnsafe: false},
		{name: "/home on linux", path: "/home/runner/artifacts", runnerOS: "linux", wantUnsafe: true}, // workspace path on GitHub-hosted runners
		{name: "/var on unknown", path: "/var/temp/artifacts", runnerOS: "unknown", wantUnsafe: true},
		{name: "/home on unknown", path: "/home/runner/artifacts", runnerOS: "unknown", wantUnsafe: true},
		{name: "/var on windows", path: "/var/temp/artifacts", runnerOS: "windows", wantUnsafe: true},

		// Windows absolute paths - always unsafe: drive-rooted paths can point into
		// the workspace (e.g. C:\actions-runner\_work\...) on Windows runners too.
		// Use ${{ runner.temp }} instead.
		{name: "Windows C drive backslash on windows", path: `C:\Temp\artifacts`, runnerOS: "windows", wantUnsafe: true},
		{name: "Windows C drive forward slash on windows", path: "C:/Temp/artifacts", runnerOS: "windows", wantUnsafe: true},
		{name: "Windows D drive on windows", path: `D:\temp\build`, runnerOS: "windows", wantUnsafe: true},
		{name: "Windows lowercase c on windows", path: `c:\temp`, runnerOS: "windows", wantUnsafe: true},
		{name: "Windows Z drive on windows", path: `Z:\artifacts`, runnerOS: "windows", wantUnsafe: true},
		{name: "Windows C drive on linux", path: `C:\Temp\artifacts`, runnerOS: "linux", wantUnsafe: true},
		{name: "Windows C drive on macos", path: "C:/Temp/artifacts", runnerOS: "macos", wantUnsafe: true},
		{name: "Windows C drive on unknown", path: `C:\Temp\artifacts`, runnerOS: "unknown", wantUnsafe: true},
		{name: "Windows workspace path on windows", path: `C:\actions-runner\_work\repo\artifacts`, runnerOS: "windows", wantUnsafe: true},

		// Unix path traversal - must be rejected even with allowed prefix
		{name: "/tmp traversal to workspace", path: "/tmp/../home/runner/work/repo", runnerOS: "linux", wantUnsafe: true},
		{name: "/var traversal to workspace", path: "/var/../home/runner/work/repo", runnerOS: "linux", wantUnsafe: true},
		{name: "/tmp traversal on unknown", path: "/tmp/../etc/passwd", runnerOS: "unknown", wantUnsafe: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUnsafePath(tt.path, tt.runnerOS)
			if got != tt.wantUnsafe {
				t.Errorf("isUnsafePath(%q, %q) = %v, want %v", tt.path, tt.runnerOS, got, tt.wantUnsafe)
			}
		})
	}
}

func TestArtifactPoisoning_VisitStep(t *testing.T) {
	tests := []struct {
		name       string
		runsOn     *ast.Runner
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
		{
			name:   "Windows path on windows runner - should error (workspace-unsafe)",
			runsOn: &ast.Runner{Labels: []*ast.String{{Value: "windows-latest"}}},
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: `C:\Temp\artifacts`},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name:   "Windows path on linux runner - should error",
			runsOn: &ast.Runner{Labels: []*ast.String{{Value: "ubuntu-latest"}}},
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: `C:\Temp\artifacts`},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name:   "/var path on linux runner - no error",
			runsOn: &ast.Runner{Labels: []*ast.String{{Value: "ubuntu-latest"}}},
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "/var/tmp/artifacts"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0,
		},
		{
			name:   "/var path on unknown runner - should error",
			runsOn: nil,
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "/var/tmp/artifacts"},
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
				RunsOn: tt.runsOn,
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
		{
			name: "whitespace-only path creates error and autofixer",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "   "},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors:     1,
			wantAutoFixers: 1,
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
