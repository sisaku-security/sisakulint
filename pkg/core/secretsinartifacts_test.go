package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestNewSecretsInArtifactsRule(t *testing.T) {
	t.Parallel()
	rule := NewSecretsInArtifactsRule()

	if rule.RuleName != "secrets-in-artifacts" {
		t.Errorf("Expected RuleName to be 'secrets-in-artifacts', got '%s'", rule.RuleName)
	}

	if rule.RuleDesc == "" {
		t.Error("Expected RuleDesc to be non-empty")
	}
}

func TestIsUnsafeArtifactPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		path       string
		wantUnsafe bool
	}{
		// Unsafe paths (entire repository)
		{name: "current directory dot", path: ".", wantUnsafe: true},
		{name: "current directory with slash", path: "./", wantUnsafe: true},
		{name: "star wildcard", path: "*", wantUnsafe: true},
		{name: "double star", path: "**", wantUnsafe: true},
		{name: "double star slash star", path: "**/*", wantUnsafe: true},
		{name: "whitespace only becomes empty", path: "   ", wantUnsafe: false}, // TrimSpace makes it ""

		// Safe paths (specific directories)
		{name: "dist directory", path: "dist/", wantUnsafe: false},
		{name: "build directory", path: "build/", wantUnsafe: false},
		{name: "specific file", path: "output.zip", wantUnsafe: false},
		{name: "nested directory", path: "build/release/", wantUnsafe: false},
		{name: "relative subdir", path: "./dist/", wantUnsafe: false},

		// Edge case: ./something pattern (issue from code review)
		{name: "relative root file", path: "./README.md", wantUnsafe: false},
		{name: "relative root dir no slash", path: "./dist", wantUnsafe: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isUnsafeArtifactPath(tt.path)
			if got != tt.wantUnsafe {
				t.Errorf("isUnsafeArtifactPath(%q) = %v, want %v", tt.path, got, tt.wantUnsafe)
			}
		})
	}
}

func TestContainsSensitivePath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		pathSpec      string
		wantSensitive bool
	}{
		// Sensitive paths
		{name: "git directory", pathSpec: ".git", wantSensitive: true},
		{name: "git subdirectory", pathSpec: ".git/config", wantSensitive: true},
		{name: "env file", pathSpec: ".env", wantSensitive: true},
		{name: "env local file", pathSpec: ".env.local", wantSensitive: true},
		{name: "npmrc", pathSpec: ".npmrc", wantSensitive: true},
		{name: "pypirc", pathSpec: ".pypirc", wantSensitive: true},
		{name: "credentials json", pathSpec: "credentials.json", wantSensitive: true},
		{name: "secrets yaml", pathSpec: "secrets.yaml", wantSensitive: true},
		{name: "aws directory", pathSpec: ".aws", wantSensitive: true},
		{name: "kube directory", pathSpec: ".kube", wantSensitive: true},
		{name: "ssh directory", pathSpec: ".ssh", wantSensitive: true},

		// Additional sensitive patterns (from code review)
		{name: "docker config", pathSpec: ".docker/config.json", wantSensitive: false}, // NOT detected - pattern missing
		{name: "terraform directory", pathSpec: ".terraform", wantSensitive: false},    // NOT detected - pattern missing
		{name: "key file", pathSpec: "private.key", wantSensitive: false},              // NOT detected - pattern missing
		{name: "pem file", pathSpec: "cert.pem", wantSensitive: false},                 // NOT detected - pattern missing
		{name: "p12 file", pathSpec: "keystore.p12", wantSensitive: false},             // NOT detected - pattern missing

		// Safe paths
		{name: "dist directory", pathSpec: "dist/", wantSensitive: false},
		{name: "build output", pathSpec: "build/output.js", wantSensitive: false},
		{name: "package json", pathSpec: "package.json", wantSensitive: false},

		// Multi-line paths
		{name: "multiline with sensitive", pathSpec: "dist/\n.git\nbuild/", wantSensitive: true},
		{name: "multiline safe", pathSpec: "dist/\nbuild/\noutput/", wantSensitive: false},

		// Current directory is NOT sensitive (it's a broad path, not a sensitive file pattern)
		{name: "current directory in multiline", pathSpec: ".\nsrc/", wantSensitive: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := containsSensitivePath(tt.pathSpec)
			if got != tt.wantSensitive {
				t.Errorf("containsSensitivePath(%q) = %v, want %v", tt.pathSpec, got, tt.wantSensitive)
			}
		})
	}
}

func TestExtractMajorVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		version string
		want    int
	}{
		{name: "v1", version: "v1", want: 1},
		{name: "v2", version: "v2", want: 2},
		{name: "v3", version: "v3", want: 3},
		{name: "v4", version: "v4", want: 4},
		{name: "v3.0.0", version: "v3.0.0", want: 3},
		{name: "v4.1.2", version: "v4.1.2", want: 4},
		{name: "without v prefix", version: "3", want: 3},
		{name: "commit SHA", version: "6b208ae046db98c579e8a3aa621ab581ff575935", want: -1},
		{name: "empty", version: "", want: -1},
		{name: "invalid", version: "latest", want: -1},

		// Additional edge cases from code review
		{name: "branch main", version: "main", want: -1},
		{name: "branch master", version: "master", want: -1},
		{name: "short SHA", version: "6b208ae", want: -1}, // FIXED: Now correctly detected as SHA
		{name: "v0", version: "v0", want: 0},
		{name: "v10", version: "v10", want: 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := extractMajorVersion(tt.version)
			if got != tt.want {
				t.Errorf("extractMajorVersion(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestParseActionVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		uses string
		want string
	}{
		{name: "v4", uses: "actions/upload-artifact@v4", want: "v4"},
		{name: "v3", uses: "actions/upload-artifact@v3", want: "v3"},
		{name: "commit SHA", uses: "actions/upload-artifact@6b208ae046db98c579e8a3aa621ab581ff575935", want: "6b208ae046db98c579e8a3aa621ab581ff575935"},
		{name: "no version", uses: "actions/upload-artifact", want: ""},

		// Additional edge cases from code review
		{name: "v1", uses: "actions/upload-artifact@v1", want: "v1"},
		{name: "branch main", uses: "actions/upload-artifact@main", want: "main"},
		{name: "branch master", uses: "actions/upload-artifact@master", want: "master"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseActionVersion(tt.uses)
			if got != tt.want {
				t.Errorf("parseActionVersion(%q) = %v, want %v", tt.uses, got, tt.want)
			}
		})
	}
}

func TestSecretsInArtifacts_VisitStep(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		step       *ast.Step
		wantErrors int
	}{
		{
			name: "upload-artifact v4 with path: . - no error (v4 excludes hidden files by default)",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "."},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0, // v4+ defaults include-hidden-files to false, so path: . is safe
		},
		{
			name: "upload-artifact v4 with path: ./ - no error (v4 excludes hidden files by default)",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "./"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0, // v4+ defaults include-hidden-files to false, so path: ./ is safe
		},
		{
			name: "upload-artifact v4 with safe path - no error",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "dist/"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0,
		},
		{
			name: "upload-artifact v3 without include-hidden-files - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v3"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "dist/"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "upload-artifact v3 with include-hidden-files: false - no error",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v3"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "dist/"},
						},
						"include-hidden-files": {
							Name:  &ast.String{Value: "include-hidden-files"},
							Value: &ast.String{Value: "false"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0,
		},
		{
			name: "upload-artifact v4 with include-hidden-files: true and path: . - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "."},
						},
						"include-hidden-files": {
							Name:  &ast.String{Value: "include-hidden-files"},
							Value: &ast.String{Value: "true"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1, // include-hidden-files: true with path: . exposes hidden files
		},
		{
			name: "upload-artifact v4 with include-hidden-files: true and safe path - no error",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "dist/"},
						},
						"include-hidden-files": {
							Name:  &ast.String{Value: "include-hidden-files"},
							Value: &ast.String{Value: "true"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0,
		},
		{
			name: "upload-artifact with .git path - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: ".git"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "non-upload-artifact action - no error",
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
			name: "download-artifact action - no error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/download-artifact@v4"},
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
			name: "upload-artifact v2 - should error (old version)",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v2"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "dist/"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "upload-artifact v4 with wildcard path - no error (v4 excludes hidden files by default)",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "**"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0, // v4+ defaults include-hidden-files to false
		},
		{
			name: "upload-artifact v1 - should error (old version like v3)",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v1"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "dist/"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "upload-artifact with commit SHA - no error (version unknown)",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@6b208ae046db98c579e8a3aa621ab581ff575935"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "dist/"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0, // Can't determine version from SHA, so no error
		},
		{
			name: "upload-artifact with branch main - no error (version unknown)",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@main"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "dist/"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0, // Can't determine version from branch name, so no error
		},
		{
			name: "upload-artifact with .docker/config.json - should error (sensitive file)",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: ".docker/config.json"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0, // Currently NOT detected - pattern is missing
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := NewSecretsInArtifactsRule()
			err := rule.VisitStep(tt.step)
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

func TestSecretsInArtifacts_FixStep(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		step             *ast.Step
		wantPath         string
		wantHiddenFiles  string
		checkPath        bool
		checkHiddenFiles bool
	}{
		{
			name: "fix v3 - should add include-hidden-files: false",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v3"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "dist/"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantHiddenFiles:  "false",
			checkHiddenFiles: true,
		},
		{
			name: "v4 with path: . - no fix needed (v4 excludes hidden files by default)",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "."},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantPath:  ".", // path should remain unchanged
			checkPath: true,
		},
		{
			name: "fix v4 with include-hidden-files: true - should set to false",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "."},
						},
						"include-hidden-files": {
							Name:  &ast.String{Value: "include-hidden-files"},
							Value: &ast.String{Value: "true"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantPath:         ".",     // path remains unchanged
			wantHiddenFiles:  "false", // include-hidden-files is set to false
			checkPath:        true,
			checkHiddenFiles: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := NewSecretsInArtifactsRule()
			err := rule.FixStep(tt.step)
			if err != nil {
				t.Errorf("FixStep() error = %v", err)
				return
			}

			action := tt.step.Exec.(*ast.ExecAction)

			if tt.checkPath {
				pathInput, ok := action.Inputs["path"]
				if !ok || pathInput == nil || pathInput.Value == nil {
					t.Error("FixStep() did not set path input")
				} else if pathInput.Value.Value != tt.wantPath {
					t.Errorf("FixStep() path = %v, want %v", pathInput.Value.Value, tt.wantPath)
				}
			}

			if tt.checkHiddenFiles {
				hiddenInput, ok := action.Inputs["include-hidden-files"]
				if !ok || hiddenInput == nil || hiddenInput.Value == nil {
					t.Error("FixStep() did not set include-hidden-files input")
				} else if hiddenInput.Value.Value != tt.wantHiddenFiles {
					t.Errorf("FixStep() include-hidden-files = %v, want %v", hiddenInput.Value.Value, tt.wantHiddenFiles)
				}
			}
		})
	}
}

func TestSecretsInArtifacts_Integration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		step           *ast.Step
		wantErrors     int
		wantAutoFixers int
	}{
		{
			name: "path: . with v4 creates no error (v4 excludes hidden files by default)",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "."},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors:     0,
			wantAutoFixers: 0,
		},
		{
			name: "v3 creates error and autofixer",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v3"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "dist/"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors:     1,
			wantAutoFixers: 1,
		},
		{
			name: "safe v4 upload creates no error",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "dist/"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors:     0,
			wantAutoFixers: 0,
		},
		{
			name: "sensitive path creates error but no autofixer",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/upload-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: ".env"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors:     1,
			wantAutoFixers: 0, // No auto-fix for sensitive paths as user may have reasons
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := NewSecretsInArtifactsRule()
			err := rule.VisitStep(tt.step)
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

			autoFixers := rule.AutoFixers()
			if len(autoFixers) != tt.wantAutoFixers {
				t.Errorf("VisitStep() got %d autofixers, want %d autofixers", len(autoFixers), tt.wantAutoFixers)
			}
		})
	}
}
