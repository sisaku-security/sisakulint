package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestNewUnmaskedSecretExposureRule(t *testing.T) {
	t.Parallel()

	rule := NewUnmaskedSecretExposureRule()
	if rule.RuleName != "unmasked-secret-exposure" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "unmasked-secret-exposure")
	}
	if !strings.Contains(rule.RuleDesc, "unmasked") {
		t.Errorf("RuleDesc should contain 'unmasked', got %q", rule.RuleDesc)
	}
}

func TestUnmaskedSecretExposure_FromJSONSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		envValue    string
		wantErrors  int
		description string
	}{
		{
			name:        "fromJson(secrets.AZURE_CREDENTIALS).clientId",
			envValue:    "${{ fromJson(secrets.AZURE_CREDENTIALS).clientId }}",
			wantErrors:  1,
			description: "Should detect fromJson extracting from secrets",
		},
		{
			name:        "fromJSON uppercase",
			envValue:    "${{ fromJSON(secrets.MY_SECRET).field }}",
			wantErrors:  1,
			description: "Should detect fromJSON (case-insensitive)",
		},
		{
			name:        "FromJson mixed case",
			envValue:    "${{ FromJson(secrets.CONFIG).value }}",
			wantErrors:  1,
			description: "Should detect FromJson (case-insensitive)",
		},
		{
			name:        "fromJson with nested property access",
			envValue:    "${{ fromJson(secrets.CREDS).nested.deeply.value }}",
			wantErrors:  1,
			description: "Should detect nested property access from fromJson",
		},
		{
			name:        "fromJson with secrets and index access",
			envValue:    "${{ fromJson(secrets.CONFIG)['key'] }}",
			wantErrors:  1,
			description: "Should detect index access on fromJson result",
		},
		{
			name:        "Multiple fromJson calls",
			envValue:    "${{ fromJson(secrets.A).x }} and ${{ fromJson(secrets.B).y }}",
			wantErrors:  2,
			description: "Should detect multiple fromJson expressions",
		},
		{
			name:        "fromJson with github.event (not secrets)",
			envValue:    "${{ fromJson(github.event.inputs).value }}",
			wantErrors:  0,
			description: "Should not flag fromJson with non-secrets context",
		},
		{
			name:        "fromJson with needs output",
			envValue:    "${{ fromJson(needs.job.outputs.data).result }}",
			wantErrors:  0,
			description: "Should not flag fromJson with needs context",
		},
		{
			name:        "Direct secret access (safe)",
			envValue:    "${{ secrets.MY_SECRET }}",
			wantErrors:  0,
			description: "Should not flag direct secret access",
		},
		{
			name:        "fromJson without dereferencing (just conversion)",
			envValue:    "${{ fromJson(secrets.JSON_DATA) }}",
			wantErrors:  0,
			description: "Should not flag fromJson without property access (though still risky)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := NewUnmaskedSecretExposureRule()

			step := &ast.Step{
				Env: &ast.Env{
					Vars: map[string]*ast.EnvVar{
						"test_var": {
							Name: &ast.String{Value: "TEST_VAR"},
							Value: &ast.String{
								Value: tt.envValue,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			}

			job := &ast.Job{Steps: []*ast.Step{step}}
			_ = rule.VisitJobPre(job)

			gotErrors := len(rule.Errors())
			if gotErrors != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d errors. Errors: %v",
					tt.description, gotErrors, tt.wantErrors, rule.Errors())
			}
		})
	}
}

func TestUnmaskedSecretExposure_RunScript(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "fromJson in run script",
			runScript:   `echo "${{ fromJson(secrets.CONFIG).password }}"`,
			wantErrors:  1,
			description: "Should detect fromJson in run scripts",
		},
		{
			name:        "Multiple expressions in run script",
			runScript:   `echo "${{ fromJson(secrets.A).x }}" && echo "${{ secrets.B }}"`,
			wantErrors:  1,
			description: "Should detect only fromJson expressions, not direct secrets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := NewUnmaskedSecretExposureRule()

			step := &ast.Step{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: tt.runScript,
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			}

			job := &ast.Job{Steps: []*ast.Step{step}}
			_ = rule.VisitJobPre(job)

			gotErrors := len(rule.Errors())
			if gotErrors != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d errors. Errors: %v",
					tt.description, gotErrors, tt.wantErrors, rule.Errors())
			}
		})
	}
}

func TestUnmaskedSecretExposure_ActionInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputValue  string
		wantErrors  int
		description string
	}{
		{
			name:        "fromJson in action input",
			inputValue:  "${{ fromJson(secrets.AZURE_CREDENTIALS).clientId }}",
			wantErrors:  1,
			description: "Should detect fromJson in action inputs",
		},
		{
			name:        "Direct secret in action input (safe)",
			inputValue:  "${{ secrets.GITHUB_TOKEN }}",
			wantErrors:  0,
			description: "Should not flag direct secret in action inputs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := NewUnmaskedSecretExposureRule()

			step := &ast.Step{
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "some/action@v1"},
					Inputs: map[string]*ast.Input{
						"token": {
							Name: &ast.String{Value: "token"},
							Value: &ast.String{
								Value: tt.inputValue,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			}

			job := &ast.Job{Steps: []*ast.Step{step}}
			_ = rule.VisitJobPre(job)

			gotErrors := len(rule.Errors())
			if gotErrors != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d errors. Errors: %v",
					tt.description, gotErrors, tt.wantErrors, rule.Errors())
			}
		})
	}
}

func TestUnmaskedSecretExposure_WorkflowLevelEnv(t *testing.T) {
	t.Parallel()

	rule := NewUnmaskedSecretExposureRule()

	workflow := &ast.Workflow{
		Env: &ast.Env{
			Vars: map[string]*ast.EnvVar{
				"client_id": {
					Name: &ast.String{Value: "CLIENT_ID"},
					Value: &ast.String{
						Value: "${{ fromJson(secrets.AZURE_CREDENTIALS).clientId }}",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
		},
	}

	_ = rule.VisitWorkflowPre(workflow)

	gotErrors := len(rule.Errors())
	if gotErrors != 1 {
		t.Errorf("Expected 1 error for fromJson(secrets...) at workflow level, got %d. Errors: %v",
			gotErrors, rule.Errors())
	}
}

func TestUnmaskedSecretExposure_JobLevelEnv(t *testing.T) {
	t.Parallel()

	rule := NewUnmaskedSecretExposureRule()

	job := &ast.Job{
		Env: &ast.Env{
			Vars: map[string]*ast.EnvVar{
				"client_id": {
					Name: &ast.String{Value: "CLIENT_ID"},
					Value: &ast.String{
						Value: "${{ fromJson(secrets.CREDS).clientId }}",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
		},
		Steps: []*ast.Step{},
	}

	_ = rule.VisitJobPre(job)

	gotErrors := len(rule.Errors())
	if gotErrors != 1 {
		t.Errorf("Expected 1 error for fromJson(secrets...) at job level, got %d. Errors: %v",
			gotErrors, rule.Errors())
	}
}

func TestUnmaskedSecretExposure_ErrorMessages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		envValue       string
		expectedSubstr string
		description    string
	}{
		{
			name:           "Error message mentions unmasked",
			envValue:       "${{ fromJson(secrets.AZURE_CREDENTIALS).clientId }}",
			expectedSubstr: "not automatically masked",
			description:    "Error message should explain unmasked risk",
		},
		{
			name:           "Error message suggests separate secrets",
			envValue:       "${{ fromJson(secrets.CONFIG).password }}",
			expectedSubstr: "separate secret",
			description:    "Error message should suggest using separate secrets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := NewUnmaskedSecretExposureRule()

			step := &ast.Step{
				Env: &ast.Env{
					Vars: map[string]*ast.EnvVar{
						"test": {
							Name: &ast.String{Value: "TEST"},
							Value: &ast.String{
								Value: tt.envValue,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			}

			job := &ast.Job{Steps: []*ast.Step{step}}
			_ = rule.VisitJobPre(job)

			errors := rule.Errors()
			if len(errors) == 0 {
				t.Fatalf("%s: Expected at least one error", tt.description)
			}

			found := false
			for _, err := range errors {
				if strings.Contains(err.Description, tt.expectedSubstr) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: Expected error message to contain %q, got %v",
					tt.description, tt.expectedSubstr, errors)
			}
		})
	}
}

func TestUnmaskedSecretExposure_AutoFix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		envValue          string
		wantFixers        int
		wantFixedContains string
		description       string
	}{
		{
			name:              "Auto-fix adds add-mask command",
			envValue:          "${{ fromJson(secrets.AZURE_CREDENTIALS).clientId }}",
			wantFixers:        1,
			wantFixedContains: "add-mask",
			description:       "Should add add-mask step before using derived secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := NewUnmaskedSecretExposureRule()

			step := &ast.Step{
				Env: &ast.Env{
					Vars: map[string]*ast.EnvVar{
						"client_id": {
							Name: &ast.String{Value: "CLIENT_ID"},
							Value: &ast.String{
								Value: tt.envValue,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: "echo using client id",
						Pos:   &ast.Position{Line: 2, Col: 1},
					},
				},
			}

			job := &ast.Job{Steps: []*ast.Step{step}}
			_ = rule.VisitJobPre(job)

			// Check number of fixers
			fixers := rule.AutoFixers()
			if len(fixers) != tt.wantFixers {
				t.Errorf("%s: got %d fixers, want %d fixers",
					tt.description, len(fixers), tt.wantFixers)
			}

			// Apply fixers if any
			if len(fixers) > 0 {
				for _, fixer := range fixers {
					if err := fixer.Fix(); err != nil {
						t.Errorf("%s: Fix() returned error: %v", tt.description, err)
					}
				}

				// Check that the fix was applied (step should have add-mask in run script)
				if step.Exec != nil {
					execRun, ok := step.Exec.(*ast.ExecRun)
					if ok && execRun.Run != nil {
						if !strings.Contains(execRun.Run.Value, tt.wantFixedContains) {
							t.Errorf("%s: After fix, expected run to contain %q, got %q",
								tt.description, tt.wantFixedContains, execRun.Run.Value)
						}
					}
				}
			}
		})
	}
}

func TestUnmaskedSecretExposure_AutoFixEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("Does not duplicate existing add-mask", func(t *testing.T) {
		t.Parallel()

		rule := NewUnmaskedSecretExposureRule()

		step := &ast.Step{
			Env: &ast.Env{
				Vars: map[string]*ast.EnvVar{
					"client_id": {
						Name: &ast.String{Value: "CLIENT_ID"},
						Value: &ast.String{
							Value: "${{ fromJson(secrets.AZURE_CREDENTIALS).clientId }}",
							Pos:   &ast.Position{Line: 1, Col: 1},
						},
					},
				},
			},
			Exec: &ast.ExecRun{
				Run: &ast.String{
					Value: "echo \"::add-mask::$AZURE_CREDENTIALS_CLIENTID\"\necho using client id",
					Pos:   &ast.Position{Line: 2, Col: 1},
				},
			},
		}

		job := &ast.Job{Steps: []*ast.Step{step}}
		_ = rule.VisitJobPre(job)

		fixers := rule.AutoFixers()
		if len(fixers) != 1 {
			t.Errorf("Expected 1 fixer, got %d", len(fixers))
		}

		// Apply fixer
		if len(fixers) > 0 {
			for _, fixer := range fixers {
				if err := fixer.Fix(); err != nil {
					t.Errorf("Fix() returned error: %v", err)
				}
			}

			// Check that add-mask wasn't duplicated
			if step.Exec != nil {
				execRun, ok := step.Exec.(*ast.ExecRun)
				if ok && execRun.Run != nil {
					// Count occurrences of add-mask
					count := strings.Count(execRun.Run.Value, "::add-mask::")
					if count != 1 {
						t.Errorf("Expected 1 occurrence of add-mask, got %d. Script:\n%s", count, execRun.Run.Value)
					}
				}
			}
		}
	})

	t.Run("Handles existing env var with same name", func(t *testing.T) {
		t.Parallel()

		rule := NewUnmaskedSecretExposureRule()

		step := &ast.Step{
			Env: &ast.Env{
				Vars: map[string]*ast.EnvVar{
					"azure_credentials_clientid": {
						Name:  &ast.String{Value: "AZURE_CREDENTIALS_CLIENTID"},
						Value: &ast.String{Value: "existing-value"},
					},
					"client_id": {
						Name: &ast.String{Value: "CLIENT_ID"},
						Value: &ast.String{
							Value: "${{ fromJson(secrets.AZURE_CREDENTIALS).clientId }}",
							Pos:   &ast.Position{Line: 1, Col: 1},
						},
					},
				},
			},
			Exec: &ast.ExecRun{
				Run: &ast.String{
					Value: "echo using client id",
					Pos:   &ast.Position{Line: 2, Col: 1},
				},
			},
		}

		job := &ast.Job{Steps: []*ast.Step{step}}
		_ = rule.VisitJobPre(job)

		fixers := rule.AutoFixers()
		if len(fixers) != 1 {
			t.Errorf("Expected 1 fixer, got %d", len(fixers))
		}

		// Apply fixer
		if len(fixers) > 0 {
			for _, fixer := range fixers {
				if err := fixer.Fix(); err != nil {
					t.Errorf("Fix() returned error: %v", err)
				}
			}

			// Check that existing env var value is preserved
			if step.Env.Vars["azure_credentials_clientid"].Value.Value != "existing-value" {
				t.Errorf("Existing env var was overwritten, got: %s", step.Env.Vars["azure_credentials_clientid"].Value.Value)
			}
		}
	})

	t.Run("Handles multiple fromJson expressions in same step", func(t *testing.T) {
		t.Parallel()

		rule := NewUnmaskedSecretExposureRule()

		step := &ast.Step{
			Env: &ast.Env{
				Vars: map[string]*ast.EnvVar{
					"client_id": {
						Name: &ast.String{Value: "CLIENT_ID"},
						Value: &ast.String{
							Value: "${{ fromJson(secrets.AZURE_CREDENTIALS).clientId }}",
							Pos:   &ast.Position{Line: 1, Col: 1},
						},
					},
					"client_secret": {
						Name: &ast.String{Value: "CLIENT_SECRET"},
						Value: &ast.String{
							Value: "${{ fromJson(secrets.AZURE_CREDENTIALS).clientSecret }}",
							Pos:   &ast.Position{Line: 2, Col: 1},
						},
					},
				},
			},
			Exec: &ast.ExecRun{
				Run: &ast.String{
					Value: "echo using credentials",
					Pos:   &ast.Position{Line: 3, Col: 1},
				},
			},
		}

		job := &ast.Job{Steps: []*ast.Step{step}}
		_ = rule.VisitJobPre(job)

		// Should detect 2 errors
		errors := rule.Errors()
		if len(errors) != 2 {
			t.Errorf("Expected 2 errors, got %d", len(errors))
		}

		// Should have 2 fixers
		fixers := rule.AutoFixers()
		if len(fixers) != 2 {
			t.Errorf("Expected 2 fixers, got %d", len(fixers))
		}

		// Apply all fixers
		for _, fixer := range fixers {
			if err := fixer.Fix(); err != nil {
				t.Errorf("Fix() returned error: %v", err)
			}
		}

		// Check that both add-mask commands were added
		if step.Exec != nil {
			execRun, ok := step.Exec.(*ast.ExecRun)
			if ok && execRun.Run != nil {
				count := strings.Count(execRun.Run.Value, "::add-mask::")
				if count != 2 {
					t.Errorf("Expected 2 add-mask commands, got %d. Script:\n%s", count, execRun.Run.Value)
				}
			}
		}
	})

	t.Run("Handles complex run script with shebang", func(t *testing.T) {
		t.Parallel()

		rule := NewUnmaskedSecretExposureRule()

		step := &ast.Step{
			Env: &ast.Env{
				Vars: map[string]*ast.EnvVar{
					"client_id": {
						Name: &ast.String{Value: "CLIENT_ID"},
						Value: &ast.String{
							Value: "${{ fromJson(secrets.AZURE_CREDENTIALS).clientId }}",
							Pos:   &ast.Position{Line: 1, Col: 1},
						},
					},
				},
			},
			Exec: &ast.ExecRun{
				Run: &ast.String{
					Value: "#!/bin/bash\nset -e\necho \"Starting...\"",
					Pos:   &ast.Position{Line: 2, Col: 1},
				},
			},
		}

		job := &ast.Job{Steps: []*ast.Step{step}}
		_ = rule.VisitJobPre(job)

		fixers := rule.AutoFixers()
		if len(fixers) != 1 {
			t.Errorf("Expected 1 fixer, got %d", len(fixers))
		}

		// Apply fixer
		if len(fixers) > 0 {
			for _, fixer := range fixers {
				if err := fixer.Fix(); err != nil {
					t.Errorf("Fix() returned error: %v", err)
				}
			}

			// Check that add-mask was added and script still works
			if step.Exec != nil {
				execRun, ok := step.Exec.(*ast.ExecRun)
				if ok && execRun.Run != nil {
					if !strings.Contains(execRun.Run.Value, "::add-mask::") {
						t.Errorf("add-mask was not added")
					}

					// CRITICAL: Shebang must be on the first line
					lines := strings.Split(execRun.Run.Value, "\n")
					if len(lines) == 0 || !strings.HasPrefix(lines[0], "#!/bin/bash") {
						t.Errorf("Shebang is not on the first line. First line: %q, Full script:\n%s",
							lines[0], execRun.Run.Value)
					}

					// add-mask should be on the second line (after shebang)
					if len(lines) < 2 || !strings.Contains(lines[1], "::add-mask::") {
						t.Errorf("add-mask is not on the second line (after shebang). Second line: %q",
							lines[1])
					}
				}
			}
		}
	})
}

func TestUnmaskedSecretExposure_ComplexPatterns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		envValue    string
		wantErrors  int
		description string
	}{
		{
			name:        "Chained method calls",
			envValue:    "${{ fromJson(toJson(fromJson(secrets.DATA))).value }}",
			wantErrors:  1,
			description: "Should detect nested fromJson with secrets",
		},
		{
			name:        "fromJson in conditional",
			envValue:    "${{ fromJson(secrets.CONFIG).enabled && 'yes' || 'no' }}",
			wantErrors:  1,
			description: "Should detect fromJson in conditional expressions",
		},
		{
			name:        "fromJson with comparison",
			envValue:    "${{ fromJson(secrets.VERSION).major > 1 }}",
			wantErrors:  1,
			description: "Should detect fromJson in comparisons",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := NewUnmaskedSecretExposureRule()

			step := &ast.Step{
				Env: &ast.Env{
					Vars: map[string]*ast.EnvVar{
						"test": {
							Name: &ast.String{Value: "TEST"},
							Value: &ast.String{
								Value: tt.envValue,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			}

			job := &ast.Job{Steps: []*ast.Step{step}}
			_ = rule.VisitJobPre(job)

			gotErrors := len(rule.Errors())
			if gotErrors != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d errors. Errors: %v",
					tt.description, gotErrors, tt.wantErrors, rule.Errors())
			}
		})
	}
}
