package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestNewSecretExposureRule(t *testing.T) {
	rule := NewSecretExposureRule()
	if rule.RuleName != "secret-exposure" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "secret-exposure")
	}
	if !strings.Contains(rule.RuleDesc, "excessive secret exposure") {
		t.Errorf("RuleDesc should contain 'excessive secret exposure', got %q", rule.RuleDesc)
	}
}

func TestSecretExposure_ToJSONSecrets(t *testing.T) {
	tests := []struct {
		name        string
		envValue    string
		wantErrors  int
		description string
	}{
		{
			name:        "toJSON(secrets) in env",
			envValue:    "${{ toJSON(secrets) }}",
			wantErrors:  1,
			description: "Should detect toJSON(secrets)",
		},
		{
			name:        "TOJSON(secrets) uppercase",
			envValue:    "${{ TOJSON(secrets) }}",
			wantErrors:  1,
			description: "Should detect TOJSON(secrets) (case-insensitive)",
		},
		{
			name:        "ToJson(secrets) mixed case",
			envValue:    "${{ ToJson(secrets) }}",
			wantErrors:  1,
			description: "Should detect ToJson(secrets) (case-insensitive)",
		},
		{
			name:        "toJSON(github.event)",
			envValue:    "${{ toJSON(github.event) }}",
			wantErrors:  0,
			description: "Should not detect toJSON with other variables",
		},
		{
			name:        "toJSON(matrix)",
			envValue:    "${{ toJSON(matrix) }}",
			wantErrors:  0,
			description: "Should not detect toJSON with matrix",
		},
		{
			name:        "toJSON(needs)",
			envValue:    "${{ toJSON(needs) }}",
			wantErrors:  0,
			description: "Should not detect toJSON with needs",
		},
		{
			name:        "specific secret",
			envValue:    "${{ secrets.MY_SECRET }}",
			wantErrors:  0,
			description: "Should not detect specific secret access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExposureRule()

			step := &ast.Step{
				Env: &ast.Env{
					Vars: map[string]*ast.EnvVar{
						"all_secrets": {
							Name: &ast.String{Value: "ALL_SECRETS"},
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

func TestSecretExposure_DynamicAccess(t *testing.T) {
	tests := []struct {
		name        string
		envValue    string
		wantErrors  int
		description string
	}{
		{
			name:        "secrets[format(...)]",
			envValue:    "${{ secrets[format('GH_PAT_%s', matrix.env)] }}",
			wantErrors:  1,
			description: "Should detect secrets with format() index",
		},
		{
			name:        "secrets['literal']",
			envValue:    "${{ secrets['MY_SECRET'] }}",
			wantErrors:  1,
			description: "Should detect secrets with string literal index",
		},
		{
			name:        "secrets[variable]",
			envValue:    "${{ secrets[secret_name] }}",
			wantErrors:  1,
			description: "Should detect secrets with variable index",
		},
		{
			name:        "secrets[matrix.env]",
			envValue:    "${{ secrets[matrix.env] }}",
			wantErrors:  1,
			description: "Should detect secrets with object property index",
		},
		{
			name:        "secrets.MY_SECRET (dot notation)",
			envValue:    "${{ secrets.MY_SECRET }}",
			wantErrors:  0,
			description: "Should not detect dot notation access",
		},
		{
			name:        "env[variable]",
			envValue:    "${{ env[var_name] }}",
			wantErrors:  0,
			description: "Should not detect dynamic access on other variables",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExposureRule()

			step := &ast.Step{
				Env: &ast.Env{
					Vars: map[string]*ast.EnvVar{
						"my_token": {
							Name: &ast.String{Value: "MY_TOKEN"},
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

func TestSecretExposure_ActionInputs(t *testing.T) {
	tests := []struct {
		name        string
		inputValue  string
		wantErrors  int
		description string
	}{
		{
			name:        "toJSON(secrets) in action input",
			inputValue:  "${{ toJSON(secrets) }}",
			wantErrors:  1,
			description: "Should detect toJSON(secrets) in action inputs",
		},
		{
			name:        "secrets[format(...)] in action input",
			inputValue:  "${{ secrets[format('KEY_%s', matrix.env)] }}",
			wantErrors:  1,
			description: "Should detect dynamic secret access in action inputs",
		},
		{
			name:        "specific secret in action input",
			inputValue:  "${{ secrets.GITHUB_TOKEN }}",
			wantErrors:  0,
			description: "Should not detect specific secret in action inputs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExposureRule()

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

func TestSecretExposure_RunScript(t *testing.T) {
	tests := []struct {
		name        string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "toJSON(secrets) in run script",
			runScript:   `echo "${{ toJSON(secrets) }}"`,
			wantErrors:  1,
			description: "Should detect toJSON(secrets) in run scripts",
		},
		{
			name:        "specific secret in run script",
			runScript:   `echo "${{ secrets.MY_SECRET }}"`,
			wantErrors:  0,
			description: "Should not detect specific secret in run scripts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExposureRule()

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

func TestSecretExposure_WorkflowLevelEnv(t *testing.T) {
	rule := NewSecretExposureRule()

	workflow := &ast.Workflow{
		Env: &ast.Env{
			Vars: map[string]*ast.EnvVar{
				"all_secrets": {
					Name: &ast.String{Value: "ALL_SECRETS"},
					Value: &ast.String{
						Value: "${{ toJSON(secrets) }}",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
		},
	}

	_ = rule.VisitWorkflowPre(workflow)

	gotErrors := len(rule.Errors())
	if gotErrors != 1 {
		t.Errorf("Expected 1 error for toJSON(secrets) at workflow level, got %d. Errors: %v",
			gotErrors, rule.Errors())
	}
}

func TestSecretExposure_JobLevelEnv(t *testing.T) {
	rule := NewSecretExposureRule()

	job := &ast.Job{
		Env: &ast.Env{
			Vars: map[string]*ast.EnvVar{
				"all_secrets": {
					Name: &ast.String{Value: "ALL_SECRETS"},
					Value: &ast.String{
						Value: "${{ toJSON(secrets) }}",
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
		t.Errorf("Expected 1 error for toJSON(secrets) at job level, got %d. Errors: %v",
			gotErrors, rule.Errors())
	}
}

func TestSecretExposure_MultipleExpressions(t *testing.T) {
	rule := NewSecretExposureRule()

	step := &ast.Step{
		Env: &ast.Env{
			Vars: map[string]*ast.EnvVar{
				"multi": {
					Name: &ast.String{Value: "MULTI"},
					Value: &ast.String{
						Value: "prefix ${{ toJSON(secrets) }} middle ${{ secrets['KEY'] }} suffix",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
		},
	}

	job := &ast.Job{Steps: []*ast.Step{step}}
	_ = rule.VisitJobPre(job)

	gotErrors := len(rule.Errors())
	if gotErrors != 2 {
		t.Errorf("Expected 2 errors for multiple exposures, got %d. Errors: %v",
			gotErrors, rule.Errors())
	}
}

func TestSecretExposure_ErrorMessages(t *testing.T) {
	tests := []struct {
		name           string
		envValue       string
		expectedSubstr string
		description    string
	}{
		{
			name:           "toJSON error message",
			envValue:       "${{ toJSON(secrets) }}",
			expectedSubstr: "toJSON(secrets) exposes all repository and organization secrets",
			description:    "Error message should explain toJSON risk",
		},
		{
			name:           "dynamic access error message",
			envValue:       "${{ secrets[format('KEY_%s', env.name)] }}",
			expectedSubstr: "dynamically constructs the secret name",
			description:    "Error message should explain dynamic construction risk",
		},
		{
			name:           "bracket notation error message",
			envValue:       "${{ secrets['MY_KEY'] }}",
			expectedSubstr: "bracket notation",
			description:    "Error message should mention bracket notation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExposureRule()

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

func TestSecretExposure_AutoFix(t *testing.T) {
	tests := []struct {
		name           string
		envValue       string
		wantFixers     int
		wantFixedValue string
		description    string
	}{
		{
			name:           "Basic bracket notation - single quotes",
			envValue:       "${{ secrets['GITHUB_TOKEN'] }}",
			wantFixers:     1,
			wantFixedValue: "${{ secrets.GITHUB_TOKEN }}",
			description:    "Should auto-fix secrets['TOKEN'] to secrets.TOKEN",
		},
		{
			name:           "Double quotes are not supported",
			envValue:       `${{ secrets["API_KEY"] }}`,
			wantFixers:     0,
			wantFixedValue: `${{ secrets["API_KEY"] }}`,
			description:    "Double quotes are not valid GitHub Actions expression syntax (only single quotes supported)",
		},
		{
			name:           "Secret with underscores",
			envValue:       "${{ secrets['MY_SECRET_TOKEN'] }}",
			wantFixers:     1,
			wantFixedValue: "${{ secrets.MY_SECRET_TOKEN }}",
			description:    "Should handle secret names with underscores",
		},
		{
			name:           "Multiple bracket notations",
			envValue:       "prefix ${{ secrets['TOKEN1'] }} middle ${{ secrets['TOKEN2'] }} suffix",
			wantFixers:     2, // Each expression gets its own fixer
			wantFixedValue: "prefix ${{ secrets.TOKEN1 }} middle ${{ secrets.TOKEN2 }} suffix",
			description:    "Should fix multiple bracket notations in same string",
		},
		{
			name:           "Mixed with other expressions",
			envValue:       "${{ secrets['TOKEN'] }} and ${{ github.actor }}",
			wantFixers:     1,
			wantFixedValue: "${{ secrets.TOKEN }} and ${{ github.actor }}",
			description:    "Should only fix bracket notation, preserve other expressions",
		},
		{
			name:           "Invalid name with hyphen",
			envValue:       "${{ secrets['MY-SECRET'] }}",
			wantFixers:     0,
			wantFixedValue: "${{ secrets['MY-SECRET'] }}",
			description:    "Should NOT auto-fix names with hyphens",
		},
		{
			name:           "Invalid name with dot",
			envValue:       "${{ secrets['MY.SECRET'] }}",
			wantFixers:     0,
			wantFixedValue: "${{ secrets['MY.SECRET'] }}",
			description:    "Should NOT auto-fix names with dots",
		},
		{
			name:           "Invalid name starting with number",
			envValue:       "${{ secrets['123SECRET'] }}",
			wantFixers:     0,
			wantFixedValue: "${{ secrets['123SECRET'] }}",
			description:    "Should NOT auto-fix names starting with number",
		},
		{
			name:           "Dynamic access with format",
			envValue:       "${{ secrets[format('PAT_%s', matrix.env)] }}",
			wantFixers:     0,
			wantFixedValue: "${{ secrets[format('PAT_%s', matrix.env)] }}",
			description:    "Should NOT auto-fix dynamic format() access",
		},
		{
			name:           "Dynamic access with variable",
			envValue:       "${{ secrets[env.SECRET_NAME] }}",
			wantFixers:     0,
			wantFixedValue: "${{ secrets[env.SECRET_NAME] }}",
			description:    "Should NOT auto-fix dynamic variable access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExposureRule()

			step := &ast.Step{
				Env: &ast.Env{
					Vars: map[string]*ast.EnvVar{
						"my_token": {
							Name: &ast.String{Value: "MY_TOKEN"},
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

				// Check the fixed value
				gotValue := step.Env.Vars["my_token"].Value.Value
				if gotValue != tt.wantFixedValue {
					t.Errorf("%s: After fix, got %q, want %q",
						tt.description, gotValue, tt.wantFixedValue)
				}
			} else {
				// No fixers - value should remain unchanged
				gotValue := step.Env.Vars["my_token"].Value.Value
				if gotValue != tt.wantFixedValue {
					t.Errorf("%s: Without fix, got %q, want %q (unchanged)",
						tt.description, gotValue, tt.wantFixedValue)
				}
			}
		})
	}
}

func TestSecretExposure_AutoFix_ActionInputs(t *testing.T) {
	rule := NewSecretExposureRule()

	step := &ast.Step{
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "some/action@v1"},
			Inputs: map[string]*ast.Input{
				"token": {
					Name: &ast.String{Value: "token"},
					Value: &ast.String{
						Value: "${{ secrets['GITHUB_TOKEN'] }}",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
		},
	}

	job := &ast.Job{Steps: []*ast.Step{step}}
	_ = rule.VisitJobPre(job)

	// Should have one fixer
	fixers := rule.AutoFixers()
	if len(fixers) != 1 {
		t.Fatalf("Expected 1 fixer, got %d", len(fixers))
	}

	// Apply the fix
	if err := fixers[0].Fix(); err != nil {
		t.Fatalf("Fix() returned error: %v", err)
	}

	// Check the fixed value
	gotValue := step.Exec.(*ast.ExecAction).Inputs["token"].Value.Value
	wantValue := "${{ secrets.GITHUB_TOKEN }}"
	if gotValue != wantValue {
		t.Errorf("After fix, got %q, want %q", gotValue, wantValue)
	}
}

func TestSecretExposure_AutoFix_WorkflowLevel(t *testing.T) {
	rule := NewSecretExposureRule()

	workflow := &ast.Workflow{
		Env: &ast.Env{
			Vars: map[string]*ast.EnvVar{
				"token": {
					Name: &ast.String{Value: "TOKEN"},
					Value: &ast.String{
						Value: "${{ secrets['MY_TOKEN'] }}",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
		},
		Jobs: map[string]*ast.Job{},
	}

	// Note: Workflow-level env doesn't have a step context, so no auto-fix should be added
	_ = rule.VisitWorkflowPre(workflow)

	fixers := rule.AutoFixers()
	// Workflow-level violations won't have fixers because there's no step context
	if len(fixers) != 0 {
		t.Errorf("Expected 0 fixers for workflow-level env (no step context), got %d", len(fixers))
	}
}

func TestIsValidSecretNameForDotNotation(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"Valid uppercase", "MY_SECRET", true},
		{"Valid with underscores", "MY_SECRET_TOKEN", true},
		{"Valid starting with underscore", "_MY_SECRET", true},
		{"Valid alphanumeric", "API_KEY123", true},
		{"Invalid with hyphen", "MY-SECRET", false},
		{"Invalid with dot", "MY.SECRET", false},
		{"Invalid with space", "MY SECRET", false},
		{"Invalid starting with number", "123SECRET", false},
		{"Invalid empty", "", false},
		{"Valid with quotes (should be trimmed)", "'MY_SECRET'", true},
		{"Valid with double quotes", `"MY_SECRET"`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidSecretNameForDotNotation(tt.input)
			if got != tt.want {
				t.Errorf("isValidSecretNameForDotNotation(%q) = %v, want %v",
					tt.input, got, tt.want)
			}
		})
	}
}

func TestSecretExposure_AutoFix_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		envValue       string
		wantFixers     int
		wantFixedValue string
		description    string
	}{
		{
			name:           "Extra spaces after ${{",
			envValue:       "${{  secrets['GITHUB_TOKEN'] }}",
			wantFixers:     1,
			wantFixedValue: "${{  secrets.GITHUB_TOKEN }}",
			description:    "Should handle extra spaces after ${{",
		},
		{
			name:           "Extra spaces before }}",
			envValue:       "${{ secrets['GITHUB_TOKEN']  }}",
			wantFixers:     1,
			wantFixedValue: "${{ secrets.GITHUB_TOKEN  }}",
			description:    "Should handle extra spaces before }}",
		},
		{
			name:           "Extra spaces on both sides",
			envValue:       "${{  secrets['GITHUB_TOKEN']  }}",
			wantFixers:     1,
			wantFixedValue: "${{  secrets.GITHUB_TOKEN  }}",
			description:    "Should handle extra spaces on both sides",
		},
		{
			name:           "Tab character after ${{",
			envValue:       "${{ \tsecrets['GITHUB_TOKEN'] }}",
			wantFixers:     1,
			wantFixedValue: "${{ \tsecrets.GITHUB_TOKEN }}",
			description:    "Should handle tab character",
		},
		{
			name:           "Multiple spaces between tokens",
			envValue:       "${{   secrets['GITHUB_TOKEN']   }}",
			wantFixers:     1,
			wantFixedValue: "${{   secrets.GITHUB_TOKEN   }}",
			description:    "Should handle multiple spaces",
		},
		{
			name:           "No spaces (compact)",
			envValue:       "${{secrets['GITHUB_TOKEN']}}",
			wantFixers:     1,
			wantFixedValue: "${{secrets.GITHUB_TOKEN}}",
			description:    "Should handle compact format without spaces",
		},
		{
			name:           "Mixed spacing in multiple expressions",
			envValue:       "${{ secrets['TOKEN1'] }} and ${{secrets['TOKEN2']}}",
			wantFixers:     2,
			wantFixedValue: "${{ secrets.TOKEN1 }} and ${{secrets.TOKEN2}}",
			description:    "Should handle mixed spacing across multiple expressions",
		},
		{
			name:           "Spaces in string with prefix and suffix",
			envValue:       "prefix ${{  secrets['MY_KEY']  }} suffix",
			wantFixers:     1,
			wantFixedValue: "prefix ${{  secrets.MY_KEY  }} suffix",
			description:    "Should preserve spacing in string with prefix/suffix",
		},
		{
			name:           "Newline in expression (multiline)",
			envValue:       "${{ \nsecrets['GITHUB_TOKEN']\n}}",
			wantFixers:     1,
			wantFixedValue: "${{ \nsecrets.GITHUB_TOKEN\n}}",
			description:    "Should handle newlines in expression",
		},
		{
			name:           "Extra spaces with invalid name",
			envValue:       "${{  secrets['MY-SECRET']  }}",
			wantFixers:     0,
			wantFixedValue: "${{  secrets['MY-SECRET']  }}",
			description:    "Should NOT auto-fix invalid names even with extra spaces",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExposureRule()

			step := &ast.Step{
				Env: &ast.Env{
					Vars: map[string]*ast.EnvVar{
						"my_token": {
							Name: &ast.String{Value: "MY_TOKEN"},
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

				// Check the fixed value
				gotValue := step.Env.Vars["my_token"].Value.Value
				if gotValue != tt.wantFixedValue {
					t.Errorf("%s: After fix, got %q, want %q",
						tt.description, gotValue, tt.wantFixedValue)
				}
			} else {
				// No fixers - value should remain unchanged
				gotValue := step.Env.Vars["my_token"].Value.Value
				if gotValue != tt.wantFixedValue {
					t.Errorf("%s: Without fix, got %q, want %q (unchanged)",
						tt.description, gotValue, tt.wantFixedValue)
				}
			}
		})
	}
}
