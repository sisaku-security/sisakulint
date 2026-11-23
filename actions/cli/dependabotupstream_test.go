package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestDependabotUpstreamCases runs the cases of the tests of upstream's
// dependabot-github-actions (pkg/core/dependabot_github_actions_test.go of
// sisakulint 17c2d82151a966e6e388a17619b060ae2919712e) with --root, and
// holds how many findings this repository gives, where upstream gives
// another number.
func TestDependabotUpstreamCases(t *testing.T) {
	const pinned = "b4ffde65f46336ab88eb53be808477a3936bae11"
	dependabotYAML := func(eco string) string {
		return "version: 2\nupdates:\n  - package-ecosystem: \"" + eco + "\"\n    directory: \"/\"\n    schedule:\n      interval: \"weekly\"\n"
	}
	for _, c := range []struct {
		name          string
		uses          string
		files         map[string]string
		upstream, got int
	}{
		{"NoDependabotFile", "actions/checkout@v4", nil, 1, 1},
		{"DependabotWithoutGitHubActions", "actions/checkout@v4", map[string]string{".github/dependabot.yaml": dependabotYAML("npm")}, 1, 1},
		{"DependabotWithGitHubActions", "actions/checkout@v4", map[string]string{".github/dependabot.yaml": dependabotYAML("github-actions")}, 0, 0},
		{"PinnedActions", "actions/checkout@" + pinned, nil, 0, 1}, // u1: Dependabot updates a SHA too
		{"LocalAction", "./local-action", nil, 0, 0},
		{"DockerAction", "docker://alpine:3.8", nil, 0, 0},
		{"DependabotYml", "actions/checkout@v4", map[string]string{".github/dependabot.yml": dependabotYAML("github-actions")}, 0, 0},
		{"RenovateWithGitHubActions", "actions/checkout@v4", map[string]string{".github/renovate.json": `{"extends": ["config:recommended"], "packageRules": [{"matchManagers": ["github-actions"], "groupName": "github-actions", "pinDigests": true}]}`}, 0, 0},
		{"RenovateAtRootLevel", "actions/checkout@v4", map[string]string{"renovate.json": `{"packageRules": [{"matchManagers": ["github-actions"]}]}`}, 0, 0},
		{"RenovateWithoutGitHubActions", "actions/checkout@v4", map[string]string{".github/renovate.json": `{"packageRules": [{"matchManagers": ["npm"], "groupName": "npm-packages"}]}`}, 1, 0}, // u3: the manager is on by default
		// upstream's own case has no uses; with one, upstream reads
		// .github/renovate.json first (npm only), Renovate the root
		{"RenovateFirstValidConfigWins", "actions/checkout@v4", map[string]string{".github/renovate.json": `{"packageRules": [{"matchManagers": ["npm"]}]}`, "renovate.json": `{"extends": ["config:recommended"]}`}, 1, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string]string{".github/workflows/test.yaml": "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + c.uses + "\n"}
			for n, text := range c.files {
				files[n] = text
			}
			for n, text := range files {
				p := filepath.Join(dir, n)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			out := run(t, args("--root", dir, "--rule", "dependabot-github-actions"))
			var rep struct {
				QualityFindings []struct {
					Certainty string `json:"certainty"`
				} `json:"quality_findings"`
			}
			if err := json.Unmarshal([]byte(out.stdout), &rep); err != nil {
				t.Fatalf("%v: %s %s", err, out.stdout, out.stderr)
			}
			if len(rep.QualityFindings) != c.got {
				t.Errorf("%d findings, want %d (upstream %d)", len(rep.QualityFindings), c.got, c.upstream)
			}
			for _, f := range rep.QualityFindings {
				if f.Certainty != "confirmed" {
					t.Errorf("a finding is %s", f.Certainty)
				}
			}
		})
	}
}
