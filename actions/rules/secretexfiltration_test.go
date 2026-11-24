package rules

import (
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// exfilStore is a file of facts with entries.
func exfilStore(t *testing.T, entries ...string) *facts.Store {
	t.Helper()
	s, err := facts.LoadStore([]byte(`{"schema":"sisakulint/facts/v0","facts":[` + strings.Join(entries, ",") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// trusted is an entry of a file of facts that trusts the pair.
func trusted(secret, destination string, v bool) string {
	b := "false"
	if v {
		b = "true"
	}
	return `{"query":{"kind":"request.destination-trusted","secret":"` + secret + `","destination":"` + destination + `"},"state":"found","value":` + b + `}`
}

// exfilResults are the findings of rules on files with r, as
// "<kind> <secret> <destination> <certainty>", and the inconclusive kinds.
func exfilResults(t *testing.T, rules []lint.Rule, files map[string]string, r facts.Resolver) []string {
	t.Helper()
	rep, _, _ := checkRules(t, rules, files, r)
	var out []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		switch a := f.Args.(type) {
		case SecretExfiltrationUntrustedDestination:
			out = append(out, "untrusted-destination "+a.Secret+" "+a.Destination+" "+f.Certainty.String())
		default:
			out = append(out, f.Args.KindID().String())
		}
	}
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		out = append(out, g.InconclusiveKind.String())
	}
	return out
}

// exfilRun is a workflow on push whose job runs on runsOn, with env, and
// one step of run.
func exfilRun(runsOn, env, run string) map[string]string {
	return wfFile("on: push\njobs:\n  j:\n    runs-on: " + runsOn + "\n    env:\n      T: ${{ secrets.T }}\n      U: ${{ secrets.U }}\n" + env + "    steps:\n      - run: |\n          " + strings.ReplaceAll(run, "\n", "\n          ") + "\n")
}

var exfilRules = []lint.Rule{SecretExfiltration}

// TestSecretExfiltrationTrusted: a pair the file of facts trusts gives
// nothing; another secret to the same host still gives a finding.
func TestSecretExfiltrationTrusted(t *testing.T) {
	files := exfilRun("ubuntu-latest", "", `curl -H "A: $T" -H "B: $U" https://API.example.com/x`)
	got := exfilResults(t, exfilRules, files, exfilStore(t, trusted("t", "api.example.com", true)))
	if want := []string{"untrusted-destination U api.example.com conditional"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	// a named destination
	named := exfilRun("ubuntu-latest", "", `curl -d "$T" "${{ secrets.UPLOAD_API }}"`)
	got = exfilResults(t, exfilRules, named, exfilStore(t, trusted("T", "${{ secrets.UPLOAD_API }}", true)))
	if len(got) != 0 {
		t.Errorf("named, trusted: %q", got)
	}
	got = exfilResults(t, exfilRules, named, exfilStore(t))
	if want := []string{"untrusted-destination T ${{ secrets.upload_api }} conditional"}; !slices.Equal(got, want) {
		t.Errorf("named: got %q, want %q", got, want)
	}
}

// TestSecretExfiltrationUnknownFacts: a fixed host and no answer to
// request.destination-trusted: the finding is conditional.
func TestSecretExfiltrationUnknownFacts(t *testing.T) {
	got := exfilResults(t, exfilRules, exfilRun("ubuntu-latest", "", `curl -H "A: $T" https://api.example.com/x`), exfilStore(t))
	if want := []string{"untrusted-destination T api.example.com conditional"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestSecretExfiltrationExclusions: GitHub's hosts, a service of the job,
// and localhost on a GitHub-hosted runner give nothing; localhost on a
// self-hosted runner gives a finding.
func TestSecretExfiltrationExclusions(t *testing.T) {
	for _, run := range []string{
		`curl -H "A: $T" https://api.github.com/x`,
		`curl -H "A: $T" https://uploads.github.com/x`,
		`curl -H "A: $T" "$GITHUB_API_URL/repos/x"`,
		`curl -H "A: $T" "${{ github.server_url }}/x"`,
		`gh api repos/x -H "A: $T"`,
		`curl -u "admin:$T" http://localhost:9200/`,
		`curl -u "admin:$T" http://127.0.0.1:9200/`,
		`curl -u "admin:$T" "http://[::1]:9200/"`,
	} {
		if got := exfilResults(t, exfilRules, exfilRun("ubuntu-latest", "", run), exfilStore(t)); len(got) != 0 {
			t.Errorf("%s: %q", run, got)
		}
	}
	service := wfFile("on: push\njobs:\n  j:\n    runs-on: [self-hosted, linux]\n    services:\n      db:\n        image: postgres\n    steps:\n      - shell: bash\n        env:\n          T: ${{ secrets.T }}\n        run: |\n          curl -u \"admin:$T\" http://db:9200/\n")
	if got := exfilResults(t, exfilRules, service, exfilStore(t)); len(got) != 0 {
		t.Errorf("service: %q", got)
	}
	self := wfFile("on: push\njobs:\n  j:\n    runs-on: [self-hosted, linux]\n    steps:\n      - shell: bash\n        env:\n          T: ${{ secrets.T }}\n        run: |\n          curl -u \"admin:$T\" http://localhost:9200/\n")
	if got, want := exfilResults(t, exfilRules, self, exfilStore(t)), []string{"untrusted-destination T localhost conditional"}; !slices.Equal(got, want) {
		t.Errorf("self-hosted localhost: got %q, want %q", got, want)
	}
}

// TestSecretExfiltrationUnnamed: a destination with no name of its origin
// is inconclusive.
func TestSecretExfiltrationUnnamed(t *testing.T) {
	got := exfilResults(t, exfilRules, exfilRun("ubuntu-latest", "", "URL=$(curl -s https://api.github.com/x | jq -r .url)\ncurl -H \"A: $T\" \"$URL\""), exfilStore(t))
	if want := []string{"destination-unknown"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestSecretExfiltrationNoOverlap: a host an attacker decides is
// request-forgery's alone.
func TestSecretExfiltrationNoOverlap(t *testing.T) {
	files := wfFile("on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      T: ${{ secrets.T }}\n    steps:\n      - run: |\n          curl -H \"A: $T\" \"https://${{ github.event.issue.title }}/x\"\n")
	got := exfilResults(t, []lint.Rule{SecretExfiltration, RequestForgery}, files, exfilStore(t))
	if want := []string{"request-forgery.credential-host"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestSecretExfiltrationToken: the job's token is the secret GITHUB_TOKEN of
// the fact.
func TestSecretExfiltrationToken(t *testing.T) {
	got := exfilResults(t, exfilRules, exfilRun("ubuntu-latest", "", `curl -H "Authorization: token ${{ github.token }}" https://coveralls.io/api`), exfilStore(t))
	if want := []string{"untrusted-destination GITHUB_TOKEN coveralls.io conditional"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestSecretExfiltrationHostForms: a named host with an attacker's path,
// the runner's own address, and named destinations by the case of their
// path.
func TestSecretExfiltrationHostForms(t *testing.T) {
	// a named host and an attacker's value in the path, through env
	files := wfFile("on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      T: ${{ secrets.T }}\n      URL: ${{ vars.BASE }}/${{ github.event.issue.title }}\n    steps:\n      - run: |\n          curl -H \"A: $T\" \"$URL\"\n")
	if got, want := exfilResults(t, []lint.Rule{SecretExfiltration, RequestForgery}, files, exfilStore(t)), []string{"untrusted-destination T ${{ vars.base }} conditional"}; !slices.Equal(got, want) {
		t.Errorf("a named host with an attacker's path: got %q, want %q", got, want)
	}
	// 0.0.0.0 is the runner itself
	if got := exfilResults(t, exfilRules, exfilRun("ubuntu-latest", "", `curl -u "admin:$T" http://0.0.0.0:9200/`), exfilStore(t)); len(got) != 0 {
		t.Errorf("0.0.0.0: %q", got)
	}
	// a named destination is answered whatever the case of its path
	named := exfilRun("ubuntu-latest", "", `curl -d "$T" "${{ secrets.UPLOAD_API }}"`)
	if got := exfilResults(t, exfilRules, named, exfilStore(t, trusted("T", "${{ secrets.upload_api }}", true))); len(got) != 0 {
		t.Errorf("case of the path: %q", got)
	}
}

// TestExfiltrationFingerprintPerStep: removing a request of a step before
// does not change the Fingerprint of the same request in a step after.
func TestExfiltrationFingerprintPerStep(t *testing.T) {
	step := "      - run: |\n          curl -H \"A: ${{ secrets.T }}\" \"https://${{ github.event.issue.title }}/x\"\n          curl -H \"A: ${{ secrets.T }}\" https://api.example.com/x\n"
	two := wfFile("on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + step + step)
	one := wfFile("on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n" + step)
	rules := []lint.Rule{SecretExfiltration, RequestForgery}
	a, _, _ := checkRules(t, rules, two, exfilStore(t))
	b, _, _ := checkRules(t, rules, one, exfilStore(t))
	if len(a.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 4 || len(b.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 2 {
		t.Fatalf("findings: %d, %d", len(a.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)), len(b.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
	var last []string
	for _, f := range a.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[2:] {
		last = append(last, f.Fingerprint.String())
	}
	for _, f := range b.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if !slices.Contains(last, f.Fingerprint.String()) {
			t.Errorf("%s: Fingerprint %s changed", f.Args.KindID(), f.Fingerprint)
		}
	}
}
