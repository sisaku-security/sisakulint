package facts

import (
	"context"
	"testing"
)

func TestParseSecretName(t *testing.T) {
	for in, want := range map[string]string{"gh_pat": "GH_PAT", "API_KEY": "API_KEY", "_x1": "_X1"} {
		if n, err := ParseSecretName(in); err != nil || n.String() != want {
			t.Errorf("ParseSecretName(%q) = %v, %v; want %s", in, n, err, want)
		}
	}
	for _, bad := range []string{"", "1x", "a-b", "a b"} {
		if _, err := ParseSecretName(bad); err == nil {
			t.Errorf("ParseSecretName(%q): no error", bad)
		}
	}
}

func TestParseRequestDestination(t *testing.T) {
	for in, want := range map[string]string{"API.Example.com": "api.example.com", "localhost": "localhost", "github.com": "github.com", "${{ secrets.UPLOAD_API }}": "${{ secrets.upload_api }}", "${{ vars.HOOK }}": "${{ vars.hook }}", "under_score.example": "under_score.example", "${{ github.event.client_payload.url }}": "${{ github.event.client_payload.url }}"} {
		if d, err := ParseRequestDestination(in); err != nil || d.String() != want {
			t.Errorf("ParseRequestDestination(%q) = %v, %v; want %s", in, d, err, want)
		}
	}
	for _, bad := range []string{"", "api.example.com:443", "https://api.example.com", "api.example.com/x", "a b", "${{secrets.X}}", "${{ format('a') }}"} {
		if _, err := ParseRequestDestination(bad); err == nil {
			t.Errorf("ParseRequestDestination(%q): no error", bad)
		}
	}
}

// TestRequestDestinationTrustedAssumption: no answer is the worst case,
// that the destination is not trusted, marked as assumed.
func TestRequestDestinationTrustedAssumption(t *testing.T) {
	q := RequestDestinationTrusted{Secret: MustSecretName("T"), Destination: MustRequestDestination("api.example.com")}
	ctx := context.Background()
	if r := q.Ask(ctx, Assumptions()); r.State != StateFound || r.Value {
		t.Errorf("assumed %+v, want found false", r)
	}
	if raw := Checked(q, Assumptions().Resolve(ctx, q)); !raw.Assumed() {
		t.Errorf("not assumed: %+v", raw)
	}
	b, err := EncodeQuery(q)
	if err != nil || string(b) != `{"kind":"request.destination-trusted","secret":"T","destination":"api.example.com"}` {
		t.Errorf("EncodeQuery = %s, %v", b, err)
	}
}

func TestParseConfigurationVariableName(t *testing.T) {
	for in, want := range map[string]string{"mascot": "MASCOT", "RUNNERS": "RUNNERS", "_x1": "_X1", "GITHUB": "GITHUB", "github": "GITHUB", "GITHUBX": "GITHUBX"} {
		if n, err := ParseConfigurationVariableName(in); err != nil || n.String() != want {
			t.Errorf("ParseConfigurationVariableName(%q) = %v, %v; want %s", in, n, err, want)
		}
	}
	// github_x, GITHUB_Y, 1X and a-b are the names GitHub's API refused to
	// create on 2026-11-03 (HTTP 422)
	for _, bad := range []string{"", "github_x", "GITHUB_Y", "Github_z", "1X", "a-b", "a b", "é"} {
		if _, err := ParseConfigurationVariableName(bad); err == nil {
			t.Errorf("ParseConfigurationVariableName(%q): no error", bad)
		}
	}
}

func TestConfigurationVariablesAnswer(t *testing.T) {
	ctx := context.Background()
	s, err := LoadStore([]byte(`{"schema":"sisakulint/facts/v0","facts":[{"query":{"kind":"repo.configuration-variables"},"state":"found","value":["mascot","RUNNERS"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	a := RepoConfigurationVariables{}.Ask(ctx, s)
	if a.State != StateFound || len(a.Value) != 2 || a.Value[0] != MustConfigurationVariableName("MASCOT") {
		t.Fatalf("answer = %+v; want MASCOT and RUNNERS", a)
	}
	if _, err := LoadStore([]byte(`{"schema":"sisakulint/facts/v0","facts":[{"query":{"kind":"repo.configuration-variables"},"state":"found","value":["github_x"]}]}`)); err == nil {
		t.Error("a file of facts with the name github_x: no error")
	}
}
