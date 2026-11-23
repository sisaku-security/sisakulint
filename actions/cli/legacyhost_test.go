package cli

import (
	"reflect"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
)

func TestParseLegacyHost(t *testing.T) {
	for _, tc := range []struct {
		entry string
		want  legacyHost
	}{
		{"api.example.com", legacyHost{"api.example.com", false}},
		{"API.Example.com", legacyHost{"api.example.com", false}},
		{"*.example.com", legacyHost{"example.com", true}},
		{`"'quoted.example.com'"`, legacyHost{"quoted.example.com", false}},
		{" spaced.example.com ", legacyHost{"spaced.example.com", false}},
		{"::1", legacyHost{"[::1]", false}},
		{"[::1]", legacyHost{"[::1]", false}},
		{"2001:DB8::1", legacyHost{"[2001:db8::1]", false}},
	} {
		got, err := parseLegacyHost(tc.entry)
		if err != nil || got != tc.want {
			t.Errorf("parseLegacyHost(%q) = %+v, %v; want %+v", tc.entry, got, err, tc.want)
		}
	}
	for _, entry := range []string{"", "https://a.example.com", "a.example.com/b", "a.example.com:443", "[::1]:443", "[::1", "[127.0.0.1]", "1:2", "*", "a.*.b", "*.", "*.*.b", "a b", "a@b", "a?b", "a#b"} {
		if got, err := parseLegacyHost(entry); err == nil {
			t.Errorf("parseLegacyHost(%q) = %+v, want an error", entry, got)
		}
	}
}

func pair(t *testing.T, secret, destination, file string) destinationPair {
	t.Helper()
	s, err := facts.ParseSecretName(secret)
	if err != nil {
		t.Fatal(err)
	}
	d, err := facts.ParseRequestDestination(destination)
	if err != nil {
		t.Fatal(err)
	}
	return destinationPair{facts.RequestDestinationTrusted{Secret: s, Destination: d}, facts.MustCleanInputPath(file)}
}

func TestLegacyAllowedHosts(t *testing.T) {
	const a, b = ".github/workflows/a.yml", ".github/workflows/b.yml"
	pairs := []destinationPair{
		pair(t, "TOKEN", "evil.example.com", a),
		pair(t, "TOKEN", "api.example.com", a),
		pair(t, "TOKEN", "api.example.com", b),
		pair(t, "TOKEN", "api.example.com", a), // another step
		pair(t, "T2", "example.com", a),
		pair(t, "T3", "${{ vars.hook }}", a),
		pair(t, "T4", "other.example.net", a),
		pair(t, "T4", "other.example.net", b),
		pair(t, "T5", "[::1]", a),
	}
	entries := []legacyItem{{"api.example.com", 3}, {"*.example.com", 4}, {"unused.example.org", 5}, {"https://x", 6}, {"::1", 7}}
	directives := []legacyDirective{{legacyItem{"other.example.net", 1}, facts.MustCleanInputPath(b)}, {legacyItem{"nothing.example.net", 1}, facts.MustCleanInputPath(b)}}
	got, notes := legacyAllowedHosts(entries, directives, pairs)

	var texts []string
	for _, f := range got {
		texts = append(texts, f.factText())
		if f.kind != facts.KindRequestDestinationTrusted || f.value != "true" {
			t.Errorf("%s: kind, value = %v, %q", f.factText(), f.kind, f.value)
		}
		if !mentions(f.notes, "secret", "Finding") && !mentions(f.notes, "another secret") {
			t.Errorf("%s: no note on the pairs of now: %q", f.factText(), f.notes)
		}
	}
	want := []string{
		"request.destination-trusted[secret=T4,destination=other.example.net]=true",
		"request.destination-trusted[secret=T5,destination=[::1]]=true",
		"request.destination-trusted[secret=TOKEN,destination=api.example.com]=true",
		"request.destination-trusted[secret=TOKEN,destination=evil.example.com]=true",
	}
	if !reflect.DeepEqual(texts, want) {
		t.Errorf("facts =\n%q\nwant\n%q", texts, want)
	}
	for _, f := range got {
		fromDirective := f.factText() == want[0]
		if fromDirective != mentions(f.notes, "directive", "every workflow", b) {
			t.Errorf("%s: the note of a directive is %v, want %v: %q", f.factText(), !fromDirective, fromDirective, f.notes)
		}
	}
	n := noteTexts(notes)
	if len(n) != 3 || !mentions(n, `"unused.example.org"`, "line 5", "no workflow") || !mentions(n, `"https://x"`, "line 6") || !mentions(n, `"nothing.example.net"`, b, "does not send") {
		t.Errorf("notes = %q", n)
	}
}

func TestLegacyAllowedHostsDirectiveOfOneFile(t *testing.T) {
	// The directive in b.yml counts the pairs of b.yml only: a pair only
	// in a.yml is not written.
	pairs := []destinationPair{pair(t, "TOKEN", "x.example.com", ".github/workflows/a.yml")}
	got, notes := legacyAllowedHosts(nil, []legacyDirective{{legacyItem{"x.example.com", 1}, facts.MustCleanInputPath(".github/workflows/b.yml")}}, pairs)
	if len(got) != 0 || len(notes) != 1 {
		t.Errorf("facts %d, notes %q; want none and one note", len(got), noteTexts(notes))
	}
}
