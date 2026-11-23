package shell

import (
	"bufio"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/internal/enumtest"
)

// TestRequestReading: the values of RequestReading, by enumtest.Check.
func TestRequestReading(t *testing.T) {
	s := commandsSchema(t)
	enumtest.Check(t, len(requestReadingNames), false, ParseRequestReading, func(b []byte) error {
		return s.Validate("commands.json", "#/$defs/request-reading", b)
	})
}

// requestEntry is the entry of curl, wget or gh api.
func requestEntry(t *testing.T, cmd string) *CommandEntry {
	t.Helper()
	if cmd == "gh api" {
		return subcommandOf("gh", commandNamed("gh"), "api")
	}
	return commandNamed(cmd)
}

// optionList is the spellings of testdata/<file>, one a line, # for a
// comment.
func optionList(t *testing.T, file string) []string {
	t.Helper()
	f, err := os.Open("testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// TestRequestOptionsDeclared: the entries of curl, wget and gh api declare
// with a value every option the sources say takes one, and no other.
func TestRequestOptionsDeclared(t *testing.T) {
	for _, c := range []struct{ cmd, file string }{
		{"curl", "curl-options.txt"},
		{"wget", "wget-options.txt"},
		{"gh api", "gh-api-options.txt"},
	} {
		e := requestEntry(t, c.cmd)
		if e == nil {
			t.Fatalf("%s: no entry", c.cmd)
		}
		want := optionList(t, c.file)
		for _, s := range want {
			o, holds := e.option(s)
			if o == nil || !o.Value || holds {
				t.Errorf("%s %s: option %v, holds %v; want an option with a value", c.cmd, s, o, holds)
			}
		}
		for _, o := range e.Options {
			for _, s := range o.Spellings {
				if o.Value && !slices.Contains(want, s) {
					t.Errorf("%s %s takes a value, not in testdata/%s", c.cmd, s, c.file)
				}
			}
		}
		if !e.OptionsAfterOperands {
			t.Errorf("%s: OptionsAfterOperands false; it reads an option after its URL (l2, l3)", c.cmd)
		}
	}
}

// TestRequestReadings: the request readings of the options and operands of
// curl, wget and gh api.
func TestRequestReadings(t *testing.T) {
	for _, c := range []struct {
		cmd, spelling string
		want          RequestReading
	}{
		{"curl", "--url", RequestReadingDestination},
		{"curl", "-H", RequestReadingCredential},
		{"curl", "--header", RequestReadingCredential},
		{"curl", "-u", RequestReadingCredential},
		{"curl", "--user", RequestReadingCredential},
		{"curl", "--oauth2-bearer", RequestReadingCredential},
		{"curl", "-b", RequestReadingCredential},
		{"curl", "--cookie", RequestReadingCredential},
		{"curl", "-d", RequestReadingCredential},
		{"curl", "--data", RequestReadingCredential},
		{"curl", "--data-raw", RequestReadingCredential},
		{"curl", "--data-binary", RequestReadingCredential},
		{"curl", "--data-urlencode", RequestReadingCredential},
		{"curl", "-F", RequestReadingCredential},
		{"curl", "--form", RequestReadingCredential},
		{"curl", "--form-string", RequestReadingCredential},
		{"curl", "-o", RequestReadingUnset},
		{"wget", "--header", RequestReadingCredential},
		{"wget", "--user", RequestReadingCredential},
		{"wget", "--password", RequestReadingCredential},
		{"wget", "--http-user", RequestReadingCredential},
		{"wget", "--http-password", RequestReadingCredential},
		{"wget", "--post-data", RequestReadingCredential},
		{"wget", "--body-data", RequestReadingCredential},
		{"wget", "-O", RequestReadingUnset},
		{"gh api", "-H", RequestReadingCredential},
		{"gh api", "--header", RequestReadingCredential},
		{"gh api", "-f", RequestReadingCredential},
		{"gh api", "--raw-field", RequestReadingCredential},
		{"gh api", "-F", RequestReadingCredential},
		{"gh api", "--field", RequestReadingCredential},
		{"gh api", "--hostname", RequestReadingHostname},
		{"gh api", "-X", RequestReadingUnset},
	} {
		o, _ := requestEntry(t, c.cmd).option(c.spelling)
		if o == nil {
			t.Errorf("%s %s: no option", c.cmd, c.spelling)
			continue
		}
		if o.Request != c.want {
			t.Errorf("%s %s: Request %v, want %v", c.cmd, c.spelling, o.Request, c.want)
		}
	}
	for _, c := range []struct {
		cmd  string
		want RequestReading
	}{
		{"curl", RequestReadingDestination},
		{"wget", RequestReadingDestination},
		{"gh api", RequestReadingEndpoint},
	} {
		if got := requestEntry(t, c.cmd).OperandRequest; got != c.want {
			t.Errorf("%s: OperandRequest %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestRequestOptionSpellings: the value joined to the option, and short
// options run together, as each command reads them.
func TestRequestOptionSpellings(t *testing.T) {
	for _, c := range []struct {
		cmd, word, want string
		holds           bool
	}{
		{"curl", "-HAuthorization: x", "-H", true},
		{"curl", "--header=Authorization: x", "--header", true},
		{"curl", "-sSfH", "-H", false},
		{"wget", "--header=X: y", "--header", true},
		{"wget", "-qO-", "-O", true},
		{"gh api", "--header=X: y", "--header", true},
		{"gh api", "-HX: y", "-H", true},
	} {
		o, holds := requestEntry(t, c.cmd).option(c.word)
		if o == nil || !slices.Contains(o.Spellings, c.want) || holds != c.holds {
			t.Errorf("%s %q: option %v, holds %v; want %s, holds %v", c.cmd, c.word, o, holds, c.want, c.holds)
		}
	}
}
