package shell

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gh-intel/sisakulint/actions/internal/enumtest"
	"github.com/gh-intel/sisakulint/actions/internal/jsonschema"
	"github.com/gh-intel/sisakulint/actions/internal/releasetable"
)

func commandsSchema(t *testing.T) *jsonschema.Set {
	t.Helper()
	b, err := os.ReadFile("schema/commands.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := jsonschema.Load(map[string][]byte{"commands.json": b}, jsonschema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestCommandTraitAndReading: the values of CommandTrait and
// ArgumentReading, by enumtest.Check.
func TestCommandTraitAndReading(t *testing.T) {
	s := commandsSchema(t)
	enumtest.Check(t, len(commandTraitNames), false, ParseCommandTrait, func(b []byte) error {
		return s.Validate("commands.json", "#/$defs/command-trait", b)
	})
	enumtest.Check(t, len(argumentReadingNames), false, ParseArgumentReading, func(b []byte) error {
		return s.Validate("commands.json", "#/$defs/argument-reading", b)
	})
}

// TestCommandNamed: a command by its name, by the pattern of its version,
// and not by a subcommand's entry.
func TestCommandNamed(t *testing.T) {
	for _, c := range []struct {
		name, want string // want: the first name of the entry, or "" for none
	}{
		{"bash", "bash"},
		{"nodejs", "node"},
		{"python", "python"},
		{"python3.12", "python"},
		{"pythonx", ""},
		{"eval", "eval"},
		{"no-such-command", ""},
	} {
		e := commandNamed(c.name)
		got := ""
		if e != nil {
			got = e.Names[0]
		}
		if got != c.want {
			t.Errorf("commandNamed(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestSpell: the spellings of an option, clustered and joined.
func TestSpell(t *testing.T) {
	shellC := CommandOption{Spellings: []string{"-c"}, Value: true, Reading: ArgumentReadingCode, Cluster: true, Joined: true}
	shortJoined := CommandOption{Spellings: []string{"-e"}, Value: true, Reading: ArgumentReadingCode, Joined: true}
	long := CommandOption{Spellings: []string{"--eval"}, Value: true, Reading: ArgumentReadingCode}
	longJoined := CommandOption{Spellings: []string{"--eval"}, Value: true, Reading: ArgumentReadingCode, Joined: true}
	clusterOnly := CommandOption{Spellings: []string{"-e"}, Value: true, Cluster: true}
	shellCNotJoined := CommandOption{Spellings: []string{"-c"}, Value: true, Reading: ArgumentReadingCode, Cluster: true}
	for _, c := range []struct {
		o            CommandOption
		w            string
		match, holds bool
	}{
		{shellC, "-c", true, false},
		{shellC, "-ec", true, false},
		{shellC, "-cecho", true, true},
		{shellC, "-ecx", true, true},
		{shellC, "-e", false, false},
		{shellC, "--c", false, false},
		{shellC, "-1c", false, false},
		{shortJoined, "-e", true, false},
		{shortJoined, "-eCODE", true, true},
		{shortJoined, "-ne", false, false},
		{long, "--eval", true, false},
		{long, "--eval=x", false, false},
		{longJoined, "--eval=x", true, true},
		{longJoined, "--evaluate", false, false},
		{clusterOnly, "-ne", true, false},
		{clusterOnly, "-nex", true, false}, // without Joined, the letters after -e are other options and the value is the next word
		{shellCNotJoined, "-cx", true, false},
		{shellCNotJoined, "-cecho", true, false},
		{shellCNotJoined, "-ec", true, false},
	} {
		m, h := c.o.spell(c.w)
		if m != c.match || h != c.holds {
			t.Errorf("%v spell(%q) = %v, %v, want %v, %v", c.o.Spellings, c.w, m, h, c.match, c.holds)
		}
	}
}

// TestCommandSources fetches the source of every quote of commands.json and
// finds its text there, only with ACTIONS_UPSTREAM=1 (it asks the
// network), before a merge.
func TestCommandSources(t *testing.T) {
	if os.Getenv(releasetable.EnvVar) != "1" {
		t.Skip(releasetable.EnvVar + "=1 fetches the sources of the quotes")
	}
	b, err := os.ReadFile("commands.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Commands []struct {
			Names   []string `json:"names"`
			Sources []struct {
				Citation string `json:"citation"`
				Text     string `json:"text"`
			} `json:"sources"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	var qs []quote
	for _, e := range f.Commands {
		for _, s := range e.Sources {
			qs = append(qs, quote{e.Names[0], s.Citation, s.Text})
		}
	}
	errs, quotes, sources := checkQuotes(&http.Client{Timeout: 60 * time.Second}, 2*time.Second, qs)
	for _, err := range errs {
		t.Error(err)
	}
	t.Logf("%d quotes of %d sources", quotes, sources)
}

// quote is a text of commands.json, the source it cites, and the first
// name of its command.
type quote struct{ command, citation, text string }

// checkQuotes fetches the source of each quote once and finds the quote's
// text there. A source that cannot be fetched is one error, and its quotes
// are not counted; a text missing from its source is one error per quote.
// quotes and sources count the quotes checked and the sources fetched.
func checkQuotes(c *http.Client, wait time.Duration, qs []quote) (errs []error, quotes, sources int) {
	bodies := map[string]string{}
	failed := map[string]bool{}
	for _, q := range qs {
		if failed[q.citation] {
			continue
		}
		body, ok := bodies[q.citation]
		if !ok {
			b, err := fetchSource(c, wait, q.citation)
			if err != nil {
				failed[q.citation] = true
				errs = append(errs, fmt.Errorf("fetch %s: %w", q.citation, err))
				continue
			}
			body, bodies[q.citation] = b, b
		}
		if !strings.Contains(body, q.text) {
			errs = append(errs, fmt.Errorf("%s: %s does not have %q", q.command, q.citation, q.text))
		}
		quotes++
	}
	return errs, quotes, len(bodies)
}

// fetchSource gets u, trying 3 times with wait between the tries: a server
// can answer with an error for a while and then serve the file again.
func fetchSource(c *http.Client, wait time.Duration, u string) (string, error) {
	var last error
	for try := range 3 {
		if try > 0 {
			time.Sleep(wait)
		}
		resp, err := c.Get(u)
		if err != nil {
			// the caller names u: keep the cause only
			if ue, ok := errors.AsType[*url.Error](err); ok {
				err = ue.Err
			}
			last = err
			continue
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		switch {
		case err != nil:
			last = err
		case resp.StatusCode != http.StatusOK:
			last = &statusError{resp.StatusCode}
		default:
			return string(b), nil
		}
	}
	return "", last
}

// statusError is an answer that is not 200.
type statusError struct{ code int }

func (e *statusError) Error() string {
	return fmt.Sprintf("HTTP %d %s", e.code, http.StatusText(e.code))
}

// TestCheckQuotes: a source that cannot be fetched is asked 3 times and
// reported once, the other sources are still checked, and a quote missing
// from its source is reported apart from a failed fetch.
func TestCheckQuotes(t *testing.T) {
	var fails, flaky atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fail":
			fails.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		case "/flaky":
			if flaky.Add(1) == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			io.WriteString(w, "hello")
		case "/ok":
			io.WriteString(w, "hello world")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	qs := []quote{
		{"a", srv.URL + "/fail", "x"},
		{"b", srv.URL + "/fail", "y"},
		{"c", srv.URL + "/flaky", "hello"},
		{"d", srv.URL + "/ok", "missing"},
		{"e", closed.URL + "/gone", "z"},
	}
	errs, quotes, sources := checkQuotes(srv.Client(), 0, qs)
	if len(errs) != 3 {
		t.Fatalf("errors %q, want 3", errs)
	}
	if prefix, got := "fetch "+closed.URL+"/gone: ", errs[2].Error(); !strings.HasPrefix(got, prefix) || strings.Count(got, closed.URL) != 1 {
		t.Errorf("third error %q, want the prefix %q and the URL once", got, prefix)
	}
	if n := flaky.Load(); n != 2 {
		t.Errorf("/flaky asked %d times, want 2", n)
	}
	if want := "fetch " + srv.URL + "/fail: HTTP 500"; !strings.HasPrefix(errs[0].Error(), want) {
		t.Errorf("first error %q, want the prefix %q", errs[0], want)
	}
	if want := "d: " + srv.URL + `/ok does not have "missing"`; errs[1].Error() != want {
		t.Errorf("second error %q, want %q", errs[1], want)
	}
	if n := fails.Load(); n != 3 {
		t.Errorf("/fail asked %d times, want 3", n)
	}
	if quotes != 2 || sources != 2 {
		t.Errorf("%d quotes of %d sources, want 2 of 2", quotes, sources)
	}
}

// TestTraitEntries: entries of git, gh, npm, setsid, nohup, curl and grep
// read, with their command traits.
func TestTraitEntries(t *testing.T) {
	for _, c := range []struct {
		name string
		sub  []string
		want []CommandTrait
	}{
		{"git", []string{"push"}, []CommandTrait{CommandTraitRunsGitDirectoryCode, CommandTraitSendsNetwork, CommandTraitWritesWithToken}},
		{"git", []string{"status"}, []CommandTrait{CommandTraitRunsGitDirectoryCode}},
		{"git", []string{"log"}, []CommandTrait{CommandTraitRunsGitDirectoryCode}},
		{"setsid", nil, []CommandTrait{CommandTraitRunsOperand, CommandTraitCodeStdin, CommandTraitStartsDetached}},
		{"gh", []string{"issue", "edit"}, []CommandTrait{CommandTraitWritesWithToken}},
		{"gh", []string{"issue", "view"}, nil},
		{"gh", []string{"api"}, []CommandTrait{CommandTraitWritesWithToken}},
		{"npm", []string{"test"}, nil},
		{"curl", nil, []CommandTrait{CommandTraitSendsNetwork}},
		{"nohup", nil, []CommandTrait{CommandTraitRunsOperand, CommandTraitCodeStdin, CommandTraitStartsDetached}},
		{"grep", nil, []CommandTrait{CommandTraitTransformsInput}},
	} {
		var e *CommandEntry
		if len(c.sub) == 0 {
			e = commandNamed(c.name)
		} else {
			e = subcommandsByKey[subcommandKey(c.name, c.sub)]
		}
		if e == nil {
			t.Errorf("no entry of %s %v", c.name, c.sub)
			continue
		}
		if !slices.Equal(e.Traits, c.want) {
			t.Errorf("%s %v: %v, want %v", c.name, c.sub, e.Traits, c.want)
		}
	}
	if e := commandNamed("timeout"); e.Operands != 1 {
		t.Errorf("timeout: operands %d, want 1", e.Operands)
	}
	if e := commandNamed("env"); !e.Assignments {
		t.Error("env: no assignments")
	}
}

// TestAttackSpellings: the spellings by which an attacker's word was seen to
// run a program, or not to, and the commands that read options after their
// operands.
func TestAttackSpellings(t *testing.T) {
	const (
		with  = AttackSpellingWithBlanks
		wout  = AttackSpellingWithoutBlanks
		words = AttackSpellingTwoWords
	)
	for _, w := range []struct {
		cmd, sub, spelling string
		attack, harmless   []AttackSpelling
		remote             bool
	}{
		{"tar", "", "--to-command", []AttackSpelling{with, wout}, nil, false},
		{"tar", "", "--use-compress-program", []AttackSpelling{with}, nil, false},
		{"sed", "", "--expression", []AttackSpelling{with, wout}, nil, false},
		{"sed", "", "-e", []AttackSpelling{with, wout, AttackSpellingNameCharacters}, nil, false},
		{"git", "clone", "-u", []AttackSpelling{with}, nil, true},
		{"tar", "", "-I", []AttackSpelling{with}, nil, false},
		{"make", "", "--eval", []AttackSpelling{with}, nil, false},
		{"git", "fetch", "--upload-pack", []AttackSpelling{with, wout}, nil, true},
		{"git", "clone", "--upload-pack", []AttackSpelling{with, wout}, nil, true},
		{"git", "pull", "--upload-pack", []AttackSpelling{with, wout}, nil, true},
		{"git", "ls-remote", "--upload-pack", []AttackSpelling{with, wout}, nil, true},
		{"bash", "", "-c", []AttackSpelling{words}, []AttackSpelling{with, wout}, false},
		{"sh", "", "-c", []AttackSpelling{words}, []AttackSpelling{with, wout}, false},
		{"dash", "", "-c", []AttackSpelling{words}, []AttackSpelling{with, wout}, false},
		{"python3", "", "-c", []AttackSpelling{wout, words}, nil, false},
		{"node", "", "--eval", []AttackSpelling{wout}, nil, false},
		{"node", "", "-e", []AttackSpelling{words}, []AttackSpelling{wout}, false},
		{"perl", "", "-e", []AttackSpelling{with, words}, nil, false},
		{"ruby", "", "-e", []AttackSpelling{with}, nil, false},
	} {
		e := commandNamed(w.cmd)
		if e != nil && w.sub != "" {
			e = subcommandOf(w.cmd, e, w.sub)
		}
		if e == nil {
			t.Fatalf("%s %s: no entry", w.cmd, w.sub)
		}
		var o *CommandOption
		for i := range e.Options {
			if slices.Contains(e.Options[i].Spellings, w.spelling) {
				o = &e.Options[i]
			}
		}
		if o == nil || !slices.Equal(o.Attack, w.attack) || !slices.Equal(o.Harmless, w.harmless) || o.Remote != w.remote || !o.Runs() {
			t.Errorf("%s %s %s: %+v", w.cmd, w.sub, w.spelling, o)
		}
	}
	for _, c := range []struct {
		cmd, sub string
		after    bool
	}{{"tar", "", true}, {"sed", "", true}, {"make", "", true}, {"git", "fetch", true}, {"git", "clone", true}, {"git", "pull", true}, {"git", "ls-remote", false}, {"bash", "", false}, {"python3", "", false}} {
		e := commandNamed(c.cmd)
		if c.sub != "" {
			e = subcommandOf(c.cmd, e, c.sub)
		}
		if e.OptionsAfterOperands != c.after {
			t.Errorf("%s %s: options after operands %v", c.cmd, c.sub, e.OptionsAfterOperands)
		}
	}
	// sed -i takes its suffix in the same word only
	if o, holds := commandNamed("sed").option("-i"); o == nil || o.Value || holds {
		t.Errorf("sed -i: %+v", o)
	}
}

// TestTransformAndDigestTraits: the commands whose output is made from
// their input (transforms-input) or is a digest or count of it
// (digests-input), which secret-in-log reads.
func TestTransformAndDigestTraits(t *testing.T) {
	for _, name := range []string{"jq", "base64", "rev", "xxd", "od", "hexdump", "fold", "cut", "tr", "sed", "head", "tail", "grep", "sort", "uniq"} {
		if e := commandNamed(name); e == nil || !e.Has(CommandTraitTransformsInput) {
			t.Errorf("%s: no transforms-input", name)
		}
	}
	for _, name := range []string{"sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum", "md5sum", "b2sum", "cksum", "wc"} {
		if e := commandNamed(name); e == nil || !e.Has(CommandTraitDigestsInput) {
			t.Errorf("%s: no digests-input", name)
		}
	}
	for _, name := range []string{"cat", "echo", "printf", "curl"} {
		if e := commandNamed(name); e != nil && (e.Has(CommandTraitTransformsInput) || e.Has(CommandTraitDigestsInput)) {
			t.Errorf("%s: %v", name, e.Traits)
		}
	}
}
