package boundary

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// Quote is a text, word for word, of a file of GitHub's documents or data,
// or of the documents of the maker of a tool a workflow runs (Docker, curl),
// at a pinned commit.
type Quote struct {
	Citation lint.Citation // an https URL of the source pinned to a commit
	Text     string        // as the source has it
	// JSONPointer is where in a JSON file Text is: within the text of the
	// value it points to, as the file has it. The zero JSONPointer is the
	// whole file, JSON or not.
	JSONPointer JSONPointer
	Retrieved   lint.Date
}

// FoundIn is whether source, the whole file of the quote, has Text where
// JSONPointer points. A file that is not JSON, and a value that is not
// there, do not have it.
func (q Quote) FoundIn(source []byte) bool {
	if q.JSONPointer.IsZero() {
		return bytes.Contains(source, []byte(q.Text))
	}
	v := json.RawMessage(source)
	for _, token := range q.JSONPointer.tokens() {
		var next json.RawMessage
		var object map[string]json.RawMessage
		var array []json.RawMessage
		switch {
		case json.Unmarshal(v, &object) == nil && object != nil:
			x, ok := object[token]
			if !ok {
				return false
			}
			next = x
		case json.Unmarshal(v, &array) == nil && array != nil:
			i, err := strconv.Atoi(token)
			if err != nil || i < 0 || i >= len(array) || strconv.Itoa(i) != token {
				return false
			}
			next = array[i]
		default:
			return false
		}
		v = next
	}
	return bytes.Contains(v, []byte(q.Text))
}

// JSONPointer is a JSON pointer (RFC 6901, https://www.rfc-editor.org/rfc/rfc6901):
// the zero JSONPointer, as the empty string, is the whole document; any
// other starts with a slash, each slash before a reference token, with ~0
// for a tilde and ~1 for a slash in a token.
type JSONPointer struct{ text string }

// ParseJSONPointer reads s as a JSON pointer.
func ParseJSONPointer(s string) (JSONPointer, error) {
	if s != "" && !strings.HasPrefix(s, "/") {
		return JSONPointer{}, fmt.Errorf("the JSON pointer %q does not start with a slash", s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '~' && (i+1 == len(s) || (s[i+1] != '0' && s[i+1] != '1')) {
			return JSONPointer{}, fmt.Errorf("the JSON pointer %q has a tilde not followed by 0 or 1", s)
		}
	}
	return JSONPointer{s}, nil
}

// MustJSONPointer is ParseJSONPointer for the tables of the package: a
// pointer it cannot read is a bug.
func MustJSONPointer(s string) JSONPointer {
	p, err := ParseJSONPointer(s)
	if err != nil {
		panic("boundary: " + err.Error())
	}
	return p
}

func (p JSONPointer) String() string { return p.text }

// IsZero is whether p is the whole document.
func (p JSONPointer) IsZero() bool { return p.text == "" }

// tokens are the reference tokens of p, unescaped.
func (p JSONPointer) tokens() []string {
	if p.IsZero() {
		return nil
	}
	r := strings.NewReplacer("~1", "/", "~0", "~")
	parts := strings.Split(p.text[1:], "/")
	for i, t := range parts {
		parts[i] = r.Replace(t)
	}
	return parts
}

// RunRef names the RunGrant rows of an event and a head.
type RunRef struct {
	Event workflow.EventName
	Head  PRHead
}

// RunGrant is what GitHub gives a run of Event and Head when Condition
// holds: Token is the most its workflow may ask for in permissions (a
// workflow that asks less, or the default of the repository, gives less),
// and Cache the most it may have of the cache of the default branch's
// scope, by default or by cache-mode (a workflow that asks read gives
// less).
type RunGrant struct {
	Event       workflow.EventName
	Head        PRHead
	Condition   lint.Condition // the zero Condition always holds
	Token       Access
	Cache       Access
	Secrets     SecretsAccess
	Basis       Basis
	Quotes      []Quote
	Observed    []lint.Observation
	Uncertainty string // with BasisUnverified: what is not certain
}

// RoleBaseline is what one of Role holds when Condition holds, before any
// flaw of a workflow: the runs their own code runs in, and whether their
// own run can be on a self-hosted runner of the repository.
type RoleBaseline struct {
	Role             Role
	Condition        lint.Condition
	Runs             []RunRef
	SelfHostedRunner expr.Truth // no fact tells the runner groups yet
	Basis            Basis
	Quotes           []Quote
	Observed         []lint.Observation
	Uncertainty      string
}

// Channel is whether one of Role can write what Attacker writes (open an
// issue, comment, open a pull request from a fork) when Condition holds.
type Channel struct {
	Attacker    lint.Attacker
	Role        Role
	Condition   lint.Condition
	Writable    bool
	Basis       Basis
	Quotes      []Quote
	Observed    []lint.Observation
	Uncertainty string
}

// Pathway is whether one of Role gets at what a run of the workflow holds
// the way Attacker does, with no event, when Condition holds: downloads an
// artifact of the run, views the log of the run, has code of theirs run in
// a job of the run, or receives what a job of the run sends. Usable is not
// known only of a row whose basis is unverified.
type Pathway struct {
	Attacker    lint.Attacker
	Role        Role
	Condition   lint.Condition
	Usable      expr.Truth
	Basis       Basis
	Quotes      []Quote
	Observed    []lint.Observation
	Uncertainty string
}

// commitPath is a commit in the path of a URL: a quote of a branch would
// move.
var commitPath = regexp.MustCompile(`/[0-9a-f]{40}/`)

// checkGrounds checks that the grounds fit the basis.
func checkGrounds(b Basis, qs []Quote, os []lint.Observation, uncertainty string) error {
	switch b {
	case BasisDocumented:
		if len(qs) == 0 {
			return errors.New("documented without a quote")
		}
	case BasisObserved:
		if len(os) == 0 {
			return errors.New("observed without an observation")
		}
	case BasisUnverified:
		if uncertainty == "" {
			return errors.New("unverified without what is uncertain")
		}
	default:
		return errors.New("no basis")
	}
	for _, q := range qs {
		switch {
		case !commitPath.MatchString(q.Citation.String()):
			return fmt.Errorf("the quote of %s is not pinned to a commit", q.Citation)
		case q.Text == "":
			return fmt.Errorf("the quote of %s has no text", q.Citation)
		case q.Retrieved.IsZero():
			return fmt.Errorf("the quote of %s has no date", q.Citation)
		case !q.JSONPointer.IsZero() && !strings.HasSuffix(q.Citation.String(), ".json"):
			return fmt.Errorf("the quote of %s has a JSON pointer, but the file is not JSON", q.Citation)
		}
	}
	for _, o := range os {
		if o.Date.IsZero() || o.What == "" {
			return errors.New("an observation without a date or what was seen")
		}
	}
	return nil
}

func (g RunGrant) check() error {
	switch {
	case g.Event == workflow.EventNameUnset:
		return errors.New("no event")
	case g.Head == PRHeadUnset:
		return fmt.Errorf("%s: no head", g.Event)
	case g.Token == AccessUnset:
		return fmt.Errorf("%s %s: no token", g.Event, g.Head)
	case g.Cache == AccessUnset:
		return fmt.Errorf("%s %s: no cache", g.Event, g.Head)
	case g.Secrets == SecretsAccessUnset:
		return fmt.Errorf("%s %s: no secrets", g.Event, g.Head)
	}
	if err := checkGrounds(g.Basis, g.Quotes, g.Observed, g.Uncertainty); err != nil {
		return fmt.Errorf("%s %s: %w", g.Event, g.Head, err)
	}
	return nil
}

func (r RoleBaseline) check() error {
	if r.Role == RoleUnset {
		return errors.New("no role")
	}
	for _, ref := range r.Runs {
		if ref.Event == workflow.EventNameUnset || ref.Head == PRHeadUnset {
			return fmt.Errorf("%s: a run with no event or head", r.Role)
		}
	}
	if err := checkGrounds(r.Basis, r.Quotes, r.Observed, r.Uncertainty); err != nil {
		return fmt.Errorf("%s: %w", r.Role, err)
	}
	return nil
}

func (c Channel) check() error {
	switch {
	case c.Attacker == lint.AttackerUnset:
		return errors.New("no attacker")
	case c.Role == RoleUnset:
		return fmt.Errorf("%s: no role", c.Attacker)
	}
	if err := checkGrounds(c.Basis, c.Quotes, c.Observed, c.Uncertainty); err != nil {
		return fmt.Errorf("%s %s: %w", c.Attacker, c.Role, err)
	}
	return nil
}

func (p Pathway) check() error {
	switch {
	case p.Attacker == lint.AttackerUnset:
		return errors.New("no attacker")
	case p.Role == RoleUnset:
		return fmt.Errorf("%s: no role", p.Attacker)
	case p.Usable == expr.TruthUnknown && p.Basis != BasisUnverified:
		return fmt.Errorf("%s %s: usable not known, but the basis is %s", p.Attacker, p.Role, p.Basis)
	}
	if err := checkGrounds(p.Basis, p.Quotes, p.Observed, p.Uncertainty); err != nil {
		return fmt.Errorf("%s %s: %w", p.Attacker, p.Role, err)
	}
	return nil
}
