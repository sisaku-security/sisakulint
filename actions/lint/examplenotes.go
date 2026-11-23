package lint

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// ExampleNotes say what an example is about, written as the comments its
// file starts with (# situation: …, # reason: …, # cause: …).
type ExampleNotes struct {
	Situation string // what the workflow does
	Reason    string // why it is what its declaration says
	// Cause is what of the rule makes its verdict differ from the harm: for
	// a false positive, why it reports; for an undetected form, why it does
	// not. A true positive or negative has none.
	Cause string
	// Attack is what an attacker does, when it is not a string they put in
	// (# attack: …): a tag they move, the time of a push.
	Attack string
	// AttackValue is the string an attacker puts in, and where it goes
	// (# attack-value: <carrier> = "<Go quoted string>").
	AttackValue AttackValue
	// AttackRunBehavior is what the run does with Attack or AttackValue in
	// it (# attack-run-behavior: …); whether that is harm is Reason's.
	AttackRunBehavior string
	// Advisories are the pages of the advisories whose form the example is
	// (# advisory: <URL>, one line each, ParseAdvisoryPage), in the order
	// of its file.
	Advisories []AdvisoryPage
	// Sources are the files of repositories at a commit whose steps the
	// example reproduces, for a form that no advisory reports (# source:
	// <URL>, one line each, ParseSourceFile), in the order of its file.
	Sources []SourceFile
	// AddedAttackers are the added attackers such that a run that adds one
	// of them alone reports a finding of the kind of a true positive on the
	// example, and the run that adds none reports no finding of the rule
	// (# added-attacker: <value>, one line each, ParseAddedAttacker), in
	// the order of the values of AddedAttacker, which the registry writes
	// (the order of $defs/added-attacker), whatever the order of the file;
	// only a true positive of a rule has them.
	AddedAttackers []AddedAttacker
}

// AttackValue is a string an attacker puts in an example's run, and where
// it goes: its carrier, an expression the example has in ${{ }} or, when
// the value goes elsewhere (a file of an artifact), words. Only
// ParseExampleNotes makes one.
type AttackValue struct{ carrier, value string }

// Carrier is where the value goes.
func (a AttackValue) Carrier() string { return a.carrier }

// Value is the string.
func (a AttackValue) Value() string { return a.value }

// IsZero is whether a is none.
func (a AttackValue) IsZero() bool { return a.carrier == "" }

// parseAttackValue reads <carrier> = <Go quoted string>: the carrier is
// what comes before the first " = ", and the rest is one string in double
// quotes, read by strconv.Unquote.
func parseAttackValue(s string) (AttackValue, error) {
	c, q, ok := strings.Cut(s, " = ")
	if c = strings.TrimSpace(c); !ok || c == "" {
		return AttackValue{}, fmt.Errorf("%q is not <carrier> = <Go quoted string>: no carrier", s)
	}
	q = strings.TrimSpace(q)
	v, err := strconv.Unquote(q)
	if err != nil || !strings.HasPrefix(q, `"`) {
		return AttackValue{}, fmt.Errorf("%q is not <carrier> = <Go quoted string>: the value is not one string in double quotes", s)
	}
	return AttackValue{c, v}, nil
}

var noteKeys = []string{"situation", "reason", "cause", "attack", "attack-value", "attack-run-behavior", "advisory", "source", "added-attacker"}

// ParseExampleNotes reads the notes of text, an example's file: the
// comments before its first token that is no space, break or comment. A
// line "# <key>: <text>" starts a note, a line "#" and two spaces or more
// goes on with it, and a line "#" alone is skipped; any other comment
// line there, and a key twice, are errors. The keys are those of
// ExampleNotes: situation, reason, cause, attack, attack-value (one line,
// with no line after it that goes on) and attack-run-behavior, and
// advisory: one line each, as many as the advisories, each the URL of a
// page of a different advisory (ParseAdvisoryPage), source: one line
// each, each the URL of a different file of a repository at a commit
// (ParseSourceFile), and added-attacker: one line each, each a different
// added attacker (ParseAddedAttacker). A file with no such comment has no
// notes.
func ParseExampleNotes(text string) (ExampleNotes, error) {
	var n ExampleNotes
	var attackValue, advisory, source, added string
	field := func(k string) *string {
		switch k {
		case "situation":
			return &n.Situation
		case "reason":
			return &n.Reason
		case "cause":
			return &n.Cause
		case "attack":
			return &n.Attack
		case "attack-run-behavior":
			return &n.AttackRunBehavior
		case "attack-value":
			return &attackValue
		case "advisory":
			return &advisory
		case "source":
			return &source
		case "added-attacker":
			return &added
		}
		return nil
	}
	// addAdvisory reads the note advisory read last.
	addAdvisory := func() error {
		p, err := ParseAdvisoryPage(advisory)
		if err != nil {
			return fmt.Errorf("the note advisory: %w", err)
		}
		for _, q := range n.Advisories {
			if q.ID() == p.ID() {
				return fmt.Errorf("the advisory %s is written twice", p.ID())
			}
		}
		n.Advisories = append(n.Advisories, p)
		return nil
	}
	// addSource reads the note source read last.
	addSource := func() error {
		f, err := ParseSourceFile(source)
		if err != nil {
			return fmt.Errorf("the note source: %w", err)
		}
		for _, g := range n.Sources {
			if g.Key() == f.Key() {
				return fmt.Errorf("the source %s is written twice", f.Key())
			}
		}
		n.Sources = append(n.Sources, f)
		return nil
	}
	// addAdded reads the note added-attacker read last.
	addAdded := func() error {
		v, err := ParseAddedAttacker(added)
		if err != nil {
			return fmt.Errorf("the note added-attacker: %w", err)
		}
		if slices.Contains(n.AddedAttackers, v) {
			return fmt.Errorf("the added attacker %s is written twice", v)
		}
		n.AddedAttackers = append(n.AddedAttackers, v)
		slices.Sort(n.AddedAttackers)
		return nil
	}
	// addLast reads the note advisory, source or added-attacker read last,
	// which is one line and may come again.
	addLast := func(last string) error {
		switch last {
		case "advisory":
			return addAdvisory()
		case "source":
			return addSource()
		case "added-attacker":
			return addAdded()
		}
		return nil
	}
	seen := map[string]bool{}
	var cur *string
	last := "" // the key read last
	finish := func() (ExampleNotes, error) {
		if err := addLast(last); err != nil {
			return ExampleNotes{}, err
		}
		if !seen["attack-value"] {
			return n, nil
		}
		v, err := parseAttackValue(attackValue)
		if err != nil {
			return ExampleNotes{}, err
		}
		n.AttackValue = v
		return n, nil
	}
	for tok := range cst.Parse([]byte(text)).Root().Tokens() {
		switch tok.Kind() {
		case cst.TokNewline, cst.TokSpace:
			continue
		case cst.TokComment:
		default:
			return finish()
		}
		line := strings.TrimPrefix(string(tok.Bytes()), "#")
		switch {
		case strings.TrimSpace(line) == "":
			continue
		case strings.HasPrefix(line, "  ") && cur != nil:
			if last == "attack-value" {
				return ExampleNotes{}, errors.New("the note attack-value is one line: write a line break of the value as \\n")
			}
			if last == "advisory" {
				return ExampleNotes{}, errors.New("the note advisory is one line: the URL of one page")
			}
			if last == "source" {
				return ExampleNotes{}, errors.New("the note source is one line: the URL of one file")
			}
			if last == "added-attacker" {
				return ExampleNotes{}, errors.New("the note added-attacker is one line: one added attacker")
			}
			*cur += " " + strings.TrimSpace(line)
			continue
		}
		k, v, ok := strings.Cut(strings.TrimPrefix(line, " "), ": ")
		if !ok || field(k) == nil {
			return ExampleNotes{}, fmt.Errorf("%q is not a key of the notes (%s) or the rest of one", "#"+line, strings.Join(noteKeys, ", "))
		}
		if err := addLast(last); err != nil {
			return ExampleNotes{}, err
		}
		if seen[k] && k != "advisory" && k != "source" && k != "added-attacker" {
			return ExampleNotes{}, fmt.Errorf("the note %s is written twice", k)
		}
		seen[k] = true
		cur, last = field(k), k
		*cur = strings.TrimSpace(v)
	}
	return finish()
}

// check is whether n has what an example of what needs: a situation and a
// reason; for a rule, an attack or an attack-value (not both) and an
// attack-run-behavior, and for a quality rule none of the three and no
// advisory or source; a cause for a false positive form and an undetected form, and
// no cause for a true positive or negative.
func (n ExampleNotes) check(what ExampleWhat, quality bool) error {
	switch {
	case n.Situation == "":
		return errors.New("no situation")
	case n.Reason == "":
		return errors.New("no reason")
	case quality && (n.Attack != "" || !n.AttackValue.IsZero() || n.AttackRunBehavior != ""):
		return errors.New("an attack, attack-value or attack-run-behavior: a quality rule has no threat")
	case quality && len(n.Advisories) != 0:
		return errors.New("an advisory: a quality rule has no threat, and an advisory is of a threat")
	case quality && len(n.Sources) != 0:
		return errors.New("a source: a quality rule has no threat, and a source is of a case of a threat")
	case quality && len(n.AddedAttackers) != 0:
		return errors.New("an added attacker: a quality rule has no threat, and an added attacker is an attacker of a threat")
	case quality:
	case n.Attack != "" && !n.AttackValue.IsZero():
		return errors.New("both attack and attack-value: an attacker puts in a string or does something, not both")
	case n.Attack == "" && n.AttackValue.IsZero():
		return errors.New("no attack or attack-value: what an attacker puts in, or does")
	case n.AttackRunBehavior == "":
		return errors.New("no attack-run-behavior: what the run does with the attack in it")
	}
	if len(n.AddedAttackers) != 0 && what != ExampleTruePositive {
		return fmt.Errorf("a %s has no added attacker: the note added-attacker is of a true positive, which a run that adds the attacker reports", what)
	}
	switch what {
	case ExampleTruePositive, ExampleTrueNegative:
		if n.Cause != "" {
			return fmt.Errorf("a %s has no cause: the rule's verdict is the harm's", what)
		}
	case ExampleFalsePositive, ExampleUndetected:
		if n.Cause == "" {
			return fmt.Errorf("a %s needs its cause: what of the rule makes it differ", what)
		}
	}
	return nil
}
