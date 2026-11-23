package lint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gh-intel/sisakulint/actions/ir"
	"regexp"
	"slices"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/workflow"
	"github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

// Location is where a finding or a step of its evidence is.
type Location struct {
	File  File
	Span  cst.Span
	Exact bool       // false: where a ${{ }} is, only nearly (workflow.String.Source)
	Via   []cst.Span // the aliases it was reached through, outermost first (workflow.Base.Via)

	node cst.Node   // the element, where the path of the fingerprint ends
	vias []cst.Node // the aliases, outermost first
	tree *cst.Tree
}

// File is the input a location is in, or the fact whose value is the
// file (a remote action.yml).
type File struct {
	Input facts.InputPath // the input; zero for a file from a fact
	Query facts.Query     // the fact whose value is the file; nil for an input
}

// At is where the element b of in is: its primary span (the outermost
// alias it is used through, or itself) and the aliases.
func At(in Input, b workflow.Base) Location {
	l := Location{File: File{Input: in.Name}, Span: b.Primary(), Exact: true, node: b.Node, vias: slices.Clone(b.Via), tree: in.Tree}
	for _, v := range b.Via {
		l.Via = append(l.Via, v.ContentSpan())
	}
	return l
}

// AtSpan is the span sp inside the element b of in, such as where a ${{ }}
// is in a scalar (workflow.String.Source). exact is false when sp is only
// near it. sp is in the bytes of b, which are the anchor's when b is
// reached through aliases; Via has the aliases.
func AtSpan(in Input, b workflow.Base, sp cst.Span, exact bool) Location {
	l := At(in, b)
	l.Span, l.Exact = sp, exact
	return l
}

// Position is the line and the column where l starts; zero for a Location
// not made by At or AtSpan.
func (l Location) Position() cst.Position {
	if l.tree == nil {
		return cst.Position{}
	}
	return l.tree.Position(l.Span.Start)
}

// LineText is the text of the line where l starts, without its line
// break; empty for a Location not made by At or AtSpan.
func (l Location) LineText() string {
	if l.tree == nil {
		return ""
	}
	src := l.tree.Bytes()
	start := min(l.Span.Start, len(src))
	b := bytes.LastIndexAny(src[:start], "\r\n") + 1
	e := bytes.IndexAny(src[start:], "\r\n")
	if e < 0 {
		e = len(src)
	} else {
		e += start
	}
	return string(src[b:e])
}

// NodeSpan is the span of the element l is at, in the bytes it is
// written in: the anchor's when it is reached through aliases, where Span
// is the outermost alias. Zero for a Location not made by At or AtSpan.
func (l Location) NodeSpan() cst.Span {
	if l.tree == nil {
		return cst.Span{}
	}
	return l.node.ContentSpan()
}

// identityText is the text of the span of l and the text of the lines the
// span is on (a line break is CR LF, LF or CR, as YAML has it), with the
// indentation the lines have in common taken off and the spaces and tabs
// at the end of each line, joined by line feeds: an element moved to
// another depth keeps them, a line indented apart from the others does not.
// The first line of the span text starts where the span starts. They are
// taken from the bytes the element is written in: for a location of At
// reached through aliases, whose Span is the outermost alias, from the
// anchor's (NodeSpan), so that a value changed there changes them.
func (l Location) identityText() (span, lines string) {
	if l.tree == nil {
		return "", ""
	}
	sp := l.Span
	if len(l.Via) > 0 && sp == l.Via[0] {
		sp = l.NodeSpan()
	}
	src := l.tree.Bytes()
	start, end := min(sp.Start, len(src)), min(sp.End, len(src))
	from := bytes.LastIndexAny(src[:start], "\r\n") + 1
	to := bytes.IndexAny(src[end:], "\r\n")
	if to < 0 {
		to = len(src)
	} else {
		to += end
	}
	all := splitLines(src[from:to])
	indent := -1
	for _, x := range all {
		if t := bytes.TrimLeft(x, " \t"); len(t) > 0 {
			if n := len(x) - len(t); indent < 0 || n < indent {
				indent = n
			}
		}
	}
	dedent := func(ls [][]byte, first bool) string {
		out := make([][]byte, len(ls))
		for i, x := range ls {
			if i > 0 || !first {
				x = x[min(max(indent, 0), len(x)-len(bytes.TrimLeft(x, " \t"))):]
			}
			out[i] = bytes.TrimRight(x, " \t")
		}
		return string(bytes.Join(out, []byte{'\n'}))
	}
	return dedent(splitLines(src[start:end]), true), dedent(all, false)
}

// splitLines is b cut at each line break: CR LF, LF or CR.
func splitLines(b []byte) [][]byte {
	var out [][]byte
	for {
		i := bytes.IndexAny(b, "\r\n")
		if i < 0 {
			return append(out, b)
		}
		out = append(out, b[:i])
		if b[i] == '\r' && i+1 < len(b) && b[i+1] == '\n' {
			i++
		}
		b = b[i+1:]
	}
}

// KeyPath is the path of keys from the document to an element of an
// input, as ir.Paths.Of writes it: keys joined by dots, a key that is not
// letters, digits, - and _ as a JSON string in brackets, an item of a
// sequence as its index in brackets, an item of steps or of a parallel
// group as its id in brackets when no other item of the sequence has the
// id. The zero KeyPath is the document.
type KeyPath struct{ s string }

func (k KeyPath) String() string               { return k.s }
func (k KeyPath) MarshalJSON() ([]byte, error) { return json.Marshal(k.s) }

var (
	keyPathPlain = regexp.MustCompile(`^[A-Za-z0-9_-]+`)
	keyPathItem  = regexp.MustCompile(`^\[(?:[0-9]+|[A-Za-z_][A-Za-z0-9_-]*)\]`)
	keyPathQuote = regexp.MustCompile(`^\["(?:[^"\\]|\\.)*"\]`)
)

// ParseKeyPath checks s and makes the KeyPath; it does not say that an
// input has the element.
func ParseKeyPath(s string) (KeyPath, error) {
	rest := s
	for first := true; rest != ""; first = false {
		if !first && rest[0] == '.' {
			if m := keyPathPlain.FindString(rest[1:]); m != "" {
				rest = rest[1+len(m):]
				continue
			}
			return KeyPath{}, fmt.Errorf("%q is not a path of keys: a dot without a key after it", s)
		}
		if first {
			if m := keyPathPlain.FindString(rest); m != "" {
				rest = rest[len(m):]
				continue
			}
		}
		if m := keyPathItem.FindString(rest); m != "" {
			rest = rest[len(m):]
			continue
		}
		if m := keyPathQuote.FindString(rest); m != "" {
			var key string
			if err := json.Unmarshal([]byte(m[1:len(m)-1]), &key); err != nil {
				return KeyPath{}, fmt.Errorf("%q is not a path of keys: %v", s, err)
			}
			rest = rest[len(m):]
			continue
		}
		return KeyPath{}, fmt.Errorf("%q is not a path of keys", s)
	}
	return KeyPath{s}, nil
}

// KeyPath is the path of keys from the document to l, as ir.Paths.Of
// writes it; the zero KeyPath for a Location not made by At or AtSpan.
func (l Location) KeyPath() KeyPath { return l.keyPathIn(ir.NewPaths()) }

// keyPathIn is KeyPath with the lookups of p, which a run shares.
func (l Location) keyPathIn(p *ir.Paths) KeyPath {
	if l.tree == nil {
		return KeyPath{}
	}
	return KeyPath{p.Of(l.tree, l.node, l.vias)}
}

type Related struct {
	Location Location
	Note     string
}

// Fix is how to fix a finding: edits of the tree of its input.
type Fix struct {
	KindID      FixKindID // of a FixKind of the rule
	Title       string
	Edits       []edit.Edit
	SideEffects []ir.SideEffect // of the PossibleSideEffects of its kind: those it makes
}

// NoFix is why a rule that fixes gives no fix for a finding.
type NoFix struct {
	Reason  ir.NoFixReason
	Queries []facts.Query // when Reason is ir.NoFixReasonFact: the facts that were not known
	Note    string        // how to fix it by hand, and so on
}

// FindingDraft is what a rule reports. The engine makes a Finding of it:
// it adds the Severity, Consequence and Remedy of its kind from the
// registry of rules, the Certainty its condition has on the answers of the
// facts, and its Fingerprint. They are not here so that a rule cannot set
// them: the registry is the one place a kind's are declared.
type FindingDraft struct {
	Rule      RuleID
	Location  Location
	Args      FindingArgs // what it is about: its kind and arguments; what is detected is made of them
	Related   []Related   // in no order that means anything
	Evidence  []Related   // the path of the evidence: from where a value comes to where it is used
	Condition *Condition  // nil: it holds
	Fix       *Fix        // a finding of a kind that fixes gives Fix or NoFix, not both
	NoFix     *NoFix
	Anchor    string // tells apart findings of one rule at one place
}

// FindingArgs are what a finding is about: its kind, and the values of the
// kind's arguments (schema/findings-v0.json of actions/rules, which makes
// the Go types of them). What is detected is made of them. MarshalJSON writes
// an object whose kind is Kind, without escaping <, > and &.
type FindingArgs interface {
	KindID() FindingKindID
	Detected() string
	json.Marshaler
}

// Detected is what f says is detected, made of its Args.
func (f FindingDraft) Detected() string {
	if f.Args == nil {
		return ""
	}
	return f.Args.Detected()
}

// Severity is how bad a finding is; the registry of rules is where it is
// written, never a finding. Its values are the oneOf of $defs/severity in
// schema/registry-v0.json (enum_gen.go), from the least to the worst.
type Severity uint8

// InputKind is what an input is read as ($defs/kind of schema/registry-v0.json).
type InputKind uint8

// Safety is whether a fix may be applied without a person looking
// ($defs/safety of schema/registry-v0.json).
type Safety uint8
