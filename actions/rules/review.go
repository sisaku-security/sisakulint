package rules

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/internal/attackrun"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// ReviewDocument is a Markdown file a person reads to approve a rule: the
// rule's Meta without its examples (meta.md), or one of its examples
// (<what>/<id>.md). Path is under the rule's directory of approved
// documents; Example is nil for meta.md.
type ReviewDocument struct {
	Rule    lint.RuleID
	Path    ReviewPath
	Text    string
	Example *ExampleLocation
}

// ReviewPath is the path of a file under a rule's directory of approved
// documents: meta.md, <what>/<id>.md, or a file left there. Only
// ParseReviewPath and ReviewDocuments make one.
type ReviewPath struct{ s string }

// ParseReviewPath is s, a slash path of a file under a rule's directory,
// as a ReviewPath.
func ParseReviewPath(s string) (ReviewPath, error) {
	if !fs.ValidPath(s) || s == "." {
		return ReviewPath{}, fmt.Errorf("%q is not the path of a file under a rule's directory", s)
	}
	return ReviewPath{s}, nil
}

// MustReviewPath is ParseReviewPath(s), which must be no error.
func MustReviewPath(s string) ReviewPath {
	p, err := ParseReviewPath(s)
	if err != nil {
		panic(err)
	}
	return p
}

func (p ReviewPath) String() string { return p.s }

// metaDocument is the Path of a rule's Meta.
var metaDocument = ReviewPath{"meta.md"}

// AllExampleChecks are the checks of the examples of every rule and
// quality rule (lint.Registry.CheckExamples on All and Quality), made once
// for the review documents (ReviewDocuments, Review) and the example
// catalog. Only CheckAllExamples makes one: a review document is made of
// the facts every run of its rule asked, so the checks of some rules alone
// would make wrong ones. Review and ReviewDocuments refuse nil and a zero
// AllExampleChecks; Of reads one CheckAllExamples made.
type AllExampleChecks struct {
	checks []lint.ExampleCheck
	made   bool
}

// errUnmadeChecks is the error of Review and ReviewDocuments on example
// checks CheckAllExamples did not make.
var errUnmadeChecks = errors.New("rules: the example checks are not made by CheckAllExamples")

// CheckAllExamples checks the examples of every rule and quality rule.
func CheckAllExamples(ctx context.Context) (*AllExampleChecks, error) {
	reg, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		return nil, err
	}
	return &AllExampleChecks{checks: reg.CheckExamples(ctx), made: true}, nil
}

// Of are the checks of the rules only, or of every rule when only is
// empty, in the order CheckExamples gives them, in a slice of their own:
// what CheckExamples gives with only. The runs in them are shared, and
// whoever reads them does not change them.
func (c *AllExampleChecks) Of(only ...lint.RuleID) []lint.ExampleCheck {
	if len(only) == 0 {
		return slices.Clone(c.checks)
	}
	var out []lint.ExampleCheck
	for _, x := range c.checks {
		if slices.Contains(only, x.Rule) {
			out = append(out, x)
		}
	}
	return out
}

// ReviewDocuments are the review documents of every rule and quality rule
// (All, Quality), by the checks c of their examples, in the order of their
// IDs; a rule's meta.md first, then its examples in the order of Examples.
func ReviewDocuments(c *AllExampleChecks) ([]ReviewDocument, error) {
	if c == nil || !c.made {
		return nil, errUnmadeChecks
	}
	reg, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		return nil, err
	}
	runs := map[exampleKey][]lint.ExampleRun{}
	for _, x := range c.checks {
		runs[keyOf(x.Rule, x.What, x.Example)] = x.Runs
	}
	var out []ReviewDocument
	var last lint.RuleID
	for _, x := range Examples() {
		if x.Rule != last {
			last = x.Rule
			b, err := reg.ExplainRule(x.Rule)
			if err != nil {
				return nil, err
			}
			out = append(out, ReviewDocument{Rule: x.Rule, Path: metaDocument, Text: string(b)})
		}
		x := x
		out = append(out, ReviewDocument{Rule: x.Rule, Path: ReviewPath{x.What.String() + "/" + x.ID + ".md"}, Text: exampleDocument(x, AttackMarkers[x.Rule], runs[keyOf(x.Rule, x.What, x.Example)]), Example: &x})
	}
	return out, nil
}

// exampleDocument is the review document of x: a heading, the path of its
// main file, the text of its declaration, each of its files as a code
// block, the facts each of runs (CheckExamples) asked and their answers,
// and, when the example has an attack value, the value put in
// (attackrun.Substitute) and whether a test runs it where the rule's harm
// shows at m (attackrun.Check). The facts are those the rule asked, not
// the facts file: the file also answers what the other rules ask.
func exampleDocument(x ExampleLocation, m attackrun.Marker, runs []lint.ExampleRun) string {
	parts := []string{
		"## " + x.What.String() + " " + x.Rule.String() + " / " + lint.MarkdownText(x.ID) + "\n",
		"`" + x.Path + "`\n",
		"> " + lint.MarkdownText(x.Declaration) + "\n",
		"`" + x.Example.Name.String() + "`\n",
		lint.MarkdownCodeBlock("yaml", normalNewlines(x.Example.Text)),
	}
	for _, o := range x.Example.Others {
		parts = append(parts, "`"+o.Name.String()+"`\n", lint.MarkdownCodeBlock("yaml", normalNewlines(o.Text)))
	}
	for i, run := range runs {
		switch {
		case len(runs) == 1:
		case i == 0:
			parts = append(parts, "With the answers of the facts file, the facts the rule asked:\n")
		default:
			var ks []string
			for _, k := range run.Flipped {
				ks = append(ks, k.String())
			}
			parts = append(parts, "With "+strings.Join(ks, ", ")+" flipped (answered false when the x-assume value of the kind is true, and true otherwise), the facts the rule asked:\n")
		}
		lines := run.FactLines()
		switch {
		case len(lines) == 0:
			parts = append(parts, "The rule asked no fact: the files alone decide what the rule reports.\n")
		case len(runs) == 1:
			parts = append(parts, "Facts the rule asked, and the answers the rule ran with:\n", lint.MarkdownCodeBlock("text", strings.Join(lines, "\n")+"\n"))
		default:
			parts = append(parts, lint.MarkdownCodeBlock("text", strings.Join(lines, "\n")+"\n"))
		}
	}
	for _, s := range attackrun.Substitute(x.Example) {
		parts = append(parts, "After substitution, `"+s.File.String()+"` `"+s.Where+"`:\n", lint.MarkdownCodeBlock("text", normalNewlines(s.Text)))
	}
	if c := attackrun.Check(x.Example, m); c != "" {
		parts = append(parts, "("+c+")\n")
	}
	return strings.Join(parts, "\n")
}

// normalNewlines is s with CR LF and CR as LF: a file's line breaks are not
// what a person reads, and git may change them.
func normalNewlines(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

// approved are the approved documents: approved/<rule>/meta.md and
// approved/<rule>/<what>/<id>.md, each as a person approved it by merging
// a review batch. A file whose name starts with . or _ is not embedded:
// git may ignore one (.DS_Store) that a review batch could not remove.
//
//go:embed approved
var approved embed.FS

// RuleReview is how the approved documents of a rule stand to its review
// documents now: those with no approved document or another one
// (Changed), and the paths of the approved documents of no review
// document (Stale). The rule is reviewed when there are none of either.
type RuleReview struct {
	Rule     lint.RuleID
	Changed  []ReviewDocument
	Stale    []ReviewPath
	Reviewed bool
}

// ReviewState is what a person approved of the rules: each rule's
// RuleReview, and which examples' approved documents are their review
// documents now.
type ReviewState struct {
	rules    []RuleReview
	meta     map[lint.RuleID]bool
	examples map[exampleKey]bool
	unknown  []lint.RuleID
}

// exampleKey finds an example of a rule by what it shows and its main
// file's name and text: examples of several files share the name of their
// main file, not its text.
type exampleKey struct {
	rule       lint.RuleID
	what       lint.ExampleWhat
	name, text string
}

// Review is the state of the approved documents built in, by the review
// documents now (ReviewDocuments of c).
func Review(c *AllExampleChecks) (ReviewState, error) {
	docs, err := ReviewDocuments(c)
	if err != nil {
		return ReviewState{}, err
	}
	sub, err := fs.Sub(approved, "approved")
	if err != nil {
		return ReviewState{}, err
	}
	var ids []lint.RuleID
	for _, r := range All() {
		ids = append(ids, r.Meta().ID)
	}
	for _, q := range Quality() {
		ids = append(ids, q.QualityMeta().ID)
	}
	return reviewOf(sub, docs, ids)
}

// reviewOf is the state of the approved documents in fsys (<rule>/…) by
// docs, of the rules ids. A directory of no rule of ids is told by
// Unknown; a file at the root of fsys is no rule's. An approved document
// that cannot be read as a file (a directory of the name) is changed, and
// what is in it stale. It is an error that the place of a rule's
// directory is a file, or that a directory's name is no rule ID: nothing
// but a person's hand makes either.
func reviewOf(fsys fs.FS, docs []ReviewDocument, ids []lint.RuleID) (ReviewState, error) {
	s := ReviewState{meta: map[lint.RuleID]bool{}, examples: map[exampleKey]bool{}}
	byRule := map[lint.RuleID][]ReviewDocument{}
	for _, d := range docs {
		byRule[d.Rule] = append(byRule[d.Rule], d)
	}
	known := map[string]bool{}
	sorted := slices.Clone(ids)
	slices.SortFunc(sorted, func(a, b lint.RuleID) int { return strings.Compare(a.String(), b.String()) })
	for _, id := range sorted {
		known[id.String()] = true
		rv := RuleReview{Rule: id}
		have := map[string]bool{}
		for _, d := range byRule[id] {
			have[d.Path.String()] = true
			b, err := fs.ReadFile(fsys, path.Join(id.String(), d.Path.String()))
			same := err == nil && string(b) == d.Text
			if !same {
				rv.Changed = append(rv.Changed, d)
			}
			if d.Example == nil {
				s.meta[id] = same
			} else {
				s.examples[keyOf(id, d.Example.What, d.Example.Example)] = same
			}
		}
		err := fs.WalkDir(fsys, id.String(), func(p string, e fs.DirEntry, err error) error {
			switch {
			case err != nil || e.IsDir():
				return err
			case p == id.String():
				return fmt.Errorf("approved/%s is a file, not the directory of the rule: remove it", p)
			}
			if rel := strings.TrimPrefix(p, id.String()+"/"); !have[rel] {
				rp, err := ParseReviewPath(rel)
				if err != nil {
					return err
				}
				rv.Stale = append(rv.Stale, rp)
			}
			return nil
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return ReviewState{}, err
		}
		rv.Reviewed = len(rv.Changed) == 0 && len(rv.Stale) == 0
		s.rules = append(s.rules, rv)
	}
	ents, err := fs.ReadDir(fsys, ".")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return ReviewState{}, err
	}
	for _, e := range ents {
		if !e.IsDir() || known[e.Name()] {
			continue
		}
		id, err := lint.ParseRuleID(e.Name())
		if err != nil {
			return ReviewState{}, fmt.Errorf("approved/%s is the directory of no rule: remove it (%w)", e.Name(), err)
		}
		s.unknown = append(s.unknown, id)
	}
	return s, nil
}

func keyOf(rule lint.RuleID, what lint.ExampleWhat, e lint.Example) exampleKey {
	return exampleKey{rule, what, e.Name.String(), e.Text}
}

// Rules are the RuleReview of every rule, in the order of their IDs.
func (s ReviewState) Rules() []RuleReview { return s.rules }

// Unknown are the directories of approved documents of no rule: a rule
// removed or renamed while a review batch of it was open.
func (s ReviewState) Unknown() []lint.RuleID { return s.unknown }

// MetaReviewed is whether the approved meta.md of rule is its review
// document now.
func (s ReviewState) MetaReviewed(rule lint.RuleID) bool { return s.meta[rule] }

// RuleReviewed is whether rule is reviewed (RuleReview.Reviewed).
func (s ReviewState) RuleReviewed(rule lint.RuleID) bool {
	for _, r := range s.rules {
		if r.Rule == rule {
			return r.Reviewed
		}
	}
	return false
}

// ExampleReviewed is whether the approved document of the example e of
// rule, which shows what, is its review document now.
func (s ReviewState) ExampleReviewed(rule lint.RuleID, what lint.ExampleWhat, e lint.Example) bool {
	return s.examples[keyOf(rule, what, e)]
}
