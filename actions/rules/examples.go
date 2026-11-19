package rules

import (
	"embed"
	"io/fs"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// examples are the inputs that show the rules' declarations:
// examples/<what>/<rule>/<id>.yml, or <id>.action.yml for an action
// metadata file. <what> is true-positive and true-negative (<id> is a kind
// of finding without its rule, then .<label> for a second one; a true
// negative of several kinds, whose fixes are the same input, joins them by
// +, as private+public),
// false-positive, undetected and inconclusive. A directory <id>/ is an
// example of several files, a repository: the declaration is about its
// called workflow .github/workflows/called.yml, or else about the action
// called/action.yml; the other files are its callers.
//
//go:embed all:examples
var examples embed.FS

// exampled is a rule whose examples are read apart from its Meta
// (lint.ExampledRule): only what shows them reads them.
type exampled struct {
	lint.Rule
	meta     func() lint.Meta // the Rule's
	exampled func() lint.Meta // meta with the examples of its declarations
}

func (r *exampled) Meta() lint.Meta         { return r.meta() }
func (r *exampled) ExampledMeta() lint.Meta { return r.exampled() }

// withExamples is r, with the declarations of the Actions policies
// (withEventPolicy), of the outside apps that check the commits of the pull
// requests from forks (withAppChecks), of the setting of allowed actions
// (withAllowedActionsBlocked), of the if that lets in only an actor the
// check of claude-code-action refuses (withRefusedActor) and of the added
// attackers (withAddedAttackers), whose examples are read when its ExampledMeta is
// first asked for. Its Meta is made when first asked for: after the
// variables of the package, which r's Meta reads, are set.
func withExamples(r lint.Rule) lint.Rule {
	meta := sync.OnceValue(func() lint.Meta {
		return withAddedAttackers(withRefusedActor(withAllowedActionsBlocked(withAppChecks(withEventPolicy(r.Meta())))))
	})
	return &exampled{r, meta, sync.OnceValue(func() lint.Meta { return attachExamples(meta()) })}
}

// exampledQuality is a quality rule whose examples are read apart from its
// QualityMeta (lint.ExampledQualityRule), as an exampled rule's.
type exampledQuality struct {
	lint.QualityRule
	meta     func() lint.QualityMeta // the QualityRule's
	exampled func() lint.QualityMeta // meta with the examples of its declarations
}

func (q *exampledQuality) QualityMeta() lint.QualityMeta         { return q.meta() }
func (q *exampledQuality) ExampledQualityMeta() lint.QualityMeta { return q.exampled() }

// withQualityExamples is q, whose examples are read when its
// ExampledQualityMeta is first asked for, as withExamples is for a rule.
func withQualityExamples(q lint.QualityRule) lint.QualityRule {
	meta := sync.OnceValue(q.QualityMeta)
	return &exampledQuality{q, meta, sync.OnceValue(func() lint.QualityMeta {
		m := meta()
		rule := m.ID.String()
		m.FindingKinds = slices.Clone(m.FindingKinds)
		for i, k := range m.FindingKinds {
			kind := strings.TrimPrefix(k.ID.String(), rule+".")
			m.FindingKinds[i].TruePositives = examplesOf("true-positive", rule, kind)
			m.FindingKinds[i].TrueNegatives = examplesOf("true-negative", rule, kind)
		}
		m.UndetectedForms = slices.Clone(m.UndetectedForms)
		for i, l := range m.UndetectedForms {
			m.UndetectedForms[i].Examples = declarationExamples("undetected", rule, l.ID.String())
		}
		m.FalsePositiveForms = slices.Clone(m.FalsePositiveForms)
		for i, f := range m.FalsePositiveForms {
			m.FalsePositiveForms[i].Examples = declarationExamples("false-positive", rule, f.ID.String())
		}
		return m
	})}
}

// attachExamples is m with the examples of examples/ given to its kinds of
// findings, undetected forms, inconclusive kinds and false positive forms.
// The slices are copied first: the Metas of rules share some. A
// declaration without a file has no example, which the registry refuses
// when it shows the examples, and TestExamples; a file of no declaration
// is TestExampleFiles's.
func attachExamples(m lint.Meta) lint.Meta {
	rule := m.ID.String()
	m.FindingKinds = slices.Clone(m.FindingKinds)
	for i, k := range m.FindingKinds {
		kind := strings.TrimPrefix(k.ID.String(), rule+".")
		m.FindingKinds[i].TruePositives = examplesOf("true-positive", rule, kind)
		m.FindingKinds[i].TrueNegatives = examplesOf("true-negative", rule, kind)
	}
	m.UndetectedForms = slices.Clone(m.UndetectedForms)
	for i, l := range m.UndetectedForms {
		m.UndetectedForms[i].Examples = declarationExamples("undetected", rule, l.ID.String())
	}
	m.InconclusiveKinds = slices.Clone(m.InconclusiveKinds)
	for i, k := range m.InconclusiveKinds {
		m.InconclusiveKinds[i].Examples = declarationExamples("inconclusive", rule, k.ID.String())
	}
	m.FalsePositiveForms = slices.Clone(m.FalsePositiveForms)
	for i, f := range m.FalsePositiveForms {
		m.FalsePositiveForms[i].Examples = declarationExamples("false-positive", rule, f.ID.String())
	}
	return m
}

// namedExample is an example and its ID: the name of its file without
// .yml or .action.yml, or of its directory.
type namedExample struct {
	id   string
	file string // its main file in examples
	e    lint.Example
}

// exampleDirs are the examples of each directory of exampleFiles, read
// once: a func() []namedExample by the directory.
var exampleDirs sync.Map

// exampleFiles are the examples of examples/<what>/<rule>/, by name; none
// when there is no such directory. The slice is the caller's.
func exampleFiles(what, rule string) []namedExample {
	dir := path.Join("examples", what, rule)
	read, _ := exampleDirs.LoadOrStore(dir, sync.OnceValue(func() []namedExample { return readExampleFiles(dir) }))
	return slices.Clone(read.(func() []namedExample)())
}

// readExampleFiles are the examples of dir (exampleFiles).
func readExampleFiles(dir string) []namedExample {
	ents, err := examples.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []namedExample
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".facts.json") {
			continue // read with its example
		}
		if e.IsDir() {
			x := severalFiles(path.Join(dir, e.Name()))
			x.Facts = factsOf(dir, e.Name())
			x.Notes = notesOf(path.Join(dir, e.Name()), x.Text)
			out = append(out, namedExample{e.Name(), path.Join(dir, e.Name(), x.Name.String()), x})
			continue
		}
		b, err := examples.ReadFile(path.Join(dir, e.Name()))
		if err != nil {
			panic(err) // the directory listed it
		}
		kind := lint.InputKindWorkflow
		if strings.HasSuffix(e.Name(), ".action.yml") {
			kind = lint.InputKindActionMetadata
		}
		x := lint.Example{InputKind: kind, Name: facts.MustCleanInputPath(e.Name()), Text: string(b)}
		x.Facts = factsOf(dir, exampleID(x))
		x.Notes = notesOf(path.Join(dir, e.Name()), x.Text)
		out = append(out, namedExample{exampleID(x), path.Join(dir, e.Name()), x})
	}
	return out
}

// factsName is the name of the facts file of the example id: what it runs
// with.
func factsName(id string) string { return id + ".facts.json" }

// factsOf are the facts of the example id in dir; none when it has no
// file yet (TestExampleFacts asks for it). It panics on a file that is not
// a file of facts: the examples are embedded.
func factsOf(dir, id string) []facts.Entry {
	b, err := examples.ReadFile(path.Join(dir, factsName(id)))
	if err != nil {
		return nil
	}
	s, err := facts.LoadStore(b)
	if err != nil {
		panic(path.Join(dir, factsName(id)) + ": " + err.Error())
	}
	return s.Entries()
}

// notesOf are the notes of the example at p, whose main file is text. It
// panics on notes it cannot read: the examples are embedded, and
// the registry, when it shows the examples, and TestExamples check what
// each kind needs.
func notesOf(p, text string) lint.ExampleNotes {
	n, err := lint.ParseExampleNotes(text)
	if err != nil {
		panic(p + ": " + err.Error())
	}
	return n
}

// mainExampleFiles are the files an example of several files is about, the
// first there: a called workflow or action, whose callers are the others;
// a workflow on repository_dispatch, whose sender is another; a workflow on
// labeled, whose labeler is another; a workflow whose step runs a composite
// action of the repository, which is another.
var mainExampleFiles = []string{".github/workflows/called.yml", "called/action.yml", "called/action.yaml", ".github/workflows/receiver.yml", ".github/workflows/labeled.yml", ".github/workflows/composite-caller.yml"}

// severalFiles is the example of several files in dir: a repository whose
// file of mainExampleFiles is the example's file, the rest the others.
// It panics on a directory without one: the examples are embedded.
func severalFiles(dir string) lint.Example {
	var files []lint.ExampleFile
	err := fs.WalkDir(examples, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := examples.ReadFile(p)
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(p, dir+"/")
		kind := lint.InputKindWorkflow
		switch b := path.Base(name); {
		case b == "action.yml" || b == "action.yaml":
			kind = lint.InputKindActionMetadata
		case path.Dir(name) != ".github/workflows":
			kind = lint.InputKindRepoFile // read by the analysis, such as the configuration of actions/labeler
		}
		files = append(files, lint.ExampleFile{InputKind: kind, Name: facts.MustCleanInputPath(name), Text: string(b)})
		return nil
	})
	if err != nil {
		panic(err)
	}
	for _, m := range mainExampleFiles {
		if i := slices.IndexFunc(files, func(f lint.ExampleFile) bool { return f.Name.String() == m }); i >= 0 {
			f := files[i]
			return lint.Example{InputKind: f.InputKind, Name: f.Name, Text: f.Text, Others: slices.Delete(files, i, i+1)}
		}
	}
	panic(dir + " has none of " + strings.Join(mainExampleFiles, ", "))
}

// exampleID is the name of e, a file, without .yml or .action.yml.
func exampleID(e lint.Example) string {
	n := e.Name.String()
	if s, ok := strings.CutSuffix(n, ".action.yml"); ok {
		return s
	}
	return strings.TrimSuffix(n, ".yml")
}

// declarationExamples are the examples of the declaration id (an
// undetected form, an inconclusive kind or a false positive form) in
// examples/<what>/<rule>/: <id>, the main one, first, then each
// <id>.<label> in the order of their names; none when there is no main
// one, which the registry refuses, and TestExampleFiles.
func declarationExamples(what, rule, id string) []lint.Example {
	return declarationExamplesOf(exampleFiles(what, rule), id)
}

// declarationExamplesOf are the examples of the declaration id among xs
// (declarationExamples).
func declarationExamplesOf(xs []namedExample, id string) []lint.Example {
	var out []lint.Example
	var labeled []namedExample
	for _, x := range xs {
		switch {
		case x.id == id:
			out = append(out, x.e)
		case strings.HasPrefix(x.id, id+"."):
			labeled = append(labeled, x)
		}
	}
	if len(out) == 0 {
		return nil
	}
	slices.SortFunc(labeled, func(a, b namedExample) int { return strings.Compare(a.id, b.id) })
	for _, x := range labeled {
		out = append(out, x.e)
	}
	return out
}

// examplesOf are the examples of the kind of finding kind (its ID without
// the rule) in examples/<what>/<rule>/: <kind> and <kind>.<label>, and the
// true negatives that join it with other kinds by +.
func examplesOf(what, rule, kind string) []lint.Example {
	var out []lint.Example
	for _, x := range exampleFiles(what, rule) {
		if slices.Contains(exampleKinds(x.id), kind) {
			out = append(out, x.e)
		}
	}
	return out
}

// exampleKinds are the kinds of finding a true positive or a true negative
// id is of: the part before its label, split at +.
func exampleKinds(id string) []string {
	kinds, _, _ := strings.Cut(id, ".")
	return strings.Split(kinds, "+")
}

// ExampleLocation is an example of a declaration of a rule, with where
// its main file is in the repository: what a reviewer marks.
type ExampleLocation struct {
	What        lint.ExampleWhat
	Rule        lint.RuleID
	ID          string // the name of its file without .yml or .action.yml, or of its directory
	Path        string // its main file, from the repository's root
	Declaration string // the text of what it shows: the consequence of a kind of finding, or the text of a form or kind
	Example     lint.Example
}

// whatDirs are the directories of examples/ by what they show, in the
// order a reviewer reads them: the false positives and undetected forms,
// whose causes were derived from the rules, first.
var whatDirs = []struct {
	what lint.ExampleWhat
	dir  string
}{
	{lint.ExampleFalsePositive, "false-positive"},
	{lint.ExampleUndetected, "undetected"},
	{lint.ExampleInconclusive, "inconclusive"},
	{lint.ExampleTruePositive, "true-positive"},
	{lint.ExampleTrueNegative, "true-negative"},
}

// Examples are every rule's and quality rule's examples, in the order of
// their IDs, then of whatDirs, then of the examples' IDs.
func Examples() []ExampleLocation {
	var all []lint.Meta
	for _, r := range All() {
		all = append(all, r.Meta())
	}
	for _, q := range Quality() {
		all = append(all, q.QualityMeta().AsMeta())
	}
	slices.SortFunc(all, func(a, b lint.Meta) int { return strings.Compare(a.ID.String(), b.ID.String()) })
	var out []ExampleLocation
	for _, m := range all {
		for _, w := range whatDirs {
			xs := exampleFiles(w.dir, m.ID.String())
			slices.SortFunc(xs, func(a, b namedExample) int { return strings.Compare(a.id, b.id) })
			for _, x := range xs {
				out = append(out, ExampleLocation{
					What: w.what, Rule: m.ID, ID: x.id,
					Path:        path.Join("actions/rules", x.file),
					Declaration: declarationText(m, w.what, x.id),
					Example:     x.e,
				})
			}
		}
	}
	return out
}

// declarationText is the text of the declaration of m that the example id
// of what shows: for a true positive, the consequence of the kind of
// finding id is named after (<kind> or <kind>.<label>); for a true
// negative, lint.TrueNegativeText of its kinds; for another declaration,
// its text (id is <form> or <form>.<label>).
func declarationText(m lint.Meta, what lint.ExampleWhat, id string) string {
	switch what {
	case lint.ExampleTruePositive, lint.ExampleTrueNegative:
		var texts []lint.FindingText // in the order of the kinds of m
		for _, k := range m.FindingKinds {
			if slices.Contains(exampleKinds(id), strings.TrimPrefix(k.ID.String(), m.ID.String()+".")) {
				texts = append(texts, k.FindingText)
			}
		}
		switch {
		case len(texts) == 0:
			return ""
		case what == lint.ExampleTrueNegative:
			return lint.TrueNegativeText(texts...)
		}
		return texts[0].Consequence
	}
	id, _, _ = strings.Cut(id, ".") // <form>.<label>
	switch what {
	case lint.ExampleFalsePositive:
		for _, f := range m.FalsePositiveForms {
			if f.ID.String() == id {
				return f.Text
			}
		}
	case lint.ExampleUndetected:
		for _, l := range m.UndetectedForms {
			if l.ID.String() == id {
				return l.Text
			}
		}
	case lint.ExampleInconclusive:
		for _, k := range m.InconclusiveKinds {
			if k.ID.String() == id {
				return k.Text
			}
		}
	}
	return ""
}
