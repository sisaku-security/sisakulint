package cli

import (
	"context"
	"fmt"
	"io/fs"
	"os"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/rules"
)

// legacyUsage is the usage of --legacy-configuration.
const legacyUsage = "with --init: read `FILE`, a configuration file of sisakulint 0.x (.github/sisakulint.yaml), and write the entries of FILE as values of the key fact. action-list is written as repo.action-list, and config-variables as repo.configuration-variables. secret-exfiltration.allowed-hosts and the directives in the workflows under --root are written as request.destination-trusted, for each pair of a secret and a destination that the workflows under --root, as the workflows are when --init runs, send the secret to; a host that no workflow sends a secret to is not written. The configuration file written has, as comments, the entries that are not written and, for each entry written, how this linter reads the entry differently from sisakulint 0.x; a line on stderr names each entry that is not written"

// initLegacy is --init with --legacy-configuration: it reads the inputs
// under --root with secret-exfiltration alone, to count the pairs of a
// secret and a destination, writes the entries of the legacy configuration
// file as facts in the template, and names on stderr each entry that is
// not written.
func initLegacy(ctx context.Context, e Env, reg *lint.Registry, o options) int {
	fail := func(code int, err error) int {
		fmt.Fprintf(e.Stderr, "sisakulint: %v\n", err)
		return code
	}
	if _, err := reg.Select(o.selection, lint.FactSources{}); err != nil { // the rules, as a run would check them
		return fail(ExitUsage, fmt.Errorf("%s: %w", o.selectBy, err))
	}
	root, err := os.OpenRoot(o.root)
	if err != nil {
		return fail(ExitNoInput, err)
	}
	defer root.Close()
	pairs, directives, inputNotes, err := destinationPairs(ctx, root.FS(), o, reg)
	if err != nil {
		return fail(ExitNoInput, err)
	}
	c := *o.legacy
	var imported []importedFact
	var left []legacyNote
	for _, write := range []func() (*importedFact, []legacyNote){
		func() (*importedFact, []legacyNote) { return legacyActionList(c.actionList) },
		func() (*importedFact, []legacyNote) { return legacyConfigurationVariables(c.configurationVariables) },
	} {
		f, notes := write()
		if f != nil {
			imported = append(imported, *f)
		}
		left = append(left, notes...)
	}
	trusted, notes := legacyAllowedHosts(c.allowedHosts.items, directives.taken, pairs)
	imported = append(imported, trusted...)
	left = append(left, notes...)
	left = append(left, directives.left...)
	left = append(left, legacyOtherNotes(c, o.legacyPath)...)
	left = append(left, inputNotes...)
	for _, f := range imported {
		written, err := parseFact(f.factText(), o.repo)
		if err != nil {
			panic(err) // a fact made from parsed values
		}
		for _, g := range o.given {
			if g.Query == written.Query {
				return fail(ExitUsage, fmt.Errorf("the fact %s is given both by --fact and by the legacy configuration file (--legacy-configuration); give the fact in one of the two", f.kind))
			}
		}
	}
	t, err := configurationTemplate(o.templateValues, imported, left)
	if err != nil {
		return fail(ExitUsage, err)
	}
	if _, err := e.Stdout.Write(t); err != nil {
		return fail(ExitIO, err)
	}
	for _, n := range left {
		fmt.Fprintf(e.Stderr, "sisakulint: legacy configuration: %s\n", n.text)
	}
	return 0
}

// legacyDirectiveSet are the directives of the workflows: the hosts
// written, and the directives not written.
type legacyDirectiveSet struct {
	taken []legacyDirective
	left  []legacyNote
}

// destinationPairs runs secret-exfiltration alone on the inputs under
// --root, with no answer to any fact, and gives the pair of each finding,
// the directives of the workflows, and a note for each input that was not
// read.
func destinationPairs(ctx context.Context, fsys fs.FS, o options, reg *lint.Registry) ([]destinationPair, legacyDirectiveSet, []legacyNote, error) {
	var d legacyDirectiveSet
	sel, err := lint.ParseSelector(rules.SecretExfiltrationID.String())
	if err != nil {
		panic(err) // the ID of a rule
	}
	only, err := reg.Select(lint.Only(sel), lint.FactSources{})
	if err != nil {
		panic(err) // a rule of the registry
	}
	in, err := readInputs(fsys, o, nil)
	if err != nil {
		return nil, d, nil, err
	}
	var notes []legacyNote
	for _, i := range in.List {
		switch i.State {
		case lint.InputStateUnreadable, lint.InputStateInvalid:
			notes = append(notes, legacyNote{fmt.Sprintf("%s: this linter could not read the file as a workflow or an action metadata file (%s), so a fact request.destination-trusted for a pair of a secret and a destination in the file may be missing", i.Name, inputWhy(i))})
		}
		if i.InputKind != lint.InputKindWorkflow || i.Tree == nil {
			continue
		}
		taken, left := legacyDirectives(i.Tree.Bytes())
		for _, t := range taken {
			d.taken = append(d.taken, legacyDirective{t, i.Name})
		}
		for _, l := range left {
			d.left = append(d.left, notWritten("the directive in "+i.Name.String(), l, "sisakulint 0.x reads a directive only at some places at the top of a workflow, and this linter writes the hosts of a directive as facts only when the directive is at a place where the authors of this linter saw sisakulint 0.x read a directive: a comment line whose next line that is not blank and not a comment is a key of the top level, or a comment at the end of the line of a key of the top level, when the value of the key ends on that line or only the colon of the key is before the comment (not a comment after an anchor, a tag, or an open [ or {, on that line)"))
		}
	}
	rep := lint.Run(ctx, in, only, offline{})
	var pairs []destinationPair
	for _, f := range rep.Findings {
		if f.Condition == nil {
			continue
		}
		for _, q := range f.Condition.Queries() {
			if t, ok := q.(facts.RequestDestinationTrusted); ok {
				pairs = append(pairs, destinationPair{t, f.Location.File.Input})
			}
		}
	}
	return pairs, d, notes, nil
}

// inputWhy is why the input i was not read as GitHub reads it.
func inputWhy(i lint.Input) string {
	switch {
	case i.Reason != "":
		return i.Reason
	case len(i.Diagnostics) != 0:
		return i.Diagnostics[0].Msg
	}
	return i.State.String()
}

// legacyOtherNotes are the notes of the entries of c that no fact has: the
// labels of self-hosted runners, the keys sisakulint 0.x does not know,
// and the YAML documents after the first. path is the legacy
// configuration file, which a note of a line that no key names names.
func legacyOtherNotes(c legacyConfiguration, path string) []legacyNote {
	var notes []legacyNote
	for _, i := range c.runnerLabels.items {
		notes = append(notes, notWritten("self-hosted-runner.labels", i, "this linter has no fact and no key for the labels of self-hosted runners, and sisakulint 0.x did not use the labels either"))
	}
	for _, k := range c.unknownKeys {
		notes = append(notes, legacyNote{fmt.Sprintf("%s, line %d: the key is not written: sisakulint 0.x does not know the key and did not read the key", k.text, k.line)})
	}
	for _, d := range c.laterDocuments {
		notes = append(notes, legacyNote{fmt.Sprintf("%s, line %d: the YAML document that starts on the line is not written: sisakulint 0.x reads the first YAML document of the file only", path, d.line)})
	}
	return notes
}
