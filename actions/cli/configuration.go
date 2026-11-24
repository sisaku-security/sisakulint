package cli

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/scalar"
)

// valueForm is how a key of the configuration file takes its values, and
// how the flag of the key does.
type valueForm uint8

const (
	formOne  valueForm = iota // one string; the value given last is the one
	formList                  // strings: the flag may be given again, the key is a sequence
)

// mergeRule is how the values of a key on the command line and in the
// configuration file go together.
type mergeRule uint8

const (
	mergeReplace   mergeRule = iota // a value on the command line replaces those of the file
	mergeUnion                      // the values of the file, then those of the command line
	mergeSelection                  // a value on the command line of any key of this rule replaces the values of the file of all of them
)

// valueOrigin is where a value of a key was given.
type valueOrigin uint8

const (
	originCommandLine valueOrigin = iota
	originFile
)

// configurationKey is a key of the configuration file and the flag of the
// same name. configurationKeys is the only place a key is defined: the
// flags, the reading of the file, the merging of the two and the template
// of --init are made from it.
type configurationKey struct {
	name  string    // the name of the flag, and of the key
	form  valueForm // how the values are given
	help  string    // what the value decides; the usage of the flag and the comment of --init
	merge mergeRule
	path  bool // the value is the path of a file, which the configuration file reads from its own directory
	// flagNote is added to the usage of the flag only, not to the comment of
	// the template of --init; templateNote, to the comment only.
	flagNote, templateNote string
	// wholeRoot: the key is of a run that reads every file under --root.
	// A value of the configuration file is not read in a run of PATHs
	// (without --read-all) or of stdin.
	wholeRoot bool
	// read checks one value and sets it in o. from is where the value was
	// given.
	read func(o *options, k *configurationKey, value string, from valueOrigin) error
}

// configurationKeys are the keys, in the order their values are read:
// repo before fact, since a repo.* fact is of the repository of repo.
var configurationKeys = []configurationKey{
	{
		name:      "exclude",
		form:      formList,
		help:      "leave out this path of the repository and what is under it: its action.yml are listed as excluded, not read; .github/workflows cannot be",
		merge:     mergeUnion,
		wholeRoot: true,
		read: func(o *options, _ *configurationKey, s string, _ valueOrigin) error {
			e, err := lint.ParseExclude(s)
			if err != nil {
				return err
			}
			o.exclude = append(o.exclude, e)
			return nil
		},
	},
	{
		name:  "fail-on",
		form:  formOne,
		help:  "the lowest severity that sets bits 1, 2 and 8 (info, low, medium, high, critical): for a finding, the severity of the finding; the severity of a finding whose certainty is inconclusive is the worst severity of the finding kinds of the rule of the finding. When --fail-on is not given, every severity sets the bits, except for an inconclusive finding that an entry of --accept matches. Whatever --fail-on is, an inconclusive finding that an entry of --accept matches sets no bit",
		merge: mergeReplace,
		read: func(o *options, _ *configurationKey, s string, _ valueOrigin) error {
			sev, err := lint.ParseSeverity(s)
			if err != nil {
				return err
			}
			o.threshold = sev
			return nil
		},
	},
	{
		name:  "rule",
		form:  formList,
		help:  "run only the rule with this ID, or the rules with these IDs joined by commas; the fixes of --fix are checked only with the rules that run. --rule runs the rule whatever the default run of the rule (default_run in the JSON of --registry)",
		merge: mergeSelection,
		read:  func(o *options, _ *configurationKey, s string, _ valueOrigin) error { return o.only.Set(s) },
	},
	{
		name:  "skip-rule",
		form:  formList,
		help:  "run every rule but the one with this ID, or but those with these IDs joined by commas; the fixes of --fix are checked only with the rules that run. A rule whose default run does not hold in the run (default_run in the JSON of --registry, and default run among the item names of --explain terms) does not run either",
		merge: mergeSelection,
		read:  func(o *options, _ *configurationKey, s string, _ valueOrigin) error { return o.skip.Set(s) },
	},
	{
		name:  "accept",
		form:  formOne,
		help:  "a file of acceptances (schema/acceptances-v0.json): a finding whose certainty is inconclusive, and whose rule, inconclusive kind, input, key_path, span_text and span_lines are equal to those of an entry of the file, does not set bit 8, and the report keeps the finding with the reason of the entry. When the rule of an entry ran and the input of the entry was read, and the entry matches no inconclusive finding, a line on stderr names the entry; the line does not change the exit code. When the rule of an entry did not run or the input of the entry was not read, nothing is written about the entry",
		merge: mergeReplace,
		path:  true,
		read: func(o *options, k *configurationKey, s string, from valueOrigin) error {
			o.acceptBy, o.acceptFrom = o.givenBy(k, from), from
			return nonEmpty(&o.acceptIn, s)
		},
	},
	{
		name:  "facts",
		form:  formOne,
		help:  "a file of facts to answer from, before GitHub",
		merge: mergeReplace,
		path:  true,
		read: func(o *options, k *configurationKey, s string, from valueOrigin) error {
			o.factsBy, o.factsFrom = o.givenBy(k, from), from
			return nonEmpty(&o.factsIn, s)
		},
	},
	{
		name:         "repo",
		form:         formOne,
		help:         "the repository the inputs are of, owner/name: the rules name it in the facts about the repository, which --online then asks the API",
		flagNote:     " (in a workflow, --repo \"$GITHUB_REPOSITORY\")",
		templateNote: " The value in this configuration file is not expanded: $GITHUB_REPOSITORY in the value is not replaced by the name of the repository. In a workflow, give --repo \"$GITHUB_REPOSITORY\" on the command line instead.",
		merge:        mergeReplace,
		read: func(o *options, _ *configurationKey, s string, _ valueOrigin) error {
			r, err := facts.ParseRepo(s)
			if err != nil {
				return err
			}
			o.repo = r
			return nil
		},
	},
	{
		name:  "fact",
		form:  formList,
		help:  "answer a fact, as KIND=VALUE or KIND[ARG=VALUE,...]=VALUE with the value as JSON (repo.public=false), before the file of facts and GitHub. A repo.* fact is of the repository of --repo",
		merge: mergeUnion,
		read:  readFact,
	},
	{
		name:  "add-attacker",
		form:  formList,
		help:  "run the rules also with this attacker added, which a run does not count by default (read-member, triage-account, writer-pull-requests-token, writer-issues-token, required-reviewer, app-installation-token, variables-writer, secrets-writer), or with these attackers joined by commas. A finding, of any certainty, that appears only because of an added attacker is marked with the added attackers (added_attackers). A marked finding sets the same bits of the exit code as a finding of the same certainty that is not marked. --add-attacker cannot be used with --fix",
		merge: mergeUnion,
		read: func(o *options, _ *configurationKey, s string, _ valueOrigin) error {
			for _, item := range strings.Split(s, ",") {
				v, err := lint.ParseAddedAttacker(strings.TrimSpace(item))
				if err != nil {
					return err
				}
				o.added = append(o.added, v)
			}
			return nil
		},
	},
}

// givenBy names where the value of k was given, for an error: the flag, or
// the configuration file and the key.
func (o *options) givenBy(k *configurationKey, from valueOrigin) string {
	if from == originFile {
		return "--config " + o.configurationPath + ": " + k.name
	}
	return "--" + k.name
}

// chooseRules sets the rules of the run from the values of the keys of
// mergeSelection, which mergeValues leaves from one place only.
func (o *options) chooseRules(values []keyValue) {
	for _, v := range values {
		if v.key.merge == mergeSelection {
			o.selectBy, o.selectedInFile = o.givenBy(v.key, v.from), v.from == originFile
		}
	}
	switch {
	case o.only.set:
		o.selection = lint.Only(o.only.of...)
	case o.skip.set:
		o.selection = lint.Skip(o.skip.of...)
	}
}

// fileError is the error err of the file p that a key names, given at by
// (givenBy) from from. From the configuration file it is the key, a colon,
// and the error, with p only when err does not name p; from the command
// line it is the flag and p, as before the configuration file.
func fileError(by string, from valueOrigin, p string, err error) error {
	var named *fs.PathError
	switch {
	case from != originFile:
		return fmt.Errorf("%s %s: %w", by, p, err)
	case errors.As(err, &named):
		return fmt.Errorf("%s: %w", by, err)
	}
	return fmt.Errorf("%s: %s: %w", by, p, err)
}

// nonEmpty sets *to to s, which may not be empty.
func nonEmpty(to *string, s string) error {
	if s == "" {
		return errors.New("the value is empty")
	}
	*to = s
	return nil
}

// readFact reads a value of fact. A fact given on the command line
// replaces the same fact given in the configuration file; a fact given
// twice from the same place is an error.
func readFact(o *options, _ *configurationKey, s string, from valueOrigin) error {
	e, err := parseFact(s, o.repo)
	if err != nil {
		return err
	}
	if _, err := facts.Arguments([]facts.Entry{e}); err != nil {
		return err
	}
	for i, g := range o.given {
		if g.Query != e.Query {
			continue
		}
		if o.givenFrom[i] == from {
			return fmt.Errorf("%s: the fact is given twice", s)
		}
		o.given[i], o.givenFrom[i] = e, from
		return nil
	}
	o.given, o.givenFrom = append(o.given, e), append(o.givenFrom, from)
	return nil
}

// keyUsage is the usage of the flag of k.
func keyUsage(k configurationKey) string {
	if k.form == formList {
		return k.help + k.flagNote + "; --" + k.name + " may be given again on the command line"
	}
	return k.help + k.flagNote
}

// keyFlag is the flag of a key: each value given is added to to.
type keyFlag struct {
	key *configurationKey
	to  *[]keyValue
}

func (f keyFlag) String() string { return "" }

func (f keyFlag) Set(s string) error {
	*f.to = append(*f.to, keyValue{f.key, s, originCommandLine})
	return nil
}

// registerKeys defines on fs a flag for each key, whose values are added
// to to.
func registerKeys(fs *flag.FlagSet, to *[]keyValue) {
	for i := range configurationKeys {
		k := &configurationKeys[i]
		fs.Var(keyFlag{k, to}, k.name, keyUsage(*k))
	}
}

// keyValue is a value of a key and where it was given.
type keyValue struct {
	key   *configurationKey
	value string
	from  valueOrigin
}

// configurationError is an error in the configuration file.
type configurationError struct{ error }

// applyValues reads values into o, key by key in the order of
// configurationKeys. An error of a value given on the command line is a
// usageError, and one of a value of the configuration file is a
// configurationError.
func applyValues(o *options, values []keyValue) error {
	fail := func(v keyValue, err error) error {
		if v.from == originFile {
			return configurationError{fmt.Errorf("%s: %w", v.key.name, err)}
		}
		return usageError{fmt.Errorf("--%s: %w", v.key.name, err)}
	}
	var selected []keyValue // the values of the keys of mergeSelection
	for i := range configurationKeys {
		k := &configurationKeys[i]
		for _, v := range values {
			if v.key != k {
				continue
			}
			if err := k.read(o, k, v.value, v.from); err != nil {
				return fail(v, err)
			}
			if k.merge == mergeSelection {
				selected = append(selected, v)
			}
		}
	}
	if o.only.set && o.skip.set {
		v := selected[len(selected)-1]
		if v.from == originFile {
			return configurationError{fmt.Errorf("a configuration file cannot have both %s: give the rules to run, or the rules to leave out", keyNames("and", selectionKey))}
		}
		return usageError{fmt.Errorf("%s do not go together: give the rules to run, or those to leave out", flagNames("and", selectionKey))}
	}
	if len(o.given) > 0 {
		a, err := facts.Arguments(o.given)
		if err != nil {
			return usageError{fmt.Errorf("the facts given: %w", err)} // readFact checks each fact, and that none is given twice
		}
		o.arguments = a
	}
	return nil
}

// readConfigurationFile reads the configuration file p: a YAML mapping of
// keys of configurationKeys. A key with a null value is as if it were not
// there. The values of a key whose value is a path are made relative to
// the directory of p. An error is a configurationError.
func readConfigurationFile(p string) ([]keyValue, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, configurationError{err}
	}
	t := cst.Parse(b)
	if len(t.Errors()) != 0 {
		return nil, configurationError{fmt.Errorf("not YAML that can be read: %v", t.Errors()[0])}
	}
	var docs []cst.Node
	for e := range t.Root().Children() {
		if d, ok := e.Node(); ok && d.Kind() == cst.NodeDocument {
			docs = append(docs, d)
		}
	}
	switch {
	case len(docs) == 0:
		return nil, nil
	case len(docs) > 1:
		return nil, configurationError{errors.New("more than one YAML document")}
	}
	d := scalar.DirectivesOf(docs[0])
	var top cst.Node
	present := false
	for c := range docs[0].Children() {
		if n, ok := c.Node(); ok && n.Kind() != cst.NodeDirective {
			top, present = n, true
			break
		}
	}
	if !present || scalar.Resolve(top, d) == scalar.TagNull {
		return nil, nil
	}
	m, ok := top.Mapping()
	if !ok {
		return nil, configurationError{errors.New("the top level of the file is not a YAML mapping of keys to values")}
	}
	var values []keyValue
	seen := map[*configurationKey]bool{}
	for e := range m.Entries() {
		name, ok := scalar.Decode(e.Key)
		if !ok || scalar.Resolve(e.Key, d) != scalar.TagStr {
			return nil, configurationError{errors.New("a key that is not a string")}
		}
		k := keyNamed(name.String())
		if k == nil {
			return nil, configurationError{fmt.Errorf("%s: not a key (the keys are %s)", name.String(), keyNames("and", func(configurationKey) bool { return true }))}
		}
		if seen[k] {
			return nil, configurationError{fmt.Errorf("%s: the key is given twice", k.name)}
		}
		seen[k] = true
		strs, err := keyStrings(*k, e.Value, d)
		if err != nil {
			return nil, configurationError{fmt.Errorf("%s: %w", k.name, err)}
		}
		for _, s := range strs {
			if k.path && s != "" && !filepath.IsAbs(s) {
				s = filepath.Join(filepath.Dir(p), s)
			}
			values = append(values, keyValue{k, s, originFile})
		}
	}
	return values, nil
}

// keyStrings are the values of n, the value of the key k in the file, as
// the flag of k would be given them.
func keyStrings(k configurationKey, n cst.Node, d scalar.Directives) ([]string, error) {
	if hasAlias(n) {
		return nil, errors.New("an alias (*name) is not taken; write the value")
	}
	text := func(n cst.Node, want scalar.Tag, what string) (string, error) {
		if scalar.Resolve(n, d) != want {
			return "", fmt.Errorf("not %s", what)
		}
		v, ok := scalar.Decode(n)
		if !ok {
			return "", fmt.Errorf("not %s", what)
		}
		return v.String(), nil
	}
	switch tag := scalar.Resolve(n, d); {
	case tag == scalar.TagNull:
		return nil, nil
	case k.form == formOne:
		s, err := text(n, scalar.TagStr, "a string")
		if err != nil {
			return nil, err
		}
		return []string{s}, nil
	}
	seq, ok := n.Sequence()
	if !ok || scalar.Resolve(n, d) != scalar.TagSeq {
		return nil, errors.New("not a list of strings")
	}
	var strs []string
	for item := range seq.Items() {
		s, err := text(item, scalar.TagStr, "a list of strings")
		if err != nil {
			return nil, err
		}
		strs = append(strs, s)
	}
	return strs, nil
}

// hasAlias is whether n, or an item of n, is an alias.
func hasAlias(n cst.Node) bool {
	if n.Kind() == cst.NodeAlias {
		return true
	}
	if seq, ok := n.Sequence(); ok {
		for item := range seq.Items() {
			if item.Kind() == cst.NodeAlias {
				return true
			}
		}
	}
	return false
}

// selectionKey holds for the keys that choose the rules together.
func selectionKey(k configurationKey) bool { return k.merge == mergeSelection }

// keyNamed is the key named name; nil when there is none.
func keyNamed(name string) *configurationKey {
	for i := range configurationKeys {
		if configurationKeys[i].name == name {
			return &configurationKeys[i]
		}
	}
	return nil
}

// keyNames are the names of the keys for which with holds, as a list in
// English joined by conjunction (and, or).
func keyNames(conjunction string, with func(configurationKey) bool) string {
	var names []string
	for _, k := range configurationKeys {
		if with(k) {
			names = append(names, k.name)
		}
	}
	return englishList(conjunction, names)
}

// englishList is names joined by commas, with conjunction before the last.
func englishList(conjunction string, names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " " + conjunction + " " + names[len(names)-1]
}

// mergeValues are the values of the command line and of the configuration
// file together, by the merge rule of each key: those of the file first.
func mergeValues(commandLine, file []keyValue) []keyValue {
	given := map[*configurationKey]bool{}
	selection := false
	for _, v := range commandLine {
		given[v.key] = true
		selection = selection || v.key.merge == mergeSelection
	}
	var merged []keyValue
	for _, v := range file {
		switch {
		case v.key.merge == mergeSelection && selection:
		case v.key.merge == mergeReplace && given[v.key]:
		default:
			merged = append(merged, v)
		}
	}
	return append(merged, commandLine...)
}

// configurationUsage is the usage of --config.
func configurationUsage() string {
	all := func(configurationKey) bool { return true }
	selection := func(k configurationKey) bool { return k.merge == mergeSelection }
	return fmt.Sprintf("read the keys of this configuration file (YAML) as the flags of the same names: %s. A flag given on the command line replaces the value of the key of the same name in the file, with two exceptions: the values of %s on the command line are used in addition to the values in the file, and when either %s is on the command line, %s of the file is used. sisakulint reads a relative path in the key %s from the directory of the configuration file. In a run that reads only the PATHs (without --read-all) or only stdin (--stdin-name), sisakulint does not use the key %s of the file",
		keyNames("and", all),
		flagNames("and", func(k configurationKey) bool { return k.merge == mergeUnion }),
		flagNames("or", selection),
		noneOfKeys(selection),
		keyNames("or", func(k configurationKey) bool { return k.path }),
		keyNames("or", func(k configurationKey) bool { return k.wholeRoot }))
}

// noneOfKeys says, in English, that no key for which with holds is used:
// "neither the key a nor the key b", or "none of the keys a, b and c".
func noneOfKeys(with func(configurationKey) bool) string {
	var names []string
	for _, k := range configurationKeys {
		if with(k) {
			names = append(names, k.name)
		}
	}
	if len(names) == 2 {
		return "neither the key " + names[0] + " nor the key " + names[1]
	}
	return "none of the keys " + englishList("and", names)
}

// flagNames are the flags of the keys for which with holds, as a list in
// English joined by conjunction.
func flagNames(conjunction string, with func(configurationKey) bool) string {
	var names []string
	for _, k := range configurationKeys {
		if with(k) {
			names = append(names, "--"+k.name)
		}
	}
	return englishList(conjunction, names)
}
