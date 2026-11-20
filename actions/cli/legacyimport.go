package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// importedFact is the answer of a fact that --init writes from the legacy
// configuration file. args are the arguments, as between the brackets of
// --fact; value is the value as JSON, or empty when the value is a list,
// whose items as JSON are list. notes are the differences between what
// sisakulint 0.x did with the entries and what this linter does with the
// fact: --init writes them as comments before the value.
type importedFact struct {
	kind  facts.Kind
	args  string
	list  []string
	value string
	notes []string
}

// factText is f as a value of --fact.
func (f importedFact) factText() string {
	s := f.kind.String()
	if f.args != "" {
		s += "[" + f.args + "]"
	}
	if f.value != "" {
		return s + "=" + f.value
	}
	return s + "=[" + strings.Join(f.list, ", ") + "]"
}

// legacyNote is an entry of the legacy configuration file that --init does
// not write as a fact, and why: --init writes it as a comment and as a
// line on stderr.
type legacyNote struct{ text string }

// notWritten is the note of the item i of the key key.
func notWritten(key string, i legacyItem, why string) legacyNote {
	return legacyNote{fmt.Sprintf("%s, line %d: %s is not written: %s", key, i.line, strconv.Quote(i.text), why)}
}

// The differences between action-list in sisakulint 0.x and repo.action-list.
var actionListNotes = []string{
	"sisakulint 0.x checked the uses of the steps only. This linter checks the uses of the steps, the uses of the jobs (reusable workflows) and the uses of the steps in action metadata files (action.yml) against repo.action-list.",
	"This linter compares the part of a pattern before the first * that names the owner and the repository case-insensitively, as GitHub compares the owner and the repository, and compares the rest of the pattern case-sensitively. sisakulint 0.x compared the whole pattern case-sensitively.",
	"This linter does not check a uses of ./ or $/ (an action or a workflow of the repository itself). sisakulint 0.x checked a uses of ./ against action-list too.",
	"This linter also checks the images of the container and of the services of each job against repo.action-list, as docker://IMAGE, and sisakulint 0.x did not check those images. So this linter reports a job whose container or service has an image that no pattern matches; to allow the image, add a pattern docker://IMAGE to repo.action-list.",
	"This linter checks a uses as GitHub reads the uses, with the empty parts and the . and .. parts of the path resolved. sisakulint 0.x checked a uses as the uses is written.",
}

// legacyActionList writes action-list as repo.action-list: nil when the
// list is not there, null or empty, since sisakulint 0.x then reports
// nothing. A pattern that this linter reads in another way, or that
// matches no uses this linter checks, is left out with a note; a list that
// is empty after that is still written, since sisakulint 0.x reported
// every uses that matches no pattern of a list that is not empty.
func legacyActionList(l legacyList) (*importedFact, []legacyNote) {
	if len(l.items) == 0 {
		return nil, nil
	}
	f := &importedFact{kind: facts.KindRepoActionList, list: []string{}, notes: actionListNotes}
	var notes []legacyNote
	for _, i := range l.items {
		var why string
		switch {
		case strings.HasPrefix(i.text, "!"):
			why = "in this linter, a pattern that starts with ! blocks the uses that the pattern matches; in sisakulint 0.x, the pattern matched no uses, since no uses starts with !"
		case strings.HasPrefix(i.text, "./"):
			why = "this linter does not check a uses of ./ against repo.action-list"
		}
		p, err := facts.ParseActionPattern(i.text)
		if why == "" && err != nil {
			why = "the pattern is empty or has white space or a comma, which a pattern of repo.action-list cannot have; in sisakulint 0.x, the pattern matched no uses of another repository"
		}
		if why != "" {
			notes = append(notes, notWritten("action-list", i, why))
			continue
		}
		b, err := p.MarshalJSON()
		if err != nil {
			panic(err) // a parsed pattern is not the zero one
		}
		f.list = append(f.list, string(b))
	}
	return f, notes
}

// The differences between config-variables in sisakulint 0.x and
// repo.configuration-variables.
var configurationVariableNotes = []string{
	"sisakulint 0.x did not tell the levels of a configuration variable apart. repo.configuration-variables has the names of the repository level and of the organization level. A name that only an environment defines is written here as a name of the repository level. So this linter does not report a job that reads the name without having that environment, although the value of the name is empty in that job.",
	"This linter reports a vars.<name> whose value is used, not a vars.<name> that is only compared or only decides a condition (vars.X == 'true', vars.X || 'default').",
	"--online answers repo.configuration-variables when the token can read the Variables of the repository; the answer of --online is then the names that the repository has at the time of the run.",
}

// legacyConfigurationVariables writes config-variables as
// repo.configuration-variables: nil when the key is not there or is null,
// since sisakulint 0.x then checks no name; an empty list is written, as
// sisakulint 0.x then allowed no name. The fact has no argument repo: a
// value of --fact without repo is the fact of the repository of --repo.
func legacyConfigurationVariables(l legacyList) (*importedFact, []legacyNote) {
	if !l.present || l.null {
		return nil, nil
	}
	f := &importedFact{kind: facts.KindRepoConfigurationVariables, list: []string{}, notes: configurationVariableNotes}
	var notes []legacyNote
	seen := map[facts.ConfigurationVariableName]bool{}
	for _, i := range l.items {
		n, err := facts.ParseConfigurationVariableName(i.text)
		if err == nil && seen[n] {
			continue // GitHub compares the names without case
		}
		seen[n] = true
		if err != nil {
			notes = append(notes, notWritten("config-variables", i, "no level of GitHub can define a configuration variable of the name: a name has only ASCII letters, digits and _, does not start with a digit and does not start with GITHUB_"))
			continue
		}
		b, err := n.MarshalJSON()
		if err != nil {
			panic(err) // a parsed name is not the zero one
		}
		f.list = append(f.list, string(b))
	}
	return f, notes
}
