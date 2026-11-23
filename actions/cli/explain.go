package cli

import (
	"errors"
	"fmt"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/rules"
)

// explainFlag is --explain: the rules asked, or all of them, or the terms.
type explainFlag struct {
	set, all, terms bool
	ids             []lint.RuleID
}

func (f *explainFlag) String() string { return "" }

func (f *explainFlag) Set(s string) error {
	f.set = true
	switch s {
	case "all":
		f.all = true
		return nil
	case "terms":
		f.terms = true
		return nil
	}
	id, err := lint.ParseRuleID(s)
	if err != nil {
		return fmt.Errorf("%w (the rules are %s)", err, ruleIDs())
	}
	f.ids = append(f.ids, id)
	return nil
}

// ruleIDs are the IDs of rules.All and rules.Quality, in their order, for
// the errors of --explain.
func ruleIDs() string {
	var ids []string
	for _, r := range rules.All() {
		ids = append(ids, r.Meta().ID.String())
	}
	for _, q := range rules.Quality() {
		ids = append(ids, q.QualityMeta().ID.String())
	}
	slices.Sort(ids)
	return strings.Join(ids, ", ")
}

// explain is the Markdown of the rules f asks of reg, or of the terms; an
// ID reg does not have is a usageError that names the ones it has, and so
// are the terms with a rule.
func explain(reg *lint.Registry, f explainFlag) ([]byte, error) {
	if f.terms {
		if f.all || len(f.ids) > 0 {
			return nil, usageError{errors.New("--explain=terms is the terms alone: it takes no rule and no all")}
		}
		return lint.Terms(commit(debug.ReadBuildInfo())), nil
	}
	ids := f.ids
	if f.all {
		ids = nil
	}
	for _, id := range ids {
		if _, ok := reg.Meta(id); !ok && !reg.IsQuality(id) {
			return nil, usageError{fmt.Errorf("--explain: no rule %s (the rules are %s)", id, ruleIDs())}
		}
	}
	return reg.Explain(ids, commit(debug.ReadBuildInfo()))
}

// commit is the commit the binary was built from, as debug.ReadBuildInfo
// gives it (bi, ok): its vcs.revision, marked when vcs.modified; unknown
// when there is none.
func commit(bi *debug.BuildInfo, ok bool) string {
	if !ok || bi == nil {
		return "unknown"
	}
	rev, modified := "", false
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	switch {
	case rev == "":
		return "unknown"
	case modified:
		return rev + " (modified)"
	}
	return rev
}
