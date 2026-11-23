package labeler

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
)

// Format is how a release of the labeler reads its configuration.
type Format uint8

const (
	FormatGlobs      Format = iota // 2.2.0: a label is a glob or a list of globs, any of which matches a changed file
	FormatAnyAll                   // v3, v4: a list of globs and of any and all
	FormatKeys                     // v5, v6: changed-files, head-branch, base-branch, any and all
	FormatKeysLimits               // v6.1.0 on: FormatKeys with max-files-changed and changed-files-labels-limit
)

// Reach is whether an attacker gets one label of the configuration on
// their pull request: never, free (with any files of their choice), or
// only on the conditions that leave it undecided (paths, a base branch).
type Reach struct{ marks uint8 }

const (
	markFree uint8 = 1 << iota
	markPaths
	markBaseBranch
)

var (
	never      = Reach{}
	freeReach  = Reach{markFree}
	pathsReach = Reach{markPaths}
	baseReach  = Reach{markBaseBranch}
)

// Never is whether the attacker never gets the label.
func (r Reach) Never() bool { return r.marks == 0 }

// Labels are the automatic labels of r: Free alone, or the conditions
// that leave it undecided; none when r is Never.
func (r Reach) Labels() []analysis.AutomaticLabel {
	if r.marks&markFree != 0 {
		return []analysis.AutomaticLabel{analysis.AutomaticLabelFree}
	}
	var out []analysis.AutomaticLabel
	if r.marks&markPaths != 0 {
		out = append(out, analysis.AutomaticLabelPaths)
	}
	if r.marks&markBaseBranch != 0 {
		out = append(out, analysis.AutomaticLabelBaseBranch)
	}
	return out
}

// or is a condition that either of r and s meets: free when one is.
func (r Reach) or(s Reach) Reach {
	if (r.marks|s.marks)&markFree != 0 {
		return freeReach
	}
	return Reach{r.marks | s.marks}
}

// and is a condition that both of r and s meet: never when one is never,
// free when both are, else the conditions that are not free.
func (r Reach) and(s Reach) Reach {
	if r.Never() || s.Never() {
		return never
	}
	m := (r.marks | s.marks) &^ markFree
	if m == 0 {
		return freeReach
	}
	return Reach{m}
}

func anyOf(rs ...Reach) Reach {
	out := never
	for _, r := range rs {
		out = out.or(r)
	}
	return out
}

func allOf(rs ...Reach) Reach {
	out := freeReach
	for _, r := range rs {
		out = out.and(r)
	}
	return out
}

// ParseConfig reads the labels of the configuration text as a release of
// format f does, and whether an attacker gets each. An error is a
// configuration on which the labeler throws and adds no label;
// ErrUnsupportedSyntax is one this does not read.
func ParseConfig(text []byte, f Format) (map[string]Reach, error) {
	top, err := readValue(text)
	if err != nil {
		return nil, err
	}
	labels := map[string]Reach{}
	switch top.kind {
	case kindNull:
		return labels, nil
	case kindMapping:
	default:
		return nil, errors.New("the configuration is not a mapping of labels")
	}
	var limits configLimits
	usesFiles := map[string]bool{}
	for _, e := range top.entries {
		if f == FormatKeysLimits && slices.Contains(limitKeys, e.key) {
			if err := limits.read(e.key, e.val); err != nil {
				return nil, err
			}
			continue
		}
		var r Reach
		ok := true
		switch f {
		case FormatGlobs:
			r, err = globsLabel(e.val)
		case FormatAnyAll:
			r, err = anyAllLabel(e.val)
		default:
			r, usesFiles[e.key], ok, err = keysLabel(e.val)
		}
		if err != nil {
			return nil, fmt.Errorf("the label %s: %w", e.key, err)
		}
		if ok {
			labels[e.key] = r
		}
	}
	if f == FormatKeysLimits {
		limits.apply(labels, usesFiles)
	}
	return labels, nil
}

// globsLabel is a label of 2.2.0: a glob or a list of globs, any of which
// matching one changed file adds the label (main.ts, checkGlobs).
func globsLabel(v value) (Reach, error) {
	globs, err := stringOrList(v)
	if err != nil {
		return never, err
	}
	for _, g := range globs {
		if g.kind != kindString {
			return never, errors.New("a glob is not a string, on which minimatch throws")
		}
	}
	if len(globs) == 0 {
		return never, nil
	}
	return freeReach, nil
}

// anyAllLabel is a label of v3 and v4: a list of globs and of any and all,
// any item of which matching adds the label (labeler.ts, checkGlobs). A
// glob is any: [glob]; any is one changed file matching every glob of it;
// all is every changed file matching every glob of it; an item with
// neither matches every pull request.
func anyAllLabel(v value) (Reach, error) {
	items, err := stringOrList(v)
	if err != nil {
		return never, err
	}
	out := never
	for _, item := range items {
		switch item.kind {
		case kindString:
			out = out.or(freeReach)
		case kindNull:
			return never, errors.New("an item is null, whose any and all the labeler cannot read")
		case kindMapping:
			r := freeReach
			if all, ok := item.lookup("all"); ok {
				globs, err := globList(all)
				if err != nil {
					return never, err
				}
				r = r.and(everyFile(globs))
			}
			if any, ok := item.lookup("any"); ok {
				if _, err := globList(any); err != nil {
					return never, err
				}
			}
			out = out.or(r)
		default: // a number or a list has no any and no all: it matches
			out = out.or(freeReach)
		}
	}
	return out, nil
}

// keysLabel is a label of v5 to v7 (get-label-configs.ts,
// getLabelConfigMapFromObject): a list of objects, each of which is any,
// all, or a key of a condition that goes into the first any. The label is
// added when every any and all of it matches (labeler.ts,
// checkMatchConfigs). usesFiles is whether a condition of it has globs of
// changed-files (configUsesChangedFiles). ok is false for a label with
// nothing to match, which the labeler leaves out.
func keysLabel(v value) (r Reach, usesFiles, ok bool, err error) {
	if v.kind != kindSequence {
		return never, false, false, errors.New("the label is not a list of config options")
	}
	var configs []matchConfig
	firstAny := func() int { return slices.IndexFunc(configs, func(c matchConfig) bool { return !c.all }) }
	for _, item := range v.items {
		switch item.kind {
		case kindNull:
			continue
		case kindMapping, kindSequence: // typeof is object; a list has keys 0, 1, … the labeler ignores
		default:
			return never, false, false, errors.New("the label is not a list of config options")
		}
		for _, e := range item.entries {
			switch {
			case e.key == "any" || e.key == "all":
				if e.val.kind != kindSequence {
					continue
				}
				var bases []baseConfig
				for _, b := range e.val.items {
					c, err := readBase(b)
					if err != nil {
						return never, false, false, err
					}
					bases = append(bases, c)
				}
				configs = append(configs, matchConfig{all: e.key == "all", bases: bases})
			case slices.Contains(conditionKeys, e.key):
				c, err := readBase(value{kind: kindMapping, entries: []entry{e}})
				if err != nil {
					return never, false, false, err
				}
				i := firstAny()
				if i < 0 {
					i = len(configs)
					configs = append(configs, matchConfig{})
				}
				configs[i].bases = append(configs[i].bases, c)
			}
		}
	}
	if len(configs) == 0 {
		return never, false, false, nil
	}
	r = freeReach
	for _, c := range configs {
		r = r.and(c.reach())
	}
	return r, slices.ContainsFunc(configs, matchConfig.usesChangedFiles), true, nil
}

var conditionKeys = []string{"changed-files", "head-branch", "base-branch"}

// matchConfig is one any or all of a label of v5 to v7.
type matchConfig struct {
	all   bool
	bases []baseConfig
}

// baseConfig is one condition of an any or an all: the globs of
// changed-files, and the regular expressions of head-branch and
// base-branch, each present or not.
type baseConfig struct {
	files      []globCondition
	hasFiles   bool
	head, base []string
	hasHead    bool
	hasBase    bool
}

// globCondition is one item of changed-files: one of its four keys and its
// globs.
type globCondition struct {
	key   string
	globs []string
}

var globKeys = []string{"any-glob-to-any-file", "any-glob-to-all-files", "all-globs-to-any-file", "all-globs-to-all-files"}

// readBase reads a condition as toMatchConfig does: changed-files that is
// missing or empty is none, and one that is not a list of objects with the
// four keys throws (changedFiles.ts, toChangedFilesMatchConfig);
// head-branch and base-branch are a string or a list (branch.ts).
func readBase(v value) (baseConfig, error) {
	var c baseConfig
	if v.kind == kindNull {
		return c, errors.New("a condition is null, whose changed-files the labeler cannot read")
	}
	if v.kind != kindMapping {
		return c, nil
	}
	if cf, ok := v.lookup("changed-files"); ok && !emptyOrFalsy(cf) {
		c.hasFiles = true
		for _, item := range cf.list() {
			if item.kind != kindMapping {
				return c, errors.New(`the "changed-files" section must have a valid config structure`)
			}
			for _, e := range item.entries {
				if !slices.Contains(globKeys, e.key) {
					return c, fmt.Errorf("unknown config options were under changed-files: %s", e.key)
				}
				var globs []string
				for _, g := range e.val.list() {
					globs = append(globs, g.text)
				}
				c.files = append(c.files, globCondition{e.key, globs})
			}
		}
	}
	for _, k := range []string{"head-branch", "base-branch"} {
		b, ok := v.lookup(k)
		if !ok || !truthy(b) {
			continue // toBranchMatchConfig reads a value that is not truthy as none
		}
		var res []string
		switch b.kind {
		case kindString:
			res = []string{b.text}
		case kindSequence:
			for _, x := range b.items {
				res = append(res, x.text)
			}
		default:
			return c, fmt.Errorf("%s is not a string or a list, whose regular expressions the labeler cannot read", k)
		}
		if k == "head-branch" {
			c.head, c.hasHead = res, true
		} else {
			c.base, c.hasBase = res, true
		}
	}
	return c, nil
}

// emptyOrFalsy is changed-files that toChangedFilesMatchConfig reads as
// none: a value that is not truthy, or whose length is 0 or undefined (a
// mapping, a number).
func emptyOrFalsy(v value) bool {
	switch v.kind {
	case kindSequence:
		return len(v.items) == 0
	case kindString:
		return v.text == ""
	}
	return true
}

func (c baseConfig) empty() bool { return !c.hasFiles && !c.hasHead && !c.hasBase }

// reach is whether the attacker meets m (labeler.ts, checkAny and
// checkAll): an any or an all with no condition never matches.
func (m matchConfig) reach() Reach {
	if !slices.ContainsFunc(m.bases, func(b baseConfig) bool { return !b.empty() }) {
		return never
	}
	var rs []Reach
	for _, b := range m.bases {
		if b.empty() {
			continue
		}
		rs = append(rs, b.reach(m.all))
	}
	if m.all {
		return allOf(rs...)
	}
	return anyOf(rs...)
}

// reach is whether the attacker meets the condition b inside an all (each
// present key) or an any (one present key).
func (b baseConfig) reach(all bool) Reach {
	var rs []Reach
	if b.hasBase {
		rs = append(rs, branchReach(b.base, all, true))
	}
	if b.hasFiles {
		var fs []Reach
		for _, g := range b.files {
			fs = append(fs, globReach(g))
		}
		if all {
			rs = append(rs, allOf(fs...))
		} else {
			rs = append(rs, anyOf(fs...))
		}
	}
	if b.hasHead {
		rs = append(rs, branchReach(b.head, all, false))
	}
	if all {
		return allOf(rs...)
	}
	return anyOf(rs...)
}

// branchReach is a list of regular expressions of a branch: the attacker
// names the head branch; the base branch is one of the repository, which
// the linter does not know, unless an expression matches every name. Any
// of no expressions never matches, all of none always does.
func branchReach(res []string, all, base bool) Reach {
	if len(res) == 0 {
		if all {
			return freeReach
		}
		return never
	}
	if !base {
		return freeReach
	}
	every := func(re string) bool { return slices.Contains(everyName, re) }
	if all && !slices.ContainsFunc(res, func(re string) bool { return !every(re) }) || !all && slices.ContainsFunc(res, every) {
		return freeReach
	}
	return baseReach
}

var (
	everyName = []string{"", ".*", "^.*", ".*$", "^.*$"}
	everyPath = []string{"**", "**/*"}
)

// globReach is one item of changed-files (changedFiles.ts): to any file the
// attacker adds one file that matches; to all files every file the pull
// request changes has to match, unless the globs match every path.
func globReach(g globCondition) Reach {
	switch g.key {
	case "any-glob-to-any-file":
		if len(g.globs) == 0 {
			return never
		}
		return freeReach
	case "all-globs-to-any-file":
		return freeReach
	case "any-glob-to-all-files":
		if len(g.globs) == 0 {
			return never
		}
		if slices.ContainsFunc(g.globs, func(s string) bool { return slices.Contains(everyPath, s) }) {
			return freeReach
		}
		return pathsReach
	}
	return everyFile(g.globs)
}

// everyFile is every changed file matching every glob of globs.
func everyFile(globs []string) Reach {
	if !slices.ContainsFunc(globs, func(s string) bool { return !slices.Contains(everyPath, s) }) {
		return freeReach
	}
	return pathsReach
}

// usesChangedFiles is configUsesChangedFiles: a condition with a key of
// changed-files, its globs or none.
func (m matchConfig) usesChangedFiles() bool {
	return slices.ContainsFunc(m.bases, func(b baseConfig) bool { return len(b.files) > 0 })
}

// truthy is whether JavaScript reads v as true.
func truthy(v value) bool {
	switch v.kind {
	case kindNull:
		return false
	case kindBool:
		return strings.EqualFold(v.text, "true")
	case kindString:
		return v.text != ""
	case kindNumber:
		n, ok := number(v.text)
		return !ok || n != 0
	}
	return true
}

// number is the value of a number of the core schema of js-yaml.
func number(s string) (float64, bool) {
	s = strings.ReplaceAll(s, "_", "")
	if i, err := strconv.ParseInt(s, 0, 64); err == nil {
		return float64(i), true
	}
	f, err := strconv.ParseFloat(s, 64)
	return f, err == nil
}

// stringOrList is a label of v2 to v4: a string is a list of one.
func stringOrList(v value) ([]value, error) {
	switch v.kind {
	case kindString:
		return []value{v}, nil
	case kindSequence:
		return v.items, nil
	}
	return nil, errors.New("the label is not a string or a list of globs")
}

func globList(v value) ([]string, error) {
	if v.kind != kindSequence {
		return nil, errors.New("any and all are lists of globs")
	}
	var out []string
	for _, g := range v.items {
		out = append(out, g.text)
	}
	return out, nil
}

var limitKeys = []string{"changed-files-labels-limit", "max-files-changed"}

// configLimits are the two limits of v7 (labeler.ts): more changed files
// than max-files-changed skip every label that uses changed-files, and
// more new labels from changed-files than changed-files-labels-limit add
// none of them.
type configLimits struct {
	maxFiles, labels *int
}

func (l *configLimits) read(k string, v value) error {
	n, err := nonNegative(v, k)
	if err != nil {
		return err
	}
	if k == "max-files-changed" {
		l.maxFiles = &n
	} else {
		l.labels = &n
	}
	return nil
}

// nonNegative reads a limit as parseNonNegativeInteger does.
func nonNegative(v value, k string) (int, error) {
	switch v.kind {
	case kindNumber:
		if n, ok := number(v.text); ok && n >= 0 && n == float64(int(n)) {
			return int(n), nil
		}
	case kindString:
		s := strings.TrimSpace(v.text)
		if regexp.MustCompile(`^\d+$`).MatchString(s) {
			if n, err := strconv.Atoi(s); err == nil {
				return n, nil
			}
		}
	case kindSequence:
		return 0, fmt.Errorf("'%s' is a reserved top-level option and cannot be used as a label name", k)
	}
	return 0, fmt.Errorf("invalid value for '%s': must be a non-negative integer", k)
}

// apply makes the labels that use changed-files never, when no pull
// request gets them, and paths when a pull request of one file does: the
// one file has to match.
func (l *configLimits) apply(labels map[string]Reach, usesFiles map[string]bool) {
	for k, r := range labels {
		if !usesFiles[k] {
			continue
		}
		switch {
		case l.maxFiles != nil && *l.maxFiles == 0, l.labels != nil && *l.labels == 0:
			labels[k] = never
		case l.maxFiles != nil && *l.maxFiles == 1 && r == freeReach:
			labels[k] = pathsReach
		}
	}
}
