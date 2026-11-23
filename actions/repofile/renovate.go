package repofile

import (
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// renovateFiles are the configuration files of Renovate on GitHub, in the
// order Renovate looks for them; it reads the first that is there
// (lib/config/app-strings.ts and lib/workers/repository/init/merge.ts of
// https://github.com/renovatebot/renovate/tree/33483f9e6a79721cd22b613505d40cea019d55f6).
// package.json counts only with the key renovate.
var renovateFiles = []string{
	"renovate.json", "renovate.jsonc", "renovate.json5",
	".github/renovate.json", ".github/renovate.jsonc", ".github/renovate.json5",
	".renovaterc", ".renovaterc.json", ".renovaterc.jsonc", ".renovaterc.json5",
	"package.json",
}

// The presets of Renovate (lib/config/presets/internal and the
// removedPresets of lib/config/presets/common.ts of
// https://github.com/renovatebot/renovate/tree/33483f9e6a79721cd22b613505d40cea019d55f6)
// that change whether the manager github-actions updates a file: the others
// set nothing that the rule reads.
var (
	// presetsDisable and presetsEnable set enabled.
	presetsDisable = []string{":disableRenovate", "default:disableRenovate"}
	presetsEnable  = []string{":enableRenovate", "default:enableRenovate"}
	// presetsIgnoreModulesAndTests set ignorePaths to ignoreModulesAndTests,
	// themselves or through config:recommended, config:js-app or
	// config:js-lib (a name of removedPresets stands for its new name).
	presetsIgnoreModulesAndTests = []string{":ignoreModulesAndTests", "default:ignoreModulesAndTests",
		"config:recommended", "config:base", "config:best-practices", "config:js-app", "config:js-lib",
		":base", ":app", ":js-app", ":library", "config:application", "config:base-js", "config:library",
		"default:base", "default:app", "default:js-app", "default:library"}
	// presetsIncludeNodeModules set ignorePaths to none.
	presetsIncludeNodeModules = []string{":includeNodeModules", "default:includeNodeModules"}
	// presetsNotRead turn packages off by packageRules, or were removed
	// with nothing in their place: what they do is not read.
	presetsNotRead = []string{"security:only-security-updates", ":disableDigestUpdates", "default:disableDigestUpdates",
		":disableMajorUpdates", "default:disableMajorUpdates", ":autodetectPinVersions", ":autodetectRangeStrategy",
		":enableGradleLite", ":switchToGradleLite", "default:onlyNpm", "helpers:oddIsUnstable", "helpers:oddIsUnstablePackages"}
	// presetGroups are the groups of the internal presets; "" is :name.
	presetGroups = []string{"", "abandonments", "config", "customManagers", "default", "docker", "global", "group",
		"helpers", "mergeConfidence", "monorepo", "packages", "preview", "replacements", "schedule", "security", "workarounds"}
)

// updateTypes are the types of updates of Renovate that an object of
// the configuration may turn off (enabled false in it).
var updateTypes = []string{"major", "minor", "patch", "pin", "digest", "pinDigest", "rollback", "replacement"}

var (
	defaultIgnorePaths    = []string{"**/node_modules/**", "**/bower_components/**"}
	ignoreModulesAndTests = []string{"**/node_modules/**", "**/bower_components/**", "**/vendor/**", "**/examples/**",
		"**/__tests__/**", "**/test/**", "**/tests/**", "**/__fixtures__/**"}
)

// managerFilePatterns are the default managerFilePatterns of the managers
// (lib/modules/manager/<manager>/index.ts of renovate 33483f9e,
// the same tree).
var managerFilePatterns = map[facts.RenovateManager][]*regexp.Regexp{
	facts.RenovateManagerGitHubActions: {
		regexp.MustCompile(`(^|/)(workflow-templates|\.(?:github|gitea|forgejo)/(?:workflows|actions))/.+\.ya?ml$`),
		regexp.MustCompile(`(^|/)action\.ya?ml$`),
	},
}

// object is a JSON object whose keys are read as written: Renovate tells
// keys apart by their case, as encoding/json into a struct does not.
type object map[string]json.RawMessage

// boolean is the boolean of the key k: ok false when there is none, err
// when it is not a boolean.
func (o object) boolean(k string) (v, ok bool, err error) {
	raw, ok := o[k]
	if !ok {
		return false, false, nil
	}
	return v, true, json.Unmarshal(raw, &v)
}

// strings is the array of strings of the key k.
func (o object) strings(k string) (v []string, ok bool, err error) {
	raw, ok := o[k]
	if !ok {
		return nil, false, nil
	}
	return v, true, json.Unmarshal(raw, &v)
}

// object is the object of the key k.
func (o object) object(k string) (v object, ok bool, err error) {
	raw, ok := o[k]
	if !ok {
		return nil, false, nil
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, true, err
	}
	if v == nil {
		return nil, true, errors.New("null")
	}
	return v, true, nil
}

// renovateManagerEnabled answers q from the first configuration file of
// Renovate.
func (r resolver) renovateManagerEnabled(q facts.RenovateManagerEnabled) facts.RawAnswer {
	name, text, why := r.renovateConfigText()
	switch {
	case why != "":
		return unknown(why)
	case name == "":
		return found(false)
	}
	var cfg object
	if err := json.Unmarshal(text, &cfg); err != nil || cfg == nil {
		return unknown(name + " is not a JSON object that can be read")
	}
	v, reason := handles(cfg, q.Manager, q.InputPath.String())
	if reason != "" {
		return unknown(name + ": " + reason)
	}
	return found(v)
}

// renovateConfigText is the name and the JSON of the first configuration
// file there is; name is empty when there is none, why is set when the
// file cannot be read.
func (r resolver) renovateConfigText() (name string, text []byte, why string) {
	for _, n := range renovateFiles {
		b, ok, err := r.readFile(n)
		if err != nil {
			return "", nil, "reading " + n + ": " + err.Error()
		}
		if !ok {
			continue
		}
		if n == "package.json" {
			var pkg object
			if json.Unmarshal(b, &pkg) != nil {
				continue // Renovate passes over a package.json it cannot read
			}
			v, ok := pkg["renovate"]
			if !ok || falsy(v) {
				continue // and over one without the key renovate, or with a value that is false in JavaScript
			}
			return n, v, ""
		}
		return n, stripJSONC(b), ""
	}
	return "", nil, ""
}

// falsy is whether the JSON value v is false in JavaScript.
func falsy(v json.RawMessage) bool {
	switch strings.TrimSpace(string(v)) {
	case "null", "false", "0", "-0", `""`:
		return true
	}
	return false
}

// handles is whether cfg has the manager m update the file p; reason is why
// that is not known, when it is not. cfg is laid over its presets, so a
// setting of cfg that turns the manager off decides before a preset whose
// content is not read.
func handles(cfg object, m facts.RenovateManager, p string) (bool, string) {
	enabled, hasEnabled, err := cfg.boolean("enabled")
	if err != nil {
		return false, "enabled is not a boolean"
	}
	if hasEnabled && !enabled {
		return false, ""
	}
	managers, _, err := cfg.strings("enabledManagers")
	if err != nil {
		return false, "enabledManagers is not an array of strings"
	}
	if len(managers) > 0 && !slices.Contains(managers, m.String()) {
		return false, ""
	}
	mgr, _, err := cfg.object(m.String())
	if err != nil {
		return false, "the object " + m.String() + " is not an object"
	}
	if off, has, err := mgr.boolean("enabled"); err != nil {
		return false, "the enabled of " + m.String() + " is not a boolean"
	} else if has && !off {
		return false, ""
	}
	ignore := defaultIgnorePaths
	disabled := false
	extends, _, err := cfg.strings("extends")
	if err != nil {
		return false, "extends is not an array of strings"
	}
	for _, e := range extends {
		name, _, _ := strings.Cut(e, "(")
		group, _, internal := strings.Cut(name, ":")
		switch {
		case !internal || strings.Contains(name, ">") || !slices.Contains(presetGroups, group) || slices.Contains(presetsNotRead, name):
			return false, "extends has " + e + ", a preset whose content is not read"
		case slices.Contains(presetsDisable, name):
			disabled = true
		case slices.Contains(presetsEnable, name):
			disabled = false
		case slices.Contains(presetsIgnoreModulesAndTests, name):
			ignore = ignoreModulesAndTests
		case slices.Contains(presetsIncludeNodeModules, name):
			ignore = nil
		}
	}
	if disabled && !hasEnabled {
		return false, ""
	}
	for _, o := range []object{cfg, mgr} {
		for _, u := range updateTypes {
			if t, has, err := o.object(u); has && err == nil {
				if on, has, _ := t.boolean("enabled"); has && !on {
					return false, "updates of the type " + u + " are turned off, which the rule does not read"
				}
			}
		}
	}
	if _, has := mgr["ignorePaths"]; has {
		return false, "the object " + m.String() + " has ignorePaths, which the rule does not read"
	}
	if include, _, _ := cfg.strings("includePaths"); len(include) > 0 {
		return false, "includePaths, which the rule does not read"
	}
	if raw, ok := cfg["packageRules"]; ok {
		var rules []object
		if json.Unmarshal(raw, &rules) != nil {
			return false, "packageRules is not an array of objects"
		}
		for _, rule := range rules {
			if why := disablesManager(rule, m); why != "" {
				return false, why
			}
		}
	}
	if paths, has, err := cfg.strings("ignorePaths"); err != nil {
		return false, "ignorePaths is not an array of strings"
	} else if has {
		ignore = paths
	}
	for _, pat := range ignore {
		if strings.Contains(p, pat) {
			return false, ""
		}
		match, ok := globMatch(pat, p)
		if !ok {
			return false, "ignorePaths has " + pat + ", a glob the rule does not read"
		}
		if match {
			return false, ""
		}
	}
	if slices.ContainsFunc(managerFilePatterns[m], func(re *regexp.Regexp) bool { return re.MatchString(p) }) {
		return true, ""
	}
	if _, has := mgr["managerFilePatterns"]; has {
		return false, "the object " + m.String() + " adds patterns of files, which the rule does not read"
	}
	if _, has := mgr["fileMatch"]; has {
		return false, "the object " + m.String() + " adds patterns of files, which the rule does not read"
	}
	return false, ""
}

// disablesManager is why the package rule may turn off every package of
// the manager m, or empty when it does not. A rule that names packages
// turns off those packages only (the undetected form ignored-dependency).
func disablesManager(rule object, m facts.RenovateManager) string {
	enabled, has, err := rule.boolean("enabled")
	if err != nil {
		return "a package rule has an enabled that is not a boolean"
	}
	if !has || enabled {
		return ""
	}
	managers, hasManagers, err := rule.strings("matchManagers")
	if err != nil {
		return "a package rule has a matchManagers that is not an array of strings"
	}
	if hasManagers {
		if slices.ContainsFunc(managers, isPattern) {
			return "a package rule matches managers by a pattern, which the rule does not read"
		}
		if !slices.Contains(managers, m.String()) {
			return ""
		}
	}
	names, _, _ := rule.strings("matchPackageNames")
	deps, _, _ := rule.strings("matchDepNames")
	if names = append(names, deps...); len(names) > 0 {
		if slices.ContainsFunc(names, isPattern) {
			return "a package rule turns off packages by a pattern, which the rule does not read"
		}
		return ""
	}
	return "a package rule turns off packages of " + m.String() + " that it does not name"
}

// isPattern is whether a value of a match list of Renovate is a glob, a
// regular expression or a negation, not a name (matchRegexOrGlobList).
func isPattern(v string) bool { return strings.ContainsAny(v, "*?!{[/") && !isActionName(v) }

// isActionName is whether n is owner/repo or owner/repo/path, a name of an
// action and not a pattern.
func isActionName(n string) bool {
	return !strings.ContainsAny(n, "*?!{[") && !strings.HasPrefix(n, "/") && strings.Count(n, "/") >= 1
}
