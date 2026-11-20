package repofile

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

func TestRenovateManagerEnabled(t *testing.T) {
	const ci = ".github/workflows/ci.yml"
	for _, c := range []struct {
		name  string
		files map[string]string
		path  string
		want  want
	}{
		{"no configuration", nil, ci, wantFalse},
		{"package.json without renovate", map[string]string{"package.json": `{"name": "x"}`}, ci, wantFalse},
		{"package.json with renovate", map[string]string{"package.json": `{"name": "x", "renovate": {}}`}, ci, wantTrue},
		{"package.json with Renovate", map[string]string{"package.json": `{"name": "x", "Renovate": {}}`}, ci, wantFalse},
		{"package.json with renovate false", map[string]string{"package.json": `{"name": "x", "renovate": false}`}, ci, wantFalse},
		{"a configuration of null", map[string]string{"renovate.json": `null`}, ci, wantUnknown},
		{"Enabled is not enabled", map[string]string{"renovate.json": `{"Enabled": false}`}, ci, wantTrue},
		{"renovate.jsonc", map[string]string{"renovate.jsonc": `{"enabled": false}`, ".github/renovate.json": `{}`}, ci, wantFalse},
		{".renovaterc.jsonc", map[string]string{".renovaterc.jsonc": `{"enabled": false}`}, ci, wantFalse},
		{"an empty configuration", map[string]string{"renovate.json": `{}`}, ci, wantTrue},
		{"the root before .github", map[string]string{"renovate.json": `{}`, ".github/renovate.json": `{"enabled": false}`}, ci, wantTrue},
		{".github before .renovaterc", map[string]string{".github/renovate.json": `{"enabled": false}`, ".renovaterc": `{}`}, ci, wantFalse},
		{"the first file only", map[string]string{"renovate.json5": `{"enabled": false}`, ".renovaterc.json": `{}`}, ci, wantFalse},
		{"JSON5 comments and a trailing comma", map[string]string{"renovate.json5": "{\n  // c\n  extends: [\"config:recommended\",],\n}"}, ci, wantUnknown},
		{"JSON5 that is JSON with comments", map[string]string{"renovate.json5": "{\n  // c\n  \"extends\": [\"config:recommended\",],\n}"}, ci, wantTrue},
		{"JSONC in renovate.json", map[string]string{"renovate.json": "{\n  /* c */ \"enabled\": true, // d\n}"}, ci, wantTrue},
		{"a comment marker in a string", map[string]string{"renovate.json": `{"ignorePaths": ["http://x//y"]}`}, ci, wantTrue},
		{"not JSON", map[string]string{"renovate.json": `{`}, ci, wantUnknown},
		{"not an object", map[string]string{"renovate.json": `[]`}, ci, wantUnknown},
		{"enabled false", map[string]string{"renovate.json": `{"enabled": false}`}, ci, wantFalse},
		{"enabledManagers without the manager", map[string]string{"renovate.json": `{"enabledManagers": ["npm"]}`}, ci, wantFalse},
		{"enabledManagers with the manager", map[string]string{"renovate.json": `{"enabledManagers": ["npm", "github-actions"]}`}, ci, wantTrue},
		{"an empty enabledManagers", map[string]string{"renovate.json": `{"enabledManagers": []}`}, ci, wantTrue},
		{"the manager off", map[string]string{"renovate.json": `{"github-actions": {"enabled": false}}`}, ci, wantFalse},
		{"ignorePaths as a string", map[string]string{"renovate.json": `{"ignorePaths": [".github/workflows"]}`}, ci, wantFalse},
		{"ignorePaths as a glob", map[string]string{"renovate.json": `{"ignorePaths": ["**/test/**"]}`}, "test/action.yml", wantFalse},
		{"ignorePaths as a glob, another file", map[string]string{"renovate.json": `{"ignorePaths": ["**/test/**"]}`}, ci, wantTrue},
		{"ignorePaths as a glob not read", map[string]string{"renovate.json": `{"ignorePaths": ["{a,b}/**"]}`}, ci, wantUnknown},
		{"the default ignorePaths", map[string]string{"renovate.json": `{}`}, "node_modules/x/action.yml", wantFalse},
		{"ignorePaths in place of the default", map[string]string{"renovate.json": `{"ignorePaths": ["vendor/"]}`}, "node_modules/x/action.yml", wantTrue},
		{"config:recommended ignores test", map[string]string{"renovate.json": `{"extends": ["config:recommended"]}`}, "test/action.yml", wantFalse},
		{"config:recommended reads a workflow", map[string]string{"renovate.json": `{"extends": ["config:recommended"]}`}, ci, wantTrue},
		{"config:base", map[string]string{"renovate.json": `{"extends": ["config:base"]}`}, "tests/x/action.yml", wantFalse},
		{":disableRenovate", map[string]string{"renovate.json": `{"extends": [":disableRenovate"]}`}, ci, wantFalse},
		{"security:only-security-updates", map[string]string{"renovate.json": `{"extends": ["security:only-security-updates"], "enabled": true}`}, ci, wantUnknown},
		{"a renamed preset", map[string]string{"renovate.json": `{"extends": [":base"]}`}, "test/action.yml", wantFalse},
		{"a removed preset", map[string]string{"renovate.json": `{"extends": ["default:onlyNpm"]}`}, ci, wantUnknown},
		{":enableRenovate after :disableRenovate", map[string]string{"renovate.json": `{"extends": [":disableRenovate", ":enableRenovate"]}`}, ci, wantTrue},
		{"enabled false over a preset not read", map[string]string{"renovate.json": `{"extends": ["github>org/x"], "enabled": false}`}, ci, wantFalse},
		{"enabledManagers over a preset not read", map[string]string{"renovate.json": `{"extends": ["github>org/x"], "enabledManagers": ["npm"]}`}, ci, wantFalse},
		{"a preset of an organization", map[string]string{"renovate.json": `{"extends": ["github>org/renovate-config"]}`}, ci, wantUnknown},
		{"a local preset", map[string]string{"renovate.json": `{"extends": ["local>org/x"]}`}, ci, wantUnknown},
		{"a preset of npm", map[string]string{"renovate.json": `{"extends": ["some-package"]}`}, ci, wantUnknown},
		{":includeNodeModules", map[string]string{"renovate.json": `{"extends": [":includeNodeModules"]}`}, "node_modules/x/action.yml", wantTrue},
		{":includeNodeModules after config:recommended", map[string]string{"renovate.json": `{"extends": ["config:recommended", ":includeNodeModules"]}`}, "test/action.yml", wantTrue},
		{"config:recommended after :includeNodeModules", map[string]string{"renovate.json": `{"extends": [":includeNodeModules", "config:recommended"]}`}, "test/action.yml", wantFalse},
		{"enabled true over :disableRenovate", map[string]string{"renovate.json": `{"extends": [":disableRenovate"], "enabled": true}`}, ci, wantTrue},
		{"an internal preset that keeps the files", map[string]string{"renovate.json": `{"extends": [":semanticCommits", "group:monorepos", ":label(deps)"]}`}, ci, wantTrue},
		{"includePaths", map[string]string{"renovate.json": `{"includePaths": ["src/"]}`}, ci, wantUnknown},
		{"packageRules off for the manager", map[string]string{"renovate.json": `{"packageRules": [{"matchManagers": ["github-actions"], "enabled": false}]}`}, ci, wantUnknown},
		{"packageRules off for everything", map[string]string{"renovate.json": `{"packageRules": [{"enabled": false}]}`}, ci, wantUnknown},
		{"packageRules off for one action", map[string]string{"renovate.json": `{"packageRules": [{"matchPackageNames": ["actions/checkout"], "enabled": false}]}`}, ci, wantTrue},
		{"packageRules off for every package", map[string]string{"renovate.json": `{"packageRules": [{"matchPackageNames": ["*"], "enabled": false}]}`}, ci, wantUnknown},
		{"packageRules off for another manager", map[string]string{"renovate.json": `{"packageRules": [{"matchManagers": ["npm"], "enabled": false}]}`}, ci, wantTrue},
		{"packageRules that keep the manager", map[string]string{"renovate.json": `{"packageRules": [{"matchManagers": ["github-actions"], "pinDigests": true}]}`}, ci, wantTrue},
		{"digest updates off", map[string]string{"renovate.json": `{"extends": [":disableDigestUpdates"]}`}, ci, wantUnknown},
		{"major updates off", map[string]string{"renovate.json": `{"extends": [":disableMajorUpdates"]}`}, ci, wantUnknown},
		{"every type of update off", map[string]string{"renovate.json": `{"major": {"enabled": false}, "minor": {"enabled": false}, "patch": {"enabled": false}}`}, ci, wantUnknown},
		{"a type of update off for the manager", map[string]string{"renovate.json": `{"github-actions": {"digest": {"enabled": false}}}`}, ci, wantUnknown},
		{"a type of update on", map[string]string{"renovate.json": `{"major": {"automerge": true}}`}, ci, wantTrue},
		{"a file the manager does not read", map[string]string{"renovate.json": `{}`}, "ci/x.yml", wantFalse},
		{"patterns of files added", map[string]string{"renovate.json": `{"github-actions": {"managerFilePatterns": ["/ci/.+\\.yml$/"]}}`}, "ci/x.yml", wantUnknown},
		{"ignorePaths of the manager", map[string]string{"renovate.json": `{"github-actions": {"ignorePaths": ["x"]}}`}, ci, wantUnknown},
		{"packageRules off for the update types", map[string]string{"renovate.json": `{"packageRules": [{"matchUpdateTypes": ["major"], "enabled": false}]}`}, ci, wantUnknown},
		{"packageRules off but for a manager", map[string]string{"renovate.json": `{"packageRules": [{"matchManagers": ["!npm"], "enabled": false}]}`}, ci, wantUnknown},
		{"packageRules off for managers by a regular expression", map[string]string{"renovate.json": `{"packageRules": [{"matchManagers": ["/^github/"], "enabled": false}]}`}, ci, wantUnknown},
		{"packageRules off for one dependency name", map[string]string{"renovate.json": `{"packageRules": [{"matchDepNames": ["actions/checkout"], "enabled": false}]}`}, ci, wantTrue},
		{"packageRules not objects", map[string]string{"renovate.json": `{"packageRules": [1]}`}, ci, wantUnknown},
		{"packageRules off by a datasource", map[string]string{"renovate.json": `{"packageRules": [{"matchDatasources": ["github-tags"], "enabled": false}]}`}, ci, wantUnknown},
		{"workflow-templates", map[string]string{"renovate.json": `{}`}, "workflow-templates/x.yml", wantTrue},
		{".github/actions", map[string]string{"renovate.json": `{}`}, ".github/actions/a/b.yml", wantTrue},
		{"an action.yaml anywhere", map[string]string{"renovate.json": `{}`}, "x/action.yaml", wantTrue},
	} {
		t.Run(c.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for name, text := range c.files {
				fsys[name] = &fstest.MapFile{Data: []byte(text)}
			}
			check(t, fsys, renovateQuery(t, c.path), c.want)
		})
	}
}

// TestRenovateUnreadable: a configuration file that cannot be read leaves
// the fact unknown.
func TestRenovateUnreadable(t *testing.T) {
	fsys := fstest.MapFS{"renovate.json": {Mode: fs.ModeDir}}
	check(t, fsys, renovateQuery(t, ".github/workflows/ci.yml"), wantUnknown)
	big := fstest.MapFS{"renovate.json": {Data: make([]byte, maxFileSize+1)}}
	check(t, big, renovateQuery(t, ".github/workflows/ci.yml"), wantUnknown)
}
