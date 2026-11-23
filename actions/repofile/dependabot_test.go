package repofile

import (
	"testing"
	"testing/fstest"
)

func dependabotFS(file, text string) fstest.MapFS {
	return fstest.MapFS{file: {Data: []byte(text)}}
}

const rootEntry = `version: 2
updates:
  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: weekly
`

func TestDependabotVersionUpdates(t *testing.T) {
	const yml = ".github/dependabot.yml"
	for _, c := range []struct {
		name, file, text, path string
		want                   want
	}{
		{"root reads a workflow", yml, rootEntry, ".github/workflows/ci.yml", wantTrue},
		{"root reads a .yaml workflow", yml, rootEntry, ".github/workflows/ci.yaml", wantTrue},
		{"root reads the root action.yml", yml, rootEntry, "action.yml", wantTrue},
		{"root reads the root action.yaml", yml, rootEntry, "action.yaml", wantTrue},
		{"root does not read below .github/workflows", yml, rootEntry, ".github/workflows/sub/x.yml", wantFalse},
		{"root does not read another action", yml, rootEntry, ".github/actions/build/action.yml", wantFalse},
		{"root does not read a file at the root", yml, rootEntry, "other.yml", wantFalse},
		{"the directory of an action", yml, "updates:\n  - package-ecosystem: github-actions\n    directory: /.github/actions/build\n", ".github/actions/build/action.yml", wantTrue},
		{"a directory with a slash at its end", yml, "updates:\n  - package-ecosystem: github-actions\n    directory: /.github/actions/build/\n", ".github/actions/build/action.yml", wantTrue},
		{"a directory without a slash at its start", yml, "updates:\n  - package-ecosystem: github-actions\n    directory: .github/actions/build\n", ".github/actions/build/action.yml", wantTrue},
		{"a directory does not read below itself", yml, "updates:\n  - package-ecosystem: github-actions\n    directory: /.github/actions\n", ".github/actions/build/action.yml", wantFalse},
		{"directories", yml, "updates:\n  - package-ecosystem: github-actions\n    directories: [\"/\", \"/.github/actions/build\"]\n", ".github/actions/build/action.yml", wantTrue},
		{"directories with the root", yml, "updates:\n  - package-ecosystem: github-actions\n    directories: [\"/\", \"/.github/actions/build\"]\n", ".github/workflows/ci.yml", wantTrue},
		{"a glob in directories", yml, "updates:\n  - package-ecosystem: github-actions\n    directories: [\"/.github/actions/*\"]\n", ".github/actions/build/action.yml", wantUnknown},
		{"a glob that the file is not near", yml, "updates:\n  - package-ecosystem: github-actions\n    directories: [\"/.github/actions/*\"]\n", ".github/workflows/ci.yml", wantUnknown},
		{"a glob and the root", yml, "updates:\n  - package-ecosystem: github-actions\n    directories: [\"/\", \"/.github/actions/*\"]\n", ".github/workflows/ci.yml", wantTrue},
		{"a glob in directory is a name", yml, "updates:\n  - package-ecosystem: github-actions\n    directory: /.github/actions/*\n", ".github/actions/build/action.yml", wantFalse},
		{"directories not a sequence", yml, "updates:\n  - package-ecosystem: github-actions\n    directories: /\n", ".github/workflows/ci.yml", wantUnknown},
		{"ignore every action", yml, rootEntry + "    ignore:\n      - dependency-name: \"*/*\"\n", ".github/workflows/ci.yml", wantUnknown},
		{"another ecosystem", yml, "updates:\n  - package-ecosystem: npm\n    directory: /\n", ".github/workflows/ci.yml", wantFalse},
		{"open-pull-requests-limit 0", yml, rootEntry + "    open-pull-requests-limit: 0\n", ".github/workflows/ci.yml", wantFalse},
		{"open-pull-requests-limit 5", yml, rootEntry + "    open-pull-requests-limit: 5\n", ".github/workflows/ci.yml", wantTrue},
		{"target-branch", yml, rootEntry + "    target-branch: develop\n", ".github/workflows/ci.yml", wantUnknown},
		{"exclude-paths", yml, rootEntry + "    exclude-paths: [\"x.yml\"]\n", ".github/workflows/ci.yml", wantUnknown},
		{"allow", yml, rootEntry + "    allow:\n      - dependency-name: actions/checkout\n", ".github/workflows/ci.yml", wantUnknown},
		{"ignore every dependency", yml, rootEntry + "    ignore:\n      - dependency-name: \"*\"\n", ".github/workflows/ci.yml", wantUnknown},
		{"ignore one dependency", yml, rootEntry + "    ignore:\n      - dependency-name: actions/checkout\n", ".github/workflows/ci.yml", wantTrue},
		{"dependabot.yaml", ".github/dependabot.yaml", rootEntry, ".github/workflows/ci.yml", wantTrue},
		{"not YAML", yml, "updates: [\n", ".github/workflows/ci.yml", wantUnknown},
		{"updates not a sequence", yml, "updates: {}\n", ".github/workflows/ci.yml", wantUnknown},
		{"no updates", yml, "version: 2\n", ".github/workflows/ci.yml", wantFalse},
	} {
		t.Run(c.name, func(t *testing.T) {
			check(t, dependabotFS(c.file, c.text), dependabotQuery(t, c.path), c.want)
		})
	}
	t.Run("no file", func(t *testing.T) {
		check(t, fstest.MapFS{}, dependabotQuery(t, ".github/workflows/ci.yml"), wantFalse)
	})
	t.Run("both names", func(t *testing.T) {
		fsys := fstest.MapFS{".github/dependabot.yml": {Data: []byte(rootEntry)}, ".github/dependabot.yaml": {Data: []byte(rootEntry)}}
		check(t, fsys, dependabotQuery(t, ".github/workflows/ci.yml"), wantUnknown)
	})
}
