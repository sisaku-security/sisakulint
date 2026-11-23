package prcode

import (
	"github.com/sisaku-security/sisakulint/actions/workflow"
	"slices"
	"strings"
	"testing"
)

// TestEvidence: the steps after a checkout that run what it
// brings.
func TestEvidence(t *testing.T) {
	for _, c := range []struct {
		name, with, after string
		runs              []string
	}{
		{"npm ci", "", "      - run: npm ci\n", []string{"npm ci"}},
		{"npm run in a list", "", "      - run: |\n          echo hi\n          npm run build && echo ok\n", []string{"npm run build"}},
		// the aliases of cmd-list.js, and the scripts stop and restart
		{"npm rum", "", "      - run: npm rum build\n", []string{"npm rum build"}},
		{"npm tst", "", "      - run: npm tst\n", []string{"npm tst"}},
		{"npm it", "", "      - run: npm it\n", []string{"npm it"}},
		{"npm cit", "", "      - run: npm cit\n", []string{"npm cit"}},
		{"npm stop", "", "      - run: npm stop\n", []string{"npm stop"}},
		{"npm restart", "", "      - run: npm restart\n", []string{"npm restart"}},
		{"npm add", "", "      - run: npm add x\n", []string{"npm add x"}},
		{"npm isntall", "", "      - run: npm isntall\n", []string{"npm isntall"}},
		// npm runs no script by its name alone, and the rule reads no
		// abbreviation
		{"npm build is no command", "", "      - run: npm build\n", nil},
		{"npm tes is not read", "", "      - run: npm tes\n", nil},
		{"npm view x is no command that runs", "", "      - run: npm view x\n", nil},
		// the commands of npm that run scripts or reify the tree
		{"npm publish", "", "      - run: npm publish\n", []string{"npm publish"}},
		{"npm pack", "", "      - run: npm pack\n", []string{"npm pack"}},
		{"npm version", "", "      - run: npm version patch\n", []string{"npm version patch"}},
		{"npm version lists", "", "      - run: npm version --json\n", nil},
		// a path that leaves the workspace by .. may come back into it
		{"a script by .. into the workspace", "", "      - run: ./../repo/build.sh\n", []string{"./../repo/build.sh"}},
		{"bash a file by .. into the workspace", "", "      - run: bash ../repo/build.sh\n", []string{"bash ../repo/build.sh"}},
		{"bash a file beside the workspace (absolute-path-out-of-tree)", "", "      - run: bash ../x.sh\n", []string{"bash ../x.sh"}},
		{"npm uninstall with no package stops", "", "      - run: npm uninstall\n", nil},
		{"npm explore with no package stops", "", "      - run: npm explore\n", nil},
		{"npm edit with no package stops", "", "      - run: npm edit\n", nil},
		{"npm version with --prefix only lists", "", "      - run: npm version --prefix web\n", nil},
		{"npm diff", "", "      - run: npm diff\n", []string{"npm diff"}},
		{"npm uninstall", "", "      - run: npm uninstall x\n", []string{"npm uninstall x"}},
		{"npm update", "", "      - run: npm update\n", []string{"npm update"}},
		{"npm dedupe", "", "      - run: npm dedupe\n", []string{"npm dedupe"}},
		{"npm link", "", "      - run: npm link\n", []string{"npm link"}},
		{"npm prune", "", "      - run: npm prune\n", []string{"npm prune"}},
		{"npm audit fix", "", "      - run: npm audit --json fix\n", []string{"npm audit --json fix"}},
		{"npm audit", "", "      - run: npm audit\n", nil},
		{"npm exec", "", "      - run: npm exec foo\n", []string{"npm exec foo"}},
		{"npm stage publish", "", "      - run: npm stage publish\n", []string{"npm stage publish"}},
		{"npm stage list", "", "      - run: npm stage list\n", nil},
		{"npm init", "", "      - run: npm init -y\n", nil},
		// the first word that names an npm command is the command
		{"npm an option's value", "", "      - run: npm --loglevel silent ci\n", []string{"npm --loglevel silent ci"}},
		{"npm not a command (npm-unknown-command)", "", "      - run: npm web ci\n", []string{"npm web ci"}},
		{"npm a value that names a command (npm-option-value-command)", "", "      - run: npm --cache view ci\n", nil},
		{"npm --prefix the tree", "", "      - run: npm --prefix web ci\n", []string{"npm --prefix web ci"}},
		{"npm --prefix the tree's directory", ", path: web", "      - run: npm --prefix web ci\n", []string{"npm --prefix web ci"}},
		{"npm --prefix a value that names a command", "", "      - run: npm --prefix view ci\n", []string{"npm --prefix view ci"}},
		{"npm -C an absolute path may be the workspace", ", path: pr", "      - run: npm -C /opt/x ci\n", []string{"npm -C /opt/x ci"}},
		// composer runs a script of composer.json whatever its command
		{"composer test", "", "      - run: composer test\n", []string{"composer test"}},
		{"composer show", "", "      - run: composer show\n", []string{"composer show"}},
		{"composer -d the tree", "", "      - run: composer -d web install\n", []string{"composer -d web install"}},
		{"composer -d an absolute path may be the workspace", ", path: pr", "      - run: composer -d /opt/x install\n", []string{"composer -d /opt/x install"}},
		{"composer --working-dir the tree's directory", ", path: pr", "      - run: composer --working-dir=pr install\n", []string{"composer --working-dir=pr install"}},
		// a setting that stops the code of the tree, for the commands it stops
		{"npm publish --ignore-scripts", "", "      - run: npm publish --ignore-scripts\n", nil},
		{"npm pack --ignore-scripts=true", "", "      - run: npm pack --ignore-scripts=true\n", nil},
		{"npm ci --ignore-scripts calls git", "", "      - run: npm ci --ignore-scripts\n", []string{"npm ci --ignore-scripts"}},
		{"npm version --ignore-scripts calls git", "", "      - run: npm version patch --ignore-scripts\n", []string{"npm version patch --ignore-scripts"}},
		{"pnpm ignore-pnpmfile is read as running (ignored-pnpmfile)", "", "      - run: pnpm --config.ignore-pnpmfile=true store prune\n", []string{"pnpm --config.ignore-pnpmfile=true store prune"}},
		{"pnpm ignore-pnpmfile and a script", "", "      - run: pnpm --config.ignore-pnpmfile=true run build\n", []string{"pnpm --config.ignore-pnpmfile=true run build"}},
		{"pnpm --ignore-pnpmfile install runs the scripts", "", "      - run: pnpm --ignore-pnpmfile install\n", []string{"pnpm --ignore-pnpmfile install"}},
		{"npm audit fix after an option's value", "", "      - run: npm audit --audit-level high fix\n", []string{"npm audit --audit-level high fix"}},
		{"npm --ignore-scripts false", "", "      - run: npm pack --ignore-scripts false\n", []string{"npm pack --ignore-scripts false"}},
		{"npm --ignore-scripts=false after", "", "      - run: npm publish --ignore-scripts --ignore-scripts=false\n", []string{"npm publish --ignore-scripts --ignore-scripts=false"}},
		{"npm --ignore-scripts false after", "", "      - run: npm publish --ignore-scripts --ignore-scripts false\n", []string{"npm publish --ignore-scripts --ignore-scripts false"}},
		{"npm --no-ignore-scripts after", "", "      - run: npm pack --ignore-scripts --no-ignore-scripts\n", []string{"npm pack --ignore-scripts --no-ignore-scripts"}},
		{"composer no scripts and no plugins", "", "      - run: composer --no-scripts --no-plugins install\n", nil},
		{"composer no plugins and no scripts after", "", "      - run: composer install --no-plugins --no-scripts\n", nil},
		{"composer no scripts alone", "", "      - run: composer --no-scripts test\n", []string{"composer --no-scripts test"}},
		{"composer an alias", "", "      - run: composer --no-scripts --no-plugins i\n", []string{"composer --no-scripts --no-plugins i"}},
		{"composer list", "", "      - run: composer --no-scripts --no-plugins list\n", []string{"composer --no-scripts --no-plugins list"}},
		{"composer run-script", "", "      - run: composer --no-scripts --no-plugins run-script x\n", []string{"composer --no-scripts --no-plugins run-script x"}},
		// the names of pnpm's bin
		{"pnpx", "", "      - run: pnpx foo\n", []string{"pnpx foo"}},
		{"pn", "", "      - run: pn build\n", []string{"pn build"}},
		{"pnx", "", "      - run: pnx foo\n", []string{"pnx foo"}},
		// pytest reads the conftest.py of its test paths, else of its directory
		{"pytest", "", "      - run: pytest\n", []string{"pytest"}},
		{"python -m pytest", "", "      - run: python -m pytest\n", []string{"python -m pytest"}},
		{"pytest a test path of the tree", ", path: pr", "      - run: pytest pr/tests\n", []string{"pytest pr/tests"}},
		{"pytest collects the tree under its directory", ", path: pr", "      - run: pytest\n", []string{"pytest"}},
		{"pytest a value of an option", "", "      - run: pytest --junitxml /tmp/j.xml\n", []string{"pytest --junitxml /tmp/j.xml"}},
		{"pytest in runner.temp", ", path: pr", "      - run: pytest\n        working-directory: ${{ runner.temp }}\n", []string{"pytest"}},
		// any command of pnpm loads the .pnpmfile.cjs of the tree
		{"pnpm build", "", "      - run: pnpm build\n", []string{"pnpm build"}},
		{"pnpm filter and a script", "", "      - run: pnpm --filter web build\n", []string{"pnpm --filter web build"}},
		{"pnpm an expression", "", "      - run: pnpm ${{ matrix.task }}\n", []string{"pnpm ${{ matrix.task }}"}},
		{"pnpm add", "", "      - run: pnpm add x\n", []string{"pnpm add x"}},
		{"pnpm store", "", "      - run: pnpm store prune\n", []string{"pnpm store prune"}},
		{"pnpm version", "", "      - run: pnpm --version\n", []string{"pnpm --version"}},
		// pnpm reads the pnpmfile of the directory it runs in
		{"pnpm -C a directory of the tree", "", "      - run: pnpm -C web install\n", []string{"pnpm -C web install"}},
		{"pnpm --dir= a directory of the tree", "", "      - run: pnpm --dir=web lint\n", []string{"pnpm --dir=web lint"}},
		{"pnpm -C an expression", "", "      - run: pnpm -C ${{ inputs.dir }} install\n", []string{"pnpm -C ${{ inputs.dir }} install"}},
		{"pnpm -C runner.temp", "", "      - run: pnpm -C ${{ runner.temp }}/tool install\n", []string{"pnpm -C ${{ runner.temp }}/tool install"}},
		{"pnpm --dir an absolute path may be the workspace", "", "      - run: pnpm --dir /opt/tool install\n", []string{"pnpm --dir /opt/tool install"}},
		{"pnpm --dir= an absolute path may be the workspace", "", "      - run: pnpm --dir=/opt/tool install\n", []string{"pnpm --dir=/opt/tool install"}},
		{"pnpm -C the parent", "", "      - run: pnpm -C .. install\n", []string{"pnpm -C .. install"}},
		{"pnpm -C runner.temp and the lockfile in the tree", "", "      - run: pnpm -C ${{ runner.temp }}/x --lockfile-dir . install\n", []string{"pnpm -C ${{ runner.temp }}/x --lockfile-dir . install"}},
		{"pnpm -C runner.temp and the lockfile out of the tree", "", "      - run: pnpm -C ${{ runner.temp }}/x --lockfile-dir=${{ runner.temp }}/x install\n", []string{"pnpm -C ${{ runner.temp }}/x --lockfile-dir=${{ runner.temp }}/x install"}},
		{"pnpm the lockfile out of the tree, in the tree", "", "      - run: pnpm --lockfile-dir /opt/x install\n", []string{"pnpm --lockfile-dir /opt/x install"}},
		{"pnpm --dir= runner.temp", "", "      - run: pnpm --dir=${{ runner.temp }}/tool store prune\n", []string{"pnpm --dir=${{ runner.temp }}/tool store prune"}},
		{"pnpm --dir= an expression", "", "      - run: pnpm --dir=${{ inputs.dir }} store prune\n", []string{"pnpm --dir=${{ inputs.dir }} store prune"}},
		{"script of the tree", "", "      - run: ./scripts/build.sh\n", []string{"./scripts/build.sh"}},
		{"bash a file", "", "      - run: bash ci/test.sh\n", []string{"bash ci/test.sh"}},
		{"python a file", "", "      - run: python3 tools/gen.py\n", []string{"python3 tools/gen.py"}},
		{"bash -c is not a file", "", "      - run: bash -c 'echo'\n", nil},
		{"make", "", "      - run: make\n", []string{"make"}},
		{"mvnw", "", "      - run: ./mvnw verify\n", []string{"./mvnw verify"}},
		{"go test", "", "      - run: go test ./...\n", []string{"go test ./..."}},
		{"go build is not", "", "      - run: go build ./...\n", nil},
		{"pip install .", "", "      - run: pip install -e .\n", []string{"pip install -e ."}},
		{"pip install a package", "", "      - run: pip install requests\n", nil},
		{"python -m pip", "", "      - run: python -m pip install -r requirements.txt\n", []string{"python -m pip install -r requirements.txt"}},
		{"npx", "", "      - run: npx markdownlint-cli '**/*.md'\n", []string{"npx markdownlint-cli '**/*.md'"}},
		{"echo only", "", "      - run: echo done\n", nil},
		{"remote action only", "", "      - uses: actions/upload-artifact@v4\n        with: {path: dist}\n", nil},
		{"local action", "", "      - uses: ./.github/actions/build\n", []string{"./.github/actions/build"}},
		{"local action outside path", ", path: pr", "      - uses: ./.github/actions/build\n", nil},
		{"local action under path", ", path: pr", "      - uses: ./pr/.github/actions/build\n", []string{"./pr/.github/actions/build"}},
		{"script outside path", ", path: pr", "      - run: ./build.sh\n", nil},
		{"script under path", ", path: pr", "      - run: ./pr/build.sh\n", []string{"./pr/build.sh"}},
		{"path by an expression", ", path: '${{ inputs.dir }}'", "      - uses: ./.github/actions/build\n", []string{"./.github/actions/build"}},
		{"pwsh", "", "      - run: npm ci\n        shell: pwsh\n", []string{"npm ci"}},
		{"absolute tool", "", "      - run: /usr/bin/npm install\n", []string{"/usr/bin/npm install"}},
		{"tool in a subshell", "", "      - run: (cd web && yarn install)\n", []string{"yarn install"}},
		{"tool in a substitution", "", "      - run: echo \"$(make version)\"\n", []string{"make version"}},
		{"expression kept", "", "      - run: npm run ${{ matrix.task }}\n", []string{"npm run ${{ matrix.task }}"}},
		// past the wrappers, and a script's name alone
		{"sudo a script", "", "      - run: sudo ./build.sh\n", []string{"sudo ./build.sh"}},
		{"sudo a script under path", ", path: pr", "      - run: sudo pr/build.sh\n", []string{"sudo pr/build.sh"}},
		{"a script under path by its path", ", path: pr", "      - run: pr/build.sh\n", []string{"pr/build.sh"}},
		{"sudo bash a script under path", ", path: pr", "      - run: sudo bash pr/build.sh\n", []string{"sudo bash pr/build.sh"}},
		{"env a script", "", "      - run: env X=1 ./x.sh\n", []string{"env X=1 ./x.sh"}},
		{"sudo a tool", "", "      - run: sudo -E npm ci\n", []string{"sudo -E npm ci"}},
		{"bash a name", "", "      - run: bash build.sh\n", []string{"bash build.sh"}},
		{"python a name", "", "      - run: python setup.py install\n", []string{"python setup.py install"}},
		{"bash a name outside path", ", path: pr", "      - run: bash build.sh\n", nil},
		{"python a name with no extension", "", "      - run: python build\n", nil},
		{"sh reads stdin", "", "      - run: curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable.sh\n", nil},
		{"bash reads stdin", "", "      - run: bash - x.sh\n", nil},
		{"php code", "", "      - run: php -r 'x.php'\n", nil},
		{"node prints", "", "      - run: node -p x.js\n", nil},
		{"bash -e runs a file", "", "      - run: bash -e ./build.sh\n", []string{"bash -e ./build.sh"}},
		{"ruby -r runs a file", "", "      - run: ruby -r ./lib.rb x.rb\n", []string{"ruby -r ./lib.rb x.rb"}},
	} {
		with := "{ref: '${{ github.event.pull_request.head.sha }}'" + c.with + "}"
		s := oneSite(t, "pull_request_target", "", "actions/checkout@v4", with, c.after)
		var got []string
		for _, e := range s.CodeRunSteps {
			got = append(got, e.Text)
			if e.Name != "steps[1]" || e.Cite.String() == "" {
				t.Errorf("%s: %+v", c.name, e)
			}
		}
		if !slices.Equal(got, c.runs) {
			t.Errorf("%s: %q; want %q", c.name, got, c.runs)
		}
	}
	// a step before the checkout does not count; a named step is named
	s := oneSite(t, "pull_request_target", "", "actions/checkout@v4", "{ref: '${{ github.event.pull_request.head.sha }}'}", "      - name: Build\n        run: make\n")
	if len(s.CodeRunSteps) != 1 || s.CodeRunSteps[0].Name != "Build" {
		t.Errorf("named: %+v", s.CodeRunSteps)
	}
	w := mustWorkflow(t, "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n      - uses: actions/checkout@v4\n        with: {ref: '${{ github.event.pull_request.head.sha }}'}\n")
	if s := Analyze(w, nil)[0]; len(s.CodeRunSteps) != 0 {
		t.Errorf("before: %+v", s.CodeRunSteps)
	}
}

func TestToolsCited(t *testing.T) {
	for _, tl := range tools {
		if !strings.HasPrefix(tl.cite.String(), "https://") {
			t.Errorf("the tool %s has no citation", tl.names)
		}
	}
	for _, c := range []Cite{treeFile, localAction} {
		if !strings.HasPrefix(c.String(), "https://") {
			t.Errorf("%v", c)
		}
	}
}

// TestCodeRunsRoots: the evidence of a download is read by the same rules
// on the root it puts its files in, and the new reading of runner.temp.
func TestCodeRunsRoots(t *testing.T) {
	for _, c := range []struct {
		name  string
		at    Placement
		after string
		runs  []string
	}{
		{"workspace: a tool", ws("."), "      - run: npm ci\n", []string{"npm ci"}},
		{"under dist: a tool is not", ws("dist"), "      - run: npm ci\n", nil},
		{"under dist: its script", ws("dist"), "      - run: bash dist/x.sh\n", []string{"bash dist/x.sh"}},
		{"runner.temp: $RUNNER_TEMP", rt("artifacts"), "      - run: bash $RUNNER_TEMP/artifacts/x.sh\n", []string{"bash $RUNNER_TEMP/artifacts/x.sh"}},
		{"runner.temp: ${RUNNER_TEMP}", rt("artifacts"), "      - run: \"${RUNNER_TEMP}/artifacts/run\"\n", []string{"${RUNNER_TEMP}/artifacts/run"}},
		{"runner.temp: the expression", rt("artifacts"), "      - run: python ${{ runner.temp }}/artifacts/x.py\n", []string{"python ${{ runner.temp }}/artifacts/x.py"}},
		{"runner.temp: the expression, other case", rt("artifacts"), "      - run: sh ${{RUNNER.TEMP}}/artifacts/x.sh\n", []string{"sh ${{RUNNER.TEMP}}/artifacts/x.sh"}},
		{"runner.temp: another directory", rt("artifacts"), "      - run: bash $RUNNER_TEMP/other/x.sh\n", nil},
		{"runner.temp: a tool is not", rt("artifacts"), "      - run: npm ci\n", nil},
		{"runner.temp: cat is not", rt("artifacts"), "      - run: cat $RUNNER_TEMP/artifacts/x\n", nil},
		{"runner.temp: a checkout after does not clean it", rt(""), "      - uses: actions/checkout@v4\n      - run: bash $RUNNER_TEMP/x.sh\n", []string{"bash $RUNNER_TEMP/x.sh"}},
		{"workspace: a checkout after cleans it", ws("."), "      - uses: actions/checkout@v4\n      - run: npm ci\n", nil},
		// actions/checkout checks out with --force, which puts back the
		// tracked files, whatever clean is
		{"workspace: clean false cleans it too", ws("."), "      - uses: actions/checkout@v4\n        with: {clean: false}\n      - run: npm ci\n", nil},
		{"other variables are not runner.temp", rt(""), "      - run: bash $HOME/x.sh\n", nil},
		// runner.temp is no place of the workspace
		{"workspace: $RUNNER_TEMP is not under it", ws("."), "      - run: bash $RUNNER_TEMP/x.sh\n", nil},
		{"workspace: ${{ runner.temp }} is not under it", ws("."), "      - run: bash ${{ runner.temp }}/x.sh\n", nil},
	} {
		src := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo first\n" + c.after
		w := mustWorkflow(t, src)
		j := w.Jobs.Value.Entries[0].Value.Value
		var got []string
		for _, e := range codeRuns(w, &j, j.Steps.Value.Items, workflow.OrderOf(j.Steps.Value.Items), 0, c.at, nil) {
			got = append(got, e.Text)
		}
		if !slices.Equal(got, c.runs) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.runs)
		}
	}
}

// TestCodeRunsAnyPath: a checkout whose path is not known is still in the
// workspace, so runner.temp is not under it.
func TestCodeRunsAnyPath(t *testing.T) {
	w := mustWorkflow(t, "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo first\n      - run: bash $RUNNER_TEMP/x.sh\n")
	j := w.Jobs.Value.Entries[0].Value.Value
	if got := codeRuns(w, &j, j.Steps.Value.Items, workflow.OrderOf(j.Steps.Value.Items), 0, workspacePlacement(anyDir()), nil); len(got) != 0 {
		t.Errorf("%+v", got)
	}
}

// TestGitRuns: every git a step after the step at after starts, past a
// checkout, which leaves .git; not before it, nor in it.
func TestGitRuns(t *testing.T) {
	w := mustWorkflow(t, `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: git status
      - run: echo agent
      - uses: actions/checkout@v4
      - run: |
          git add .
          /usr/bin/git -c user.name=x commit -m m
          echo git
          sudo git status
          timeout 30 git fetch
      - shell: pwsh
        run: git log
`)
	j := w.Jobs.Value.Entries[0].Value.Value
	var got []string
	for _, r := range GitRuns(w, &j, j.Steps.Value.Items, 1, nil) {
		got = append(got, r.Text)
	}
	want := []string{"git add .", "/usr/bin/git -c user.name=x commit -m m", "sudo git status", "timeout 30 git fetch", "git log"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func ws(rel string) Placement { return workspacePlacement(relDirOf(rel)) }
func rt(rel string) Placement { return runnerTempPlacement(relDirOf(rel)) }

// TestRefusedCheckout: a checkout that fails on its path brings nothing
// to run or to save, and takes nothing away as a later checkout.
func TestRefusedCheckout(t *testing.T) {
	s := oneSite(t, "pull_request_target", "", "actions/checkout@v4.2.2", "{ref: '${{ github.event.pull_request.head.sha }}', path: '${{ runner.temp }}/pr'}", "      - run: npm ci\n      - uses: actions/cache@v4\n        with: {path: ., key: k}\n")
	if s.Placed || len(s.CodeRunSteps) != 0 || len(s.CacheSaves) != 0 {
		t.Errorf("refused: placed %v, runs %+v, saves %+v", s.Placed, s.CodeRunSteps, s.CacheSaves)
	}
	for _, c := range []struct{ name, after string }{
		{"a later refused checkout does not clean", "      - uses: actions/checkout@v4\n        with: {path: '${{ runner.temp }}/x'}\n      - run: npm ci\n"},
		{"a later v1 of another repository does not clean", "      - uses: actions/checkout@v1\n        with: {repository: other/tools, path: tools}\n      - run: npm ci\n"},
		// v1 moves github.workspace: the rule does not read it as a clean
		{"a later v1 does not clean", "      - uses: actions/checkout@v1\n      - run: npm ci\n"},
	} {
		src := "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4.2.2\n        with: {ref: '${{ github.event.pull_request.head.sha }}'}\n" + c.after
		s := Analyze(mustWorkflow(t, src), nil)[0]
		if len(s.CodeRunSteps) != 1 || s.CodeRunSteps[0].Text != "npm ci" {
			t.Errorf("%s: %+v", c.name, s.CodeRunSteps)
		}
	}
}

// TestCodeRunsAsynchronous: a command that the script runs ended by & is a
// code run as any other, marked Asynchronous, as the exit code of the step
// does not wait for the command.
func TestCodeRunsAsynchronous(t *testing.T) {
	for _, c := range []struct {
		name, after string
		async       []bool
	}{
		{"in the shell", "      - run: ./build.sh\n", []bool{false}},
		{"ended by &", "      - run: ./build.sh &\n", []bool{true}},
		{"in a subshell ended by &", "      - run: (cd web && yarn install) &\n", []bool{true}},
		{"one of two", "      - run: |\n          ./build.sh &\n          make\n", []bool{true, false}},
		{"pwsh", "      - run: npm ci\n        shell: pwsh\n", []bool{false}},
	} {
		s := oneSite(t, "pull_request_target", "", "actions/checkout@v4", "{ref: '${{ github.event.pull_request.head.sha }}'}", c.after)
		var got []bool
		for _, e := range s.CodeRunSteps {
			got = append(got, e.Asynchronous)
		}
		if !slices.Equal(got, c.async) {
			t.Errorf("%s: %v, want %v", c.name, got, c.async)
		}
	}
}
