package prcode

import (
	"github.com/gh-intel/sisakulint/actions/calls"
	"path"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// tool is a command that reads the files of the directories it reads and
// runs code of them: a script, a build, a test. names are its names (its
// bin's aliases among them). Its command is the first word after the name
// that is not an option (nor the value of an option of dirOptions or
// readOptions), or, with commands (every name and alias name of its
// commands), the first such word that is one of them. subs, when there,
// are the commands that run code: a word, or a word and a word that
// follows it ("audit fix"; "version *": any word that is not an option);
// none: any. needs, when there, are words one of
// which must follow (pip installs the tree only when named so). dirOptions
// are the options whose value is the directory the tool runs in instead
// of the shell's, and readOptions those whose value is a directory or a
// file it reads code of too; collects, that it reads the directories under
// the one it runs in and under the paths its words name too (pytest's
// collection of tests). stops are the settings that stop the code of the
// tree it runs.
type tool struct {
	names       []string
	commands    []string
	subs        []string
	needs       []string
	cite        Cite
	dirOptions  []string
	readOptions []string
	collects    bool
	stops       []stop
}

// stop is a setting that stops the code of the tree a tool runs: each of
// options is one setting by its spellings, and every one of them is
// given; commands are the commands it stops (none: every command);
// undoable, that a word after it can undo it (npm's --ignore-scripts
// false), which an agent with a * may add.
type stop struct {
	options  [][]string
	commands []string
	undoable bool
}

// stopped is whether a stop of t holds for words, whose command is cmd
// (ok: there is one): a spelling is given when no false follows it and no
// --no-<name>, --<name>=false or <spelling> false comes after it.
func (t tool) stopped(words []runWord, cmd string, ok, open bool) bool {
	given := func(spellings []string) bool {
		last := -1
		for i, w := range words {
			for _, s := range spellings {
				name, _, _ := strings.Cut(strings.TrimPrefix(s, "--"), "=")
				switch {
				case w.lookup == s && i+1 < len(words) && words[i+1].lookup == "false",
					w.lookup == "--no-"+name, w.lookup == "--"+name+"=false":
					last = -1
				case w.lookup == s:
					last = i
				}
			}
		}
		return last >= 0
	}
	return slices.ContainsFunc(t.stops, func(s stop) bool {
		return !(open && s.undoable) && !slices.ContainsFunc(s.options, func(o []string) bool { return !given(o) }) &&
			(len(s.commands) == 0 || ok && slices.Contains(s.commands, cmd))
	})
}

// command is the command of t in words, the words after it, and whether
// there is one.
func (t tool) command(words []runWord) (string, []runWord, bool) {
	skip := false
	for i, w := range words {
		switch {
		case skip:
			skip = false
		case strings.HasPrefix(w.lookup, "-"):
			skip = slices.Contains(t.dirOptions, w.lookup) || slices.Contains(t.readOptions, w.lookup)
		case len(t.commands) == 0 || slices.Contains(t.commands, w.lookup):
			return w.lookup, words[i+1:], true
		}
	}
	return "", nil, false
}

// runs is whether the command cmd of t, followed by rest, runs code; with
// open, words may be added after rest.
func (t tool) runs(cmd string, rest []runWord, open bool) bool {
	if len(t.subs) == 0 {
		return true
	}
	// the words that are not options, nor the values of options of
	// dirOptions or readOptions, as command reads them
	var operands []string
	skip := false
	for _, w := range rest {
		switch {
		case skip:
			skip = false
		case strings.HasPrefix(w.lookup, "-"):
			skip = slices.Contains(t.dirOptions, w.lookup) || slices.Contains(t.readOptions, w.lookup)
		default:
			operands = append(operands, w.lookup)
		}
	}
	return slices.ContainsFunc(t.subs, func(s string) bool {
		first, second, two := strings.Cut(s, " ")
		return first == cmd && (!two || open || slices.ContainsFunc(operands, func(o string) bool { return o == second || second == "*" }))
	})
}

// runsCode is whether t, given words, run in cwd, runs code of the tree at
// at. With open, words may be added after them (an agent's permission with
// a *): t may then be given a command, a word of needs, an option that
// changes its directory or one that undoes a stop.
func (t tool) runsCode(words []runWord, cwd runWord, at Placement, open bool) bool {
	if !open && !t.readsTree(words, cwd, at) {
		return false
	}
	cmd, after, ok := t.command(words)
	if len(t.subs) > 0 && (ok && !t.runs(cmd, after, open) || !ok && !open) {
		return false
	}
	if t.stopped(words, cmd, ok, open) {
		return false
	}
	if open {
		return true
	}
	return len(t.needs) == 0 || slices.ContainsFunc(words, func(w runWord) bool {
		return slices.Contains(t.needs, w.lookup) || strings.HasPrefix(w.lookup, "./")
	})
}

func cite(u string) Cite {
	if !strings.HasPrefix(u, "https://") {
		panic("a Cite is an https URL: " + u)
	}
	return Cite{u}
}

var (
	npmScripts = cite("https://github.com/npm/cli/blob/0c3b82a9a612c3f9399d35c28c86708b1f8ea7d4/docs/lib/content/using-npm/scripts.md")
	npmExec    = cite("https://github.com/npm/cli/blob/0c3b82a9a612c3f9399d35c28c86708b1f8ea7d4/docs/lib/content/commands/npm-exec.md")
	pipRuns    = cite("https://github.com/pypa/pip/blob/a7002c9771a6c3f0317a4e6b9fbdcd22e643f7b6/docs/html/topics/secure-installs.md")
	goDoc      = cite("https://github.com/golang/go/blob/go1.27.1/src/cmd/go/alldocs.go")

	// treeFile: a program of the tree run by its path; localAction: an
	// action of the tree (GHSL-2021-033: "The action.yml file from the root
	// directory is attacker controlled").
	treeFile    = cite("https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target")
	localAction = cite("https://securitylab.github.com/advisories/GHSL-2021-033-game-ci-workflows/")
)

var pipInstall = []string{".", "-e", "--editable", "-r", "--requirement"}

// npmCommands are the names and the alias names of npm's commands
// (commands and aliases of lib/utils/cmd-list.js of the same commit as
// npmScripts).
var npmCommands = []string{
	"access", "approve-scripts", "audit", "bugs", "cache", "ci", "completion", "config", "dedupe", "deny-scripts",
	"deprecate", "diff", "dist-tag", "docs", "doctor", "edit", "exec", "explain", "explore", "find-dupes", "fund",
	"get", "help", "help-search", "init", "install", "install-ci-test", "install-scripts", "install-test", "link",
	"ll", "login", "logout", "ls", "org", "outdated", "owner", "pack", "patch", "ping", "pkg", "prefix", "profile",
	"prune", "publish", "query", "rebuild", "repo", "restart", "root", "run", "sbom", "search", "set", "stage",
	"start", "stop", "team", "test", "token", "trust", "undeprecate", "uninstall", "unpublish", "update",
	"version", "view", "whoami",
	"author", "home", "issues", "info", "show", "find", "add", "unlink", "remove", "rm", "r", "un", "rb", "list",
	"ln", "create", "i", "it", "cit", "u", "up", "c", "s", "se", "tst", "t", "ddp", "v", "run-script",
	"clean-install", "clean-install-test", "x", "why", "la", "verison", "ic", "innit", "in", "ins", "inst",
	"insta", "instal", "isnt", "isnta", "isntal", "isntall", "install-clean", "isntall-clean", "hlep",
	"dist-tags", "upgrade", "udpate", "rum", "sit", "urn", "ogr",
}

var tools = []tool{
	// the commands that run a script of the tree (runScript, libnpmpack,
	// libnpmversion, pacote's DirFetcher) or reify it (arborist, which runs
	// the scripts of the workspaces the tree's package.json names), and
	// their aliases; npm runs no script by its name alone, and its
	// abbreviations are not read
	{names: []string{"npm"}, cite: npmScripts, commands: npmCommands, subs: []string{
		"install", "i", "add", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall",
		"ci", "clean-install", "ic", "install-clean", "isntall-clean", "install-test", "it",
		"install-ci-test", "cit", "clean-install-test", "sit", "run", "run-script", "rum", "urn",
		"test", "t", "tst", "start", "stop", "restart", "exec", "x", "rebuild", "rb", "explore *", "edit *",
		// with no operand, version lists the version, and explore, edit and
		// uninstall (but with -g) stop with an error (version.js, explore.js,
		// edit.js, uninstall.js)
		"publish", "pack", "version *", "verison *", "diff", "uninstall *", "unlink *", "remove *", "rm *", "r *", "un *",
		"update", "u", "up", "upgrade", "udpate", "link", "ln", "patch", "dedupe", "ddp", "prune",
		"audit fix", "stage publish"},
		// prefix of workspaces/config/lib/definitions/definitions.js, short C
		dirOptions: []string{"--prefix", "-C"},
		// these pack the directory and call no git (publish.js, libnpmpack,
		// pacote's dir.js stop at ignoreScripts); the others may call the
		// git of the tree's .npmrc
		stops: []stop{{options: [][]string{{"--ignore-scripts", "--ignore-scripts=true"}}, commands: []string{"publish", "pack", "diff"}, undoable: true}}},
	{names: []string{"npx"}, cite: npmExec},
	{names: []string{"yarn"}, cite: cite("https://github.com/yarnpkg/berry/blob/e4e423a1eb117b5129f20ac626a03eb7a97aedff/packages/docusaurus/docs/advanced/02-package-management/lifecycle-scripts.mdx")},
	// every command of pnpm loads the .pnpmfile.cjs (or .mjs) of the
	// directory it runs in or of its lockfile's, which the tree has, unless
	// --ignore-pnpmfile: pnpm 11.28.13 for each command (main.ts calls
	// installConfigDepsAndLoadHooks of getConfig.ts, which calls
	// loadPnpmfileHooks); pnpm 10.34.9 by getConfig too, but for the
	// commands it passes to npm, and for those too when packageManager names
	// pnpm 11 or later
	// pn, pnpx and pnx are its bin's (pnpm11/pnpm/package.json); pnpx and
	// pnx run pnpm dlx
	{names: []string{"pnpm", "pn", "pnpx", "pnx"}, cite: cite("https://github.com/pnpm/pnpm/blob/eb0fda4ee3891f9c10e8bad83d1c3c5af343591f/pnpm11/pnpm/src/getConfig.ts"),
		// dir of pnpm11/config/reader/src/types.ts, -C of shorthands.ts; the
		// pnpmfile is of lockfileDir, else of dir (getConfig.ts)
		dirOptions: []string{"--dir", "-C"}, readOptions: []string{"--lockfile-dir"}},
	{names: []string{"pip"}, subs: []string{"install"}, needs: pipInstall, cite: pipRuns},
	{names: []string{"pip3"}, subs: []string{"install"}, needs: pipInstall, cite: pipRuns},
	// -C dir, --directory=dir: "Change to directory dir before reading the
	// makefiles"
	{names: []string{"make"}, cite: cite("https://www.gnu.org/software/make/manual/make.html"), dirOptions: []string{"-C", "--directory"}},
	// -C dir: "Change to dir before running the command"
	{names: []string{"go"}, subs: []string{"test", "run", "generate"}, cite: goDoc, dirOptions: []string{"-C"}},
	// --manifest-path: "Path to the Cargo.toml file" (cargo-build.txt of
	// the same tag)
	{names: []string{"cargo"}, subs: []string{"build", "test", "run", "bench", "check", "install"}, cite: cite("https://github.com/rust-lang/cargo/blob/0.99.0/src/doc/src/reference/build-scripts.md"),
		readOptions: []string{"--manifest-path"}},
	// -f, --file: "Force the use of an alternate POM file (or directory with
	// pom.xml)" (https://github.com/apache/maven/blob/5223074e77771a93a3670af95f2155fbde6f38f3/compat/maven-embedder/src/main/java/org/apache/maven/cli/CLIManager.java)
	{names: []string{"mvn"}, cite: cite("https://github.com/apache/maven-site/blob/75816eac1598f0d0b58e09da9b881f7b657df29c/content/markdown/guides/introduction/introduction-to-the-lifecycle.md"),
		readOptions: []string{"-f", "--file"}},
	// -p, --project-dir: "Specifies the start directory for Gradle"
	// (command_line_interface.adoc of the same tag)
	{names: []string{"gradle"}, cite: cite("https://github.com/gradle/gradle/blob/v9.8.0/platforms/documentation/docs/src/docs/userguide/reference/runtime-configuration/build_lifecycle.adoc"),
		dirOptions: []string{"-p", "--project-dir"}},
	{names: []string{"bundle"}, subs: []string{"install", "exec"}, cite: cite("https://github.com/rubygems/rubygems/blob/8e5c0371e619f1a7abc996c661fba0c6b60622dd/lib/bundler/man/gemfile.5.ronn")},
	{names: []string{"rake"}, cite: cite("https://github.com/ruby/rake/blob/e5be0795721804e5e26a820b70049b41e7ad863f/README.rdoc")},
	// every command of composer runs the pre-command-run script of the
	// tree's composer.json (BaseCommand.php of 2.10.3), and a word that is no
	// command of composer a script of it as a command (scripts.md)
	{names: []string{"composer"}, cite: cite("https://github.com/composer/composer/blob/2.10.3/doc/articles/scripts.md"),
		dirOptions: []string{"--working-dir", "-d"},
		// with both, a command by its full name runs no script and loads no
		// plugin (getDefaultCommands of Application.php, but run-script and
		// exec, which runs the bin-dir of the tree's composer.json); an
		// alias, an abbreviation, list and help load the tree's autoloader;
		// composer reads them by their presence (hasParameterOption), and no
		// word undoes them
		stops: []stop{{options: [][]string{{"--no-scripts"}, {"--no-plugins"}}, commands: []string{
			"about", "archive", "audit", "bump", "check-platform-reqs", "clear-cache", "config", "create-project",
			"depends", "diagnose", "dump-autoload", "fund", "global", "browse", "init", "install", "licenses",
			"outdated", "policy", "prohibits", "reinstall", "remove", "repository", "require", "search",
			"self-update", "show", "status", "suggests", "update", "validate"}}}},
	{names: []string{"dotnet"}, subs: []string{"build", "test", "run"}, cite: cite("https://github.com/MicrosoftDocs/visualstudio-docs/blob/083bf98e2f8590b1796f2c7411363050956fad8e/docs/msbuild/exec-task.md")},
	// pytest collects the tests, and loads the conftest.py, of its test
	// paths, else of its directory, and under them
	{names: []string{"pytest"}, collects: true, cite: cite("https://github.com/pytest-dev/pytest/blob/9efd0121a4396da80c20d7c3b7844825966612f6/doc/en/how-to/writing_plugins.rst")},
}

// interpreters run a file named as their first word that is not an option:
// a path with a /, or a name with the extension of a script (scriptExts).
var interpreters = []string{"bash", "sh", "zsh", "dash", "python", "python3", "node", "ruby", "perl", "php"}

// evidence finds the steps after s in steps (its job's, or its action's)
// that run what it brings, and those of caches (cacheSteps of steps) that
// save it to the cache.
func (s *CheckoutSite) evidence(w *workflow.Workflow, steps []workflow.Step, order workflow.StepOrder, caches jobCaches, m *shell.Memo) {
	s.Placement, s.Placed = CheckoutPlacement(s.Job, steps, order, s.Step.Order)
	if !s.Placed {
		return // the checkout fails before it puts the tree
	}
	s.CodeRunSteps = codeRuns(w, s.Job, steps, order, s.Step.Order, s.Placement, m)
	s.CacheSaves, s.Unanswered = cacheSaves(s.Job, steps, order, caches, s.Step.Order, s.Placement.dir)
}

// codeRuns are the steps of steps that run what the step at after puts
// at at: an action of it, a program of it by its path, or a tool of the
// table when at is the workspace itself. The steps read are those that may
// run after the step at after has started, the steps of a parallel group
// and background steps among them (workflow.StepOrder). A checkout of root
// or of a directory above it takes away what is there (it cleans by
// default): the steps that start after it is done are not read, when it
// is done after the step at after; runner.temp is no checkout's.
func codeRuns(w *workflow.Workflow, job *workflow.Job, steps []workflow.Step, order workflow.StepOrder, after int, at Placement, m *shell.Memo) []CodeRunStep {
	var out []CodeRunStep
	var cleans []int // the checkouts of at done after the step at after is done
	read := func(x *workflow.Step) {
		if x.Uses.Status == workflow.Present && calls.IsCheckout(x.Uses.Value) {
			if at.InWorkspace() && checkoutCleans(job, steps, order, x.Order, at.dir) && order.DoneBefore(after, x.Order) {
				cleans = append(cleans, x.Order)
			}
			return
		}
		name := StepName(*x)
		switch {
		case x.Uses.Status == workflow.Present && x.Uses.Value.Kind == workflow.UsesLocal:
			if at.InWorkspace() && at.dir.holds(x.Uses.Value.Path.Text) {
				out = append(out, CodeRunStep{Step: *x, Name: name, Text: x.Uses.Value.Text(), Cite: localAction})
			}
		case x.Run.Status == workflow.Present:
			for _, e := range runs(w, job, *x, at, m) {
				e.Step, e.Name = *x, name
				out = append(out, e)
			}
		}
	}
	for _, k := range order.RunningAt(after) {
		read(&steps[k])
	}
	for k := after + 1; k < len(steps); k++ {
		// a step a checkout of root cleans for is done, and so is every
		// step after it (DoneBefore holds from some step on)
		if slices.ContainsFunc(cleans, func(c int) bool { return order.DoneBefore(c, k) }) {
			break
		}
		read(&steps[k])
	}
	return out
}

// WorkspaceRuns are the steps of steps that run what the step at after
// leaves at root, as for a checkout's tree (codeRuns).
func WorkspaceRuns(w *workflow.Workflow, job *workflow.Job, steps []workflow.Step, after int, root string, anyPath bool, m *shell.Memo) []CodeRunStep {
	d := relDirOf(root)
	if anyPath {
		d = anyDir()
	}
	return codeRuns(w, job, steps, workflow.OrderOf(steps), after, workspacePlacement(d), m)
}

// checkoutCleans is whether the checkout at k of steps takes away what is
// in the directory d of the workspace: it puts its tree (CheckoutPlacement)
// in d or above it, and it is not v1, which moves github.workspace.
func checkoutCleans(j *workflow.Job, steps []workflow.Step, order workflow.StepOrder, k int, d relDir) bool {
	p, placed := CheckoutPlacement(j, steps, order, k)
	return placed && !mayBeV1(steps[k].Uses.Value) && cleansDir(p.dir, d)
}

// cleansDir is whether a checkout into c takes away what is in d: c is
// known, and d is c or under it (a d not known: when c is the workspace).
func cleansDir(c, d relDir) bool {
	if !c.known {
		return false
	}
	if !d.known {
		return c.path == "."
	}
	return under(d.path, c.path)
}

// gitCite is what says git runs code of .git: its hooks and its config
// (core.hooksPath, core.fsmonitor), whatever the subcommand.
var gitCite = cite("https://github.com/git/git/blob/c44beea485f0f2feaf460e2ac87fdd5608d63cf0/Documentation/config/core.adoc")

// GitRuns are the simple commands named git in the runs of the steps that
// may run after the step at after has started, or beside it. A checkout
// does not stop them: it leaves .git (actions/checkout's
// git-directory-helper.ts). A run of bash or sh (or a shell not known) is
// read by its tree, past the wrappers of the table of commands; another's
// lines by their first words. git that bash -c, a function or gh starts is
// not read.
func GitRuns(w *workflow.Workflow, job *workflow.Job, steps []workflow.Step, after int, m *shell.Memo) []CodeRunStep {
	order := workflow.OrderOf(steps)
	var out []CodeRunStep
	for k := range steps {
		x := steps[k]
		if k == after || !order.MayRunAfter(after, k) || x.Run.Status != workflow.Present {
			continue
		}
		text := x.Run.Value.Text()
		masked := taint.Masked(x.Run.Value)
		add := func(first string, sp shell.Span) {
			if path.Base(first) == "git" {
				out = append(out, CodeRunStep{Step: x, Name: StepName(x), Text: strings.TrimSpace(text[sp.Start:sp.End]), Span: sp, Cite: gitCite})
			}
		}
		switch taint.ShellOf(w, job, x) {
		case taint.ShellBash, taint.ShellSh, taint.ShellUnknown:
			sc := taint.ReadScript(m, x.Run.Value).Script
			shell.WalkSimple(sc.List, func(c *shell.Simple) {
				if len(c.Words) == 0 {
					return
				}
				// past the wrappers of the table of commands (sudo,
				// env, timeout, xargs): the command they run
				if m := shell.LookupCommand(shell.WordsOf(masked, c)); m.Entry != nil && slices.Contains(m.Entry.Names, "git") {
					add("git", shell.Span{Start: c.Words[0].Span.Start, End: c.Words[len(c.Words)-1].Span.End})
				}
			})
		default:
			start := 0
			for _, line := range strings.SplitAfter(masked, "\n") {
				if f := strings.Fields(line); len(f) > 0 {
					add(f[0], shell.Span{Start: start, End: start + len(strings.TrimRight(line, "\n"))})
				}
				start += len(line)
			}
		}
	}
	return out
}

// under is whether the relative path p is in the directory root of the
// workspace.
func under(p, root string) bool {
	p = path.Clean(p)
	return root == "." || p == root || strings.HasPrefix(p, root+"/")
}

// StepName is the name of the step x, else where it is (steps[<n>]).
func StepName(x workflow.Step) string {
	if x.Name.Status == workflow.Present && x.Name.Value.Text() != "" {
		return x.Name.Value.Text()
	}
	return x.Place.String()
}

// runs are the commands of the run of x that run the tree at at. A run of
// bash or sh (or a shell not known) is read by its tree; another's lines
// by their first words.
func runs(w *workflow.Workflow, job *workflow.Job, x workflow.Step, at Placement, m *shell.Memo) []CodeRunStep {
	text := x.Run.Value.Text()
	masked := taint.Masked(x.Run.Value)
	cwd := stepCwd(w, job, x)
	var out []CodeRunStep
	add := func(words []runWord, sp shell.Span, async bool) bool {
		if c, ok := runsTree(words, cwd, at); ok {
			out = append(out, CodeRunStep{Text: strings.TrimSpace(text[sp.Start:sp.End]), Span: sp, Cite: c, Asynchronous: async})
			return true
		}
		return false
	}
	switch taint.ShellOf(w, job, x) {
	case taint.ShellBash, taint.ShellSh, taint.ShellUnknown:
		sc := taint.ReadScript(m, x.Run.Value).Script
		// the directory a cd, pushd or popd changes to is not read: the
		// tools of the step may run anywhere
		shell.WalkSimple(sc.List, func(c *shell.Simple) {
			if changesDirectoryWords(shell.WordsOf(masked, c)) {
				cwd = anywhereWord
			}
		})
		shell.Walk("", sc.List, shell.Enclosing{}, shell.Visitor{Command: func(cmd shell.Command, in shell.Enclosing) bool {
			c, ok := cmd.(*shell.Simple)
			if !ok {
				return true
			}
			async := asynchronous(in.Env)
			var words []runWord
			for _, wd := range c.Words {
				words = append(words, wordOf(x.Run.Value, masked, wd, job == nil))
			}
			sp := c.Span()
			if len(c.Words) > 0 {
				sp.Start = c.Words[0].Span.Start
				sp.End = c.Words[len(c.Words)-1].Span.End
			}
			if !add(words, sp, async) {
				// past the wrappers of the table of commands (sudo, env,
				// timeout): the command they run
				if m := shell.LookupCommand(commandWords(words)); len(m.Wrappers) > 0 && m.Command > 0 {
					add(words[m.Command:], sp, async)
				}
			}
			return true
		}})
	default:
		// a word of any statement, in a block too, but not of a comment
		if slices.ContainsFunc(strings.FieldsFunc(pwshCode(masked), func(r rune) bool { return strings.ContainsRune(" \t\n;{}()|&", r) }), func(f string) bool {
			return changesDirectory(f, true)
		}) {
			cwd = anywhereWord
		}
		start := 0
		for _, line := range strings.SplitAfter(masked, "\n") {
			sp := shell.Span{Start: start, End: start + len(strings.TrimRight(line, "\n"))}
			for _, st := range pwshStatements(masked, sp) {
				add(pwshWords(x.Run.Value, masked, st, job == nil), sp, false)
			}
			start += len(line)
		}
	}
	return out
}

// pwshCode is the script s of pwsh without its lines that are comments
// (their first character that is not a blank is #): a # within a line may
// be a letter of a word, which goes on to a character that starts a new
// token (ScanGenericToken of
// https://github.com/PowerShell/PowerShell/blob/ba2221aed027041b6620c5fe1c0675567f14452a/src/System.Management.Automation/engine/parser/tokenizer.cs).
func pwshCode(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimLeft(l, " \t"), "#") {
			lines[i] = ""
		}
	}
	return strings.Join(lines, "\n")
}

// commandWords are words, as runsTree reads them, for LookupCommand: a
// word with an expansion that is not read is not known.
func commandWords(words []runWord) []shell.CommandWord {
	out := make([]shell.CommandWord, len(words))
	for i, w := range words {
		out[i] = shell.CommandWord{Text: w.lookup, Known: w.known}
	}
	return out
}

// scriptExts are the extensions of the scripts the interpreters run: a
// word with no / and one of them is a file of the working directory.
var scriptExts = []string{".sh", ".bash", ".py", ".js", ".mjs", ".cjs", ".rb", ".pl", ".php"}

// codeOptions are, of each interpreter, the options after which it runs
// no file of its arguments: the code is an argument (-c of the shells and
// python, -e of node, ruby and perl, -r of php, -p of node), a module (-m
// of python), or what stdin reads (-s and - of the shells, - of the
// others). bash runs a file "when ... neither the -c nor -s option is
// supplied" (https://git.savannah.gnu.org/cgit/bash.git/plain/doc/bashref.texi?h=bash-5.2).
var codeOptions = map[string][]string{
	"bash": {"-c", "-s", "-"}, "sh": {"-c", "-s", "-"}, "zsh": {"-c", "-s", "-"}, "dash": {"-c", "-s", "-"},
	"python": {"-c", "-m", "-"}, "python3": {"-c", "-m", "-"},
	"node": {"-e", "--eval", "-p", "--print", "-"},
	"ruby": {"-e", "-"}, "perl": {"-e", "-E", "-"}, "php": {"-r", "-"},
}

// runsTree is whether the command of words, run in the directory cwd,
// runs the tree at at, and what says so: a tool reads the directories it
// runs in and reads code of (readOptions), and a relative path is from
// the shell's directory, read from the workspace's root and from cwd
// (froms).
func runsTree(words []runWord, cwd runWord, at Placement) (Cite, bool) {
	if len(words) == 0 {
		return Cite{}, false
	}
	isPath := func(w runWord) bool {
		return w.isPath() && slices.ContainsFunc(froms(cwd), func(from runWord) bool { return from.join(w).mayBeUnder(at) })
	}
	cmd := words[0]
	if !cmd.known {
		return Cite{}, false
	}
	// a name with a / is a path the shell runs, not a command it looks up
	// in PATH; an absolute one is not of the tree (/usr/bin/npm is npm)
	if cmd.isPath() && !strings.HasPrefix(cmd.lookup, "/") {
		if isPath(cmd) {
			return treeFile, true
		}
		return Cite{}, false
	}
	name := path.Base(cmd.lookup)
	if slices.Contains(interpreters, name) {
		// python -m runs a module: a tool of the table by its name
		if (name == "python" || name == "python3") && len(words) >= 3 && words[1].lookup == "-m" && slices.ContainsFunc(tools, func(t tool) bool { return slices.Contains(t.names, words[2].lookup) }) {
			return runsTree(append([]runWord{literalWord(words[2].lookup)}, words[3:]...), cwd, at)
		}
		for _, w := range words[1:] {
			switch {
			case slices.Contains(codeOptions[name], w.lookup):
				return Cite{}, false
			case strings.HasPrefix(w.lookup, "-"):
				continue
			}
			if !strings.Contains(w.lookup, "/") && slices.Contains(scriptExts, path.Ext(w.lookup)) {
				// bash "first searches for the file in the current
				// directory" (bashref.texi of bash-5.2, Shell Scripts), and
				// the others open it there
				w = w.inWorkingDir()
			}
			if isPath(w) {
				return treeFile, true
			}
			return Cite{}, false
		}
		return Cite{}, false
	}
	for _, t := range tools {
		if !slices.Contains(t.names, name) {
			continue
		}
		if !t.runsCode(words[1:], cwd, at, false) {
			return Cite{}, false
		}
		return t.cite, true
	}
	return Cite{}, false
}

// dirOf is the directory that an option of options in words gives the
// tool, the last one: the next word, or the word after = (of a word of
// pwsh, which has none: any directory), as written; readsTree reads it from
// the shell's directory (join). The tool reads the directory of the shell
// otherwise.
func dirOf(words []runWord, options []string) (runWord, bool) {
	var d runWord
	found := false
	for i, w := range words {
		for _, o := range options {
			switch {
			case w.lookup == o && i+1 < len(words):
				d, found = words[i+1], true
			case strings.HasPrefix(w.lookup, o+"="):
				d, found = runWord{base: wordAnywhere, known: true, open: true}, true
				// the = of afterEq is the one after the option
				if w.afterEq != nil && len(w.lookup)-len(w.afterEq.lookup) == len(o)+1 {
					d = *w.afterEq
				}
			}
		}
	}
	return d, found
}

// readsTree is whether t, given words, reads a directory that may be in
// the tree at at: the directory it runs in (the shell's, and the value of
// dirOptions from it), a directory or a file of readOptions, and for
// collects the paths its words name and what is under them all, from
// either directory of froms.
func (t tool) readsTree(words []runWord, cwd runWord, at Placement) bool {
	d := literalWord(".")
	if v, ok := dirOf(words, t.dirOptions); ok {
		d = v
	}
	var reads []runWord
	for _, from := range froms(cwd) {
		// the value of dirOptions adds a directory, as cwd does
		reads = append(reads, from, from.join(d))
		if l, ok := dirOf(words, t.readOptions); ok {
			reads = append(reads, from.join(l))
		}
		if t.collects {
			// the words that are not options, the values of options among
			// them, as paths: a value read as a path is a path read more
			for _, w := range words {
				if !strings.HasPrefix(w.lookup, "-") {
					reads = append(reads, from.join(w))
				}
			}
		}
	}
	return slices.ContainsFunc(reads, func(r runWord) bool { return r.mayBeUnder(at) || t.collects && r.mayHold(at) })
}

// froms are the directories a relative path of a step whose shell starts
// in cwd is read from: the workspace's root, and cwd. cwd adds where a tool
// may read the tree and takes none away: a tool out of the tree may still
// read it by a way the table does not read (an option, a variable, a file
// of configuration).
func froms(cwd runWord) []runWord {
	root := literalWord(".")
	if cwd == root {
		return []runWord{root}
	}
	return []runWord{root, cwd}
}

// isRunnerTemp is whether the ${{ }} p is runner.temp alone, in any case.
func isRunnerTemp(p workflow.Part) bool {
	if p.Tree == nil {
		return false
	}
	path, ok := expr.AccessPath(p.Tree)
	return ok && len(path) == 2 && expr.EqualName(path[0].Name, "runner") && expr.EqualName(path[1].Name, "temp")
}

// asynchronous is whether the execution environment env is, or is in, a
// list ended by &.
func asynchronous(env *shell.ExecutionEnvironment) bool {
	for e := env; e != nil; e = e.Parent {
		if e.Kind == shell.ExecutionEnvironmentAsynchronous {
			return true
		}
	}
	return false
}
