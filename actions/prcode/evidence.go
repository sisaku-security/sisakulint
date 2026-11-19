package prcode

import (
	"github.com/sisaku-security/sisakulint/actions/calls"
	"path"
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/shell"
	"github.com/sisaku-security/sisakulint/actions/taint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// tool is a command that reads the files of the working directory and runs
// code of them: a script, a build, a test. subs, when there,
// are the first words after the name (options skipped) that do; none: any.
// needs, when there, are words one of which must follow (pip installs the
// tree only when named so).
type tool struct {
	name  string
	subs  []string
	needs []string
	cite  Cite
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

var tools = []tool{
	{name: "npm", subs: []string{"install", "i", "ci", "run", "run-script", "test", "t", "start", "exec", "x", "rebuild"}, cite: npmScripts},
	{name: "npx", cite: npmExec},
	{name: "yarn", cite: cite("https://github.com/yarnpkg/berry/blob/e4e423a1eb117b5129f20ac626a03eb7a97aedff/packages/docusaurus/docs/advanced/02-package-management/lifecycle-scripts.mdx")},
	{name: "pnpm", subs: []string{"install", "i", "run", "test", "t", "start", "exec", "rebuild"}, cite: cite("https://github.com/pnpm/pnpm.io/blob/6e1a8ae8dc4703b535f5b3dd00f74f243f91f757/docs/cli/install.md")},
	{name: "pip", subs: []string{"install"}, needs: pipInstall, cite: pipRuns},
	{name: "pip3", subs: []string{"install"}, needs: pipInstall, cite: pipRuns},
	{name: "make", cite: cite("https://www.gnu.org/software/make/manual/make.html")},
	{name: "go", subs: []string{"test", "run", "generate"}, cite: goDoc},
	{name: "cargo", subs: []string{"build", "test", "run", "bench", "check", "install"}, cite: cite("https://github.com/rust-lang/cargo/blob/0.99.0/src/doc/src/reference/build-scripts.md")},
	{name: "mvn", cite: cite("https://github.com/apache/maven-site/blob/75816eac1598f0d0b58e09da9b881f7b657df29c/content/markdown/guides/introduction/introduction-to-the-lifecycle.md")},
	{name: "gradle", cite: cite("https://github.com/gradle/gradle/blob/v9.8.0/platforms/documentation/docs/src/docs/userguide/reference/runtime-configuration/build_lifecycle.adoc")},
	{name: "bundle", subs: []string{"install", "exec"}, cite: cite("https://github.com/rubygems/rubygems/blob/8e5c0371e619f1a7abc996c661fba0c6b60622dd/lib/bundler/man/gemfile.5.ronn")},
	{name: "rake", cite: cite("https://github.com/ruby/rake/blob/e5be0795721804e5e26a820b70049b41e7ad863f/README.rdoc")},
	{name: "composer", subs: []string{"install", "update", "run-script", "run"}, cite: cite("https://github.com/composer/composer/blob/2.10.3/doc/articles/scripts.md")},
	{name: "dotnet", subs: []string{"build", "test", "run"}, cite: cite("https://github.com/MicrosoftDocs/visualstudio-docs/blob/083bf98e2f8590b1796f2c7411363050956fad8e/docs/msbuild/exec-task.md")},
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
	var out []CodeRunStep
	add := func(words []runWord, sp shell.Span, async bool) bool {
		if c, ok := runsTree(words, at); ok {
			out = append(out, CodeRunStep{Text: strings.TrimSpace(text[sp.Start:sp.End]), Span: sp, Cite: c, Asynchronous: async})
			return true
		}
		return false
	}
	switch taint.ShellOf(w, job, x) {
	case taint.ShellBash, taint.ShellSh, taint.ShellUnknown:
		sc := taint.ReadScript(m, x.Run.Value).Script
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

// runsTree is whether the command of words runs the tree at at, and what
// says so.
func runsTree(words []runWord, at Placement) (Cite, bool) {
	if len(words) == 0 {
		return Cite{}, false
	}
	isPath := func(w runWord) bool { return w.isPath() && w.mayBeUnder(at) }
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
	rest := options(lookups(words[1:]))
	if slices.Contains(interpreters, name) {
		if (name == "python" || name == "python3") && len(words) > 3 && words[1].lookup == "-m" && words[2].lookup == "pip" {
			return runsTree(append([]runWord{literalWord("pip")}, words[3:]...), at)
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
		if t.name != name {
			continue
		}
		if !at.InWorkspace() || at.dir.known && at.dir.path != "." {
			// a tool reads the directory it runs in, the workspace's root
			// the tree is elsewhere
			return Cite{}, false
		}
		if len(t.subs) > 0 && (len(rest) == 0 || !slices.Contains(t.subs, rest[0])) {
			return Cite{}, false
		}
		if len(t.needs) > 0 && !slices.ContainsFunc(words[1:], func(w runWord) bool {
			return slices.Contains(t.needs, w.lookup) || strings.HasPrefix(w.lookup, "./")
		}) {
			return Cite{}, false
		}
		return t.cite, true
	}
	return Cite{}, false
}

// lookups are the texts of words for LookupCommand.
func lookups(words []runWord) []string {
	out := make([]string, len(words))
	for i, w := range words {
		out[i] = w.lookup
	}
	return out
}

// options are words without the options before the first that is not one.
func options(words []string) []string {
	for i, w := range words {
		if !strings.HasPrefix(w, "-") {
			return words[i:]
		}
	}
	return nil
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
