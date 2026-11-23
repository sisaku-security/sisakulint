package prcode

import (
	"path"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// anywhereWord is a directory that may be any: the cwd of a step whose
// run changes its directory, or a value not known.
var anywhereWord = runWord{base: wordAnywhere, known: true, open: true}

// stepCwd is the directory the shell of the run step x of job starts in:
// the step's working-directory, else the job's, else the workflow's
// defaults.run.working-directory, else the workspace (a default of the job
// overrides only the one of the same name of the workflow:
// https://github.com/github/docs/blob/f48cc8401cda2d90c4fef19ab76f5bff05e98830/data/reusables/actions/defaults-override.md).
// job is nil for a step of a composite action, which has only its own.
func stepCwd(w *workflow.Workflow, job *workflow.Job, x workflow.Step) runWord {
	fields := []workflow.Field[workflow.String]{x.WorkingDirectory}
	if job != nil {
		fields = append(fields, job.DefaultWorkingDirectory)
		if w != nil {
			fields = append(fields, w.DefaultWorkingDirectory)
		}
	}
	for _, f := range fields {
		switch f.Status {
		case workflow.Present:
			// working-directory is from the workspace
			return literalWord(".").join(dirWord(f.Value, job == nil))
		case workflow.Dynamic, workflow.Invalid:
			return anywhereWord
		}
	}
	return literalWord(".")
}

// dirWord is the directory v names, read as the runner reads
// working-directory: its literals and its ${{ }}, with no expansion of the
// shell ($RUNNER_TEMP is letters).
func dirWord(v workflow.String, inComposite bool) runWord {
	t := v.Text()
	var b wordBuilder
	if len(v.Parts) == 0 {
		b.literal(t)
	}
	for _, p := range v.Parts {
		s := t[p.Span.Start:p.Span.End]
		if p.Expr {
			b.unknown(exprHead(p, inComposite), s)
			continue
		}
		b.literal(s)
	}
	return b.word()
}

// changesDirectory is whether a command named name changes the directory
// of the shell: cd, pushd and popd, and in pwsh (any case) their cmdlets
// and aliases.
func changesDirectory(name string, pwsh bool) bool {
	switch name {
	case "cd", "pushd", "popd":
		return true
	}
	if !pwsh {
		return false
	}
	for _, n := range []string{"cd", "pushd", "popd", "chdir", "sl", "Set-Location", "Push-Location", "Pop-Location"} {
		if strings.EqualFold(name, n) {
			return true
		}
	}
	return false
}

// changesDirectoryWords is whether the simple command of words changes
// the directory of the shell or of the command it runs: cd, pushd or popd,
// after builtin or command too, and env with -C or --chdir and sudo with -D
// or --chdir among their own options (sudo's -C is --close-from). A
// command named by a word not known is not read.
func changesDirectoryWords(ws []shell.CommandWord) bool {
	if len(ws) == 0 || !ws[0].Known {
		return false
	}
	name := path.Base(ws[0].Text)
	if (name == "builtin" || name == "command") && len(ws) > 1 {
		return changesDirectoryWords(ws[1:])
	}
	if name == "env" || name == "sudo" {
		// the words before the command it runs (shell.LookupCommand), or
		// all of them when an option it does not declare stops the lookup
		end := len(ws)
		if m := shell.LookupCommand(ws); len(m.Wrappers) > 0 && m.Command > 0 {
			end = m.Command
		}
		short := "-C"
		if name == "sudo" {
			short = "-D"
		}
		return slices.ContainsFunc(ws[1:end], func(w shell.CommandWord) bool {
			return w.Known && (strings.HasPrefix(w.Text, short) || strings.HasPrefix(w.Text, "--chdir"))
		})
	}
	return changesDirectory(name, false)
}

// join is the path rel names when the shell's directory is cwd: rel
// itself when it is not relative (an absolute path, one from runner.temp
// or github.workspace, or a value not known); else rel under cwd. A path
// that leaves its base by .. may be anywhere, as word reads one.
func (cwd runWord) join(rel runWord) runWord {
	if !rel.relative {
		return rel
	}
	out := rel
	switch {
	case cwd.base == wordAnywhere:
		return anywhereWord
	case cwd.base == wordBeside:
		if climbs(rel.path, rel.open) {
			return anywhereWord // .. from beside the workspace may come back into it
		}
		out = cwd // what is under it is out of every Placement too
	case cwd.open:
		out = cwd // rel is under what is not known of cwd
	case cwd.path != "." && cwd.path != "":
		out.base = cwd.base
		if rel.open {
			out.path = cwd.path + "/" + strings.TrimPrefix(rel.path, "./")
		} else {
			out.path = path.Join(cwd.path, rel.path)
		}
	default:
		out.base = cwd.base
	}
	out.relative = false
	if (out.base == wordWorkspace || out.base == wordRunnerTemp) && climbs(out.path, out.open) {
		// it may come back into its base: ../<repository>/x of the
		// workspace <work>/<repository>/<repository>
		return anywhereWord
	}
	return out
}
