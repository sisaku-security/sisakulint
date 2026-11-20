package cli

import (
	"fmt"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"io"
	"io/fs"

	"github.com/sisaku-security/sisakulint/actions/lint"
)

// readInputs reads what o names in fsys: stdin, the PATHs, or the whole
// repository, with the PATHs as the inputs reported for --read-all. fsys
// is an os.Root's, through which nothing outside it is read, a symlink
// included, or the tree of --remote; nil for stdin.
func readInputs(fsys fs.FS, o options, stdin io.Reader) (lint.Inputs, error) {
	if !o.stdinName.IsZero() {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return lint.Inputs{}, inputError{fmt.Errorf("stdin: %w", err)}
		}
		in, err := lint.Single(lint.InputBytes{Name: o.stdinName, Bytes: b})
		if err != nil {
			return lint.Inputs{}, usageError{err}
		}
		return in, nil
	}
	if len(o.paths) == 0 || o.remote != nil && o.remote.pull > 0 { // a pull request's PATHs are among the changed inputs
		in, err := lint.EnumerateExcept(fsys, o.exclude)
		if err != nil {
			return lint.Inputs{}, inputError{err}
		}
		return in, nil
	}
	seen := map[facts.InputPath]bool{}
	var paths []facts.InputPath
	var names []string
	for _, p := range o.paths {
		n, err := facts.CleanInputPath(p)
		if err != nil {
			return lint.Inputs{}, usageError{err}
		}
		if seen[n] {
			return lint.Inputs{}, usageError{fmt.Errorf("%s is given twice", n)}
		}
		seen[n] = true
		paths = append(paths, n)
		names = append(names, n.String())
		st, err := fs.Stat(fsys, n.String())
		if err != nil {
			return lint.Inputs{}, inputError{err}
		}
		if st.IsDir() {
			return lint.Inputs{}, inputError{fmt.Errorf("%s is a directory; give files, or no PATH to read the whole repository", n)}
		}
	}
	if o.readAll {
		in, err := lint.EnumerateExcept(fsys, o.exclude)
		if err != nil {
			return lint.Inputs{}, inputError{err}
		}
		if in, err = in.WithReported(paths); err != nil {
			return lint.Inputs{}, usageError{fmt.Errorf("--read-all: %w", err)}
		}
		return in, nil
	}
	in, err := lint.Files(fsys, names)
	if err != nil {
		return lint.Inputs{}, inputError{err}
	}
	return in, nil
}
