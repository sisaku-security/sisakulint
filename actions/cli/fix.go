package cli

import (
	"context"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"slices"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// fixFlag is --fix: alone it is safe; --fix=review applies all fixes.
// Without --fix the safety is unset.
type fixFlag struct{ safety lint.Safety }

func (f *fixFlag) IsBoolFlag() bool { return true }

func (f *fixFlag) String() string {
	if f == nil || f.safety == lint.SafetyUnset {
		return ""
	}
	return f.safety.String()
}

func (f *fixFlag) Set(s string) error {
	if s == "true" { // --fix alone
		s = "safe"
	}
	sf, err := lint.ParseSafety(s)
	f.safety = sf
	return err
}

// dryRun is the diff of what applyFix would write, each file that changes
// in the order of the names, as git diff writes it. It applies the fixes
// as --fix does, run again included, and writes nothing.
func dryRun(ctx context.Context, root fixFiles, in lint.Inputs, reg *lint.Registry, r facts.Resolver, rep lint.Report, safety lint.Safety, symlinked func(facts.InputPath) bool) ([]byte, []lint.Unchecked, error) {
	a, err := lint.ApplyFixes(ctx, in, reg, r, rep, safety)
	if err != nil {
		return nil, nil, err
	}
	out := a.Files
	// what --fix would refuse to write (a symlink, a file changed since it
	// was read) fails here too
	if _, err := precheck(root, in, out, symlinked); err != nil {
		return nil, nil, err
	}
	var b []byte
	for _, n := range slices.SortedFunc(maps.Keys(out), facts.CompareInputPaths) {
		input, _ := in.Lookup(n)
		b = append(b, unifiedDiff(n.String(), input.Tree.Bytes(), out[n])...)
	}
	return b, a.Unchecked, nil
}

// applyFix applies the fixes of rep to the files under root and says what
// came of it. Every file is written beside the one it replaces before any
// is renamed over it, so a failure writes nothing; only a rename that fails
// leaves the files before it fixed.
func applyFix(ctx context.Context, root *os.Root, in lint.Inputs, reg *lint.Registry, r facts.Resolver, rep lint.Report, safety lint.Safety, symlinked func(facts.InputPath) bool) *lint.FixResult {
	res := &lint.FixResult{Safety: safety}
	a, err := lint.ApplyFixes(ctx, in, reg, r, rep, safety)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	out := a.Files
	res.UncheckedRules = a.Unchecked // said though writing fails after
	perms, err := precheck(root, in, out, symlinked)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	names := slices.SortedFunc(maps.Keys(out), facts.CompareInputPaths)
	staged := map[facts.InputPath]string{}
	unstage := func() {
		for _, tmp := range staged {
			root.Remove(tmp)
		}
	}
	for _, n := range names {
		tmp, err := stage(root, n, out[n], perms[n])
		if err != nil {
			unstage()
			res.Error = fmt.Sprintf("%s: %v; nothing is written", n, err)
			return res
		}
		staged[n] = tmp
	}
	for _, n := range names {
		if err := root.Rename(staged[n], n.String()); err != nil {
			unstage()
			res.Error = fmt.Sprintf("%s: %v", n, err)
			return res
		}
		delete(staged, n)
		res.Written = append(res.Written, n)
	}
	return res
}

// fixFiles are the files a fix is checked against: an os.Root's, or the
// tree of --remote.
type fixFiles interface {
	Lstat(name string) (fs.FileInfo, error)
	ReadFile(name string) ([]byte, error)
}

// precheck checks that each file of out is a regular file (not a symlink,
// which a rename would replace, or whose target is another file) and is
// still as it was read. It gives the permission of each. symlinked, when
// not nil, is whether a file is a symlink where it was read (the tree of
// --remote, written under root as files).
func precheck(root fixFiles, in lint.Inputs, out map[facts.InputPath][]byte, symlinked func(facts.InputPath) bool) (map[facts.InputPath]fs.FileMode, error) {
	perms := map[facts.InputPath]fs.FileMode{}
	for n := range out {
		if symlinked != nil && symlinked(n) {
			return nil, fmt.Errorf("%s is a symlink in the repository; the run writes no fix to any file", n)
		}
		st, err := root.Lstat(n.String())
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file (a symlink?); nothing is written", n)
		}
		b, err := root.ReadFile(n.String())
		if err != nil {
			return nil, err
		}
		input, state := in.Lookup(n)
		if state != lint.LookupFound || input.Tree == nil || string(b) != string(input.Tree.Bytes()) {
			return nil, fmt.Errorf("%s has changed since it was read; nothing is written", n)
		}
		perms[n] = st.Mode().Perm()
	}
	return perms, nil
}
