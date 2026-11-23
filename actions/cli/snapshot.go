package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/remote"
)

// makeSnapshotDir makes dir (--write-snapshot), before the run asks GitHub
// anything: a directory that is there already is a usage error, so that
// only this run writes in it.
func makeSnapshotDir(dir string) (*os.Root, error) {
	if err := os.Mkdir(dir, 0o755); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, usageError{fmt.Errorf("--write-snapshot %s: already exists; give a path that does not exist", dir)}
		}
		return nil, fmt.Errorf("--write-snapshot: %w", err)
	}
	return os.OpenRoot(dir)
}

// writeSnapshot writes under dir the files of t whose contents the run
// read, by their paths from the root of the repository: a file as its
// blob, a symlink the run opened as the file it points to, and nothing
// else (no symlink, no submodule, no file not read). A file is created,
// never replaced; the path of an entry of the tree stays in dir (os.Root).
func writeSnapshot(dir *os.Root, t *remote.Tree) error {
	for _, f := range t.ReadFiles() {
		p := f.Path.String()
		if runtime.GOOS == "windows" && strings.Contains(p, `\`) {
			return fmt.Errorf("%s: the path has a backslash, which Windows reads as a separator of directories, so the file cannot be written on Windows", p)
		}
		var b []byte
		switch f.Mode {
		case "120000":
			if len(t.Hops(f.Path)) == 0 {
				continue // a symlink on the way to another path, or one not followed
			}
			data, err := fs.ReadFile(t, p)
			if err != nil {
				continue
			}
			b = data
		default:
			data, ok := t.Blob(f.Path)
			if !ok {
				continue // not read
			}
			b = data
		}
		if d := path.Dir(p); d != "." {
			if err := dir.MkdirAll(d, 0o755); err != nil {
				return err
			}
		}
		w, err := dir.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		if _, err := w.Write(b); err != nil {
			w.Close()
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
	}
	return nil
}

// treeSymlink is whether the entry of t at n is a symlink: a fix of it is
// refused, as --root refuses a fix of a symlink.
func treeSymlink(t *remote.Tree) func(facts.InputPath) bool {
	return func(n facts.InputPath) bool {
		m, ok := t.Mode(n)
		return ok && m == "120000"
	}
}
