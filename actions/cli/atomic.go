package cli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/gh-intel/sisakulint/actions/facts"
	"io/fs"
	"os"
	"path"
	"path/filepath"
)

// tempName is a name for a file written in a directory before it is
// renamed over another: hidden, neither a workflow nor an action.yml, so
// that lint.Enumerate never reads one left behind, and short whatever the
// name of the file it replaces.
func tempName() string {
	b := make([]byte, 8)
	rand.Read(b)
	return ".sisakulint-tmp-" + hex.EncodeToString(b)
}

// writeFileAtomic writes data to the file p of the OS: a file of facts.
// Through a symlink it writes the file linked to, and the link stays. A
// file already there keeps its permission; a new one is 0644.
func writeFileAtomic(p string, data []byte) error {
	p, err := followLinks(p)
	if err != nil {
		return err
	}
	perm := fs.FileMode(0o644)
	if st, err := os.Stat(p); err == nil {
		perm = st.Mode().Perm()
	}
	tmp := filepath.Join(filepath.Dir(p), tempName())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if err := fill(f, data, perm); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// followLinks is the file p names after its symlinks, which need not be
// there yet.
func followLinks(p string) (string, error) {
	for range 40 { // as many as Linux follows
		st, err := os.Lstat(p)
		if err != nil || st.Mode()&fs.ModeSymlink == 0 {
			return p, nil
		}
		to, err := os.Readlink(p)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(to) {
			to = filepath.Join(filepath.Dir(p), to)
		}
		p = to
	}
	return "", errors.New(p + ": too many symlinks")
}

// stage writes data, with perm, to a new file in the directory of name
// under root, and gives the new file's name, to be renamed over name. On an
// error nothing is left.
func stage(root *os.Root, name facts.InputPath, data []byte, perm fs.FileMode) (string, error) {
	tmp := path.Join(path.Dir(name.String()), tempName())
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return "", err
	}
	if err := fill(f, data, perm); err != nil {
		root.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// fill writes data to f, gives it perm (which the umask may have narrowed),
// and closes it.
func fill(f *os.File, data []byte, perm fs.FileMode) error {
	_, err := f.Write(data)
	if err == nil {
		err = f.Chmod(perm)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
