package repofile

import (
	"context"
	"errors"
	"io"
	"io/fs"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// maxFileSize is how much of a configuration file is read: one larger is
// not read, and the facts that need it are unknown.
const maxFileSize = 1 << 20

// New is the Resolver of the kinds of the provider repo-file, read from
// fsys, the root of the repository. It answers no other kind.
func New(fsys fs.FS) facts.Resolver { return resolver{fsys} }

type resolver struct{ fsys fs.FS }

func (r resolver) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	var a facts.RawAnswer
	switch q := q.(type) {
	case facts.DependabotVersionUpdates:
		a = r.dependabotVersionUpdates(q)
	case facts.RenovateManagerEnabled:
		a = r.renovateManagerEnabled(q)
	default:
		return facts.RawAnswer{State: facts.StateUnknown, Reason: "not a fact of the files of the repository"}
	}
	a.Source = facts.SourceRepoFile
	return a
}

// readFile reads name of r: ok false and no error when it is not there.
func (r resolver) readFile(name string) (b []byte, ok bool, err error) {
	f, err := r.fsys.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	b, err = io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, false, err
	}
	if len(b) > maxFileSize {
		return nil, false, errors.New(name + " is larger than 1 MiB")
	}
	return b, true, nil
}

func found(v bool) facts.RawAnswer {
	if v {
		return facts.RawAnswer{State: facts.StateFound, Value: []byte("true")}
	}
	return facts.RawAnswer{State: facts.StateFound, Value: []byte("false")}
}

func unknown(reason string) facts.RawAnswer {
	return facts.RawAnswer{State: facts.StateUnknown, Reason: reason}
}
