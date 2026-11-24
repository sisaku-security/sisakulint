package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"slices"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/facts/github"
	"github.com/gh-intel/sisakulint/actions/internal/githubapi"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/repofile"
)

// resolver is where the answers come from: --fact, the files of the
// repository in fsys that are not inputs (the kinds of the provider
// repo-file; none without fsys, as for --stdin-name), the file of facts,
// then GitHub with --online; with no file and no --online, nothing is
// asked of a file or of GitHub. What none of them answers is not known,
// and a finding whose condition depends on it is conditional. The files of
// the repository come before the file of facts, which may be of an earlier
// run; what they leave unknown, the file of facts may answer. The FactSources are what a DefaultRun of
// facts reads of them.
func resolver(o options, getenv func(string) string, fsys fs.FS) (facts.Resolver, lint.FactSources, error) {
	src := lint.FactSources{Online: o.online, AnsweredKinds: facts.AnsweredKindsOf(o.given)}
	var rs []facts.Resolver // after --fact and the files of the repository
	if o.factsIn != "" {
		b, err := os.ReadFile(o.factsIn)
		if err != nil {
			return nil, src, inputError{fileError(o.factsBy, o.factsFrom, o.factsIn, err)}
		}
		s, err := facts.LoadStore(b)
		if err != nil {
			return nil, src, inputError{fileError(o.factsBy, o.factsFrom, o.factsIn, err)}
		}
		rs = append(rs, s)
		for _, k := range s.AnsweredKinds() { // with what the file derives; --fact derives nothing
			if !slices.Contains(src.AnsweredKinds, k) {
				src.AnsweredKinds = append(src.AnsweredKinds, k)
			}
		}
	}
	if o.online {
		rs = append(rs, github.New(github.Options{Token: getenv("GITHUB_TOKEN"), BaseURL: o.githubAPI, ReadRunsUsing: readRunsUsing}))
	}
	if o.factsIn == "" && !o.online {
		rs = append(rs, offline{}) // the reason of what --fact does not give
	}
	r := rs[0]
	if len(rs) > 1 {
		r = facts.First(rs...)
	}
	if fsys != nil {
		r = repoFileFirst{repofile.New(fsys), r}
	}
	if o.arguments != nil {
		r = facts.First(o.arguments, r)
	}
	return r, src, nil
}

// repoFileFirst asks the files of the repository, then rest: an Unknown of
// the files is the answer when rest knows no more, so that its reason (a
// preset whose content is not read) is not the one of being offline.
type repoFileFirst struct{ files, rest facts.Resolver }

func (r repoFileFirst) Resolve(ctx context.Context, q facts.Query) facts.RawAnswer {
	a := facts.Checked(q, r.files.Resolve(ctx, q))
	if a.State != facts.StateUnknown {
		return a
	}
	if b := facts.Checked(q, r.rest.Resolve(ctx, q)); b.State != facts.StateUnknown || a.Source != facts.SourceRepoFile {
		return b
	}
	return a
}

// offline answers every fact Unknown: the command asks nothing unless told to.
type offline struct{}

func (offline) Resolve(context.Context, facts.Query) facts.RawAnswer {
	return facts.RawAnswer{State: facts.StateUnknown, Reason: "offline: pass --facts or --online"}
}

// parseAPI reads --github-api: an https URL with a host, or an http one
// of a loopback address (githubapi.Loopback), so that GITHUB_TOKEN does not
// leave the machine in the clear.
func parseAPI(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("--github-api: %w", err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, errors.New("--github-api: not an http or https URL with a host")
	}
	if u.Scheme == "http" && !githubapi.Loopback(u) {
		return nil, errors.New("--github-api: an http URL is taken only for a loopback address (localhost, 127.0.0.0/8, ::1); GITHUB_TOKEN would be sent in the clear: use https")
	}
	return u, nil
}

// writeFacts writes the facts of a run as a file of facts.
func writeFacts(p string, entries []facts.Entry) error {
	b, err := facts.EncodeFile(entries)
	if err != nil {
		return err
	}
	return writeFileAtomic(p, b)
}
