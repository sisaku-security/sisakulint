package github

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/githubapi"
)

const (
	// maxArchive is the most bytes of an archive read, compressed (the
	// upstream's limit of the same).
	maxArchive = 100 << 20
	// maxDefinition is the most bytes kept of a file of an archive; the
	// files kept are those a definition may be (the YAML files, so that
	// a symlink action.yml to another name is read too) up to maxKept.
	maxDefinition = 1 << 20
	maxKept       = 8 << 20
	// maxEntries is the most entries kept of an archive (the files a
	// definition may be, and the symlinks); maxRunKept the most bytes kept
	// of all the archives of a run. Past either, an archive is not read
	// (unknown), so that the archives a pull request's author names do not
	// fill the memory.
	maxEntries = 100000
	maxRunKept = 64 << 20
)

// archiveKey is one archive: a commit of a repository.
type archiveKey struct {
	repo facts.Repo
	sha  facts.SHA
}

// archiveEntry is an entry of an archive: its type, the target of a
// symlink, and the bytes of a file kept (nil when not kept).
type archiveEntry struct {
	typ  byte
	link string
	data []byte
}

// archiveInfo is an archive read once a run.
type archiveInfo struct {
	done     chan struct{}
	entries  map[string]archiveEntry // by path from the root of the repository
	why      string                  // why the archive was not read
	canceled bool
}

// archive is the archive of repo at sha, read once (as GitHub serves it to
// the runner: GET .../tarball/{sha}, which redirects to codeload). The
// request counts against k.
func (r *resolver) archive(ctx context.Context, repo facts.Repo, sha facts.SHA, k facts.Kind) *archiveInfo {
	key := archiveKey{repo, sha}
	r.mu.Lock()
	if i, ok := r.archives[key]; ok {
		r.mu.Unlock()
		select {
		case <-i.done:
			if !i.canceled {
				return i
			}
		case <-ctx.Done():
			return &archiveInfo{why: "github: not asked: " + ctx.Err().Error()}
		}
		r.mu.Lock()
	}
	i := &archiveInfo{done: make(chan struct{})}
	r.archives[key] = i
	r.mu.Unlock()
	defer close(i.done)
	r.readArchive(ctx, repo, sha, k, i)
	if ctx.Err() != nil || i.why == usesTargetSpent {
		r.mu.Lock()
		i.canceled = true
		delete(r.archives, key)
		r.mu.Unlock()
	}
	return i
}

func (r *resolver) readArchive(ctx context.Context, repo facts.Repo, sha facts.SHA, k facts.Kind, i *archiveInfo) {
	base, why := r.repoPath(repo)
	if why != "" {
		i.why = why
		return
	}
	if why, ok := r.take(k, false); !ok {
		i.why = why
		return
	}
	what := "the archive of " + repo.String() + "@" + sha.String()
	entries := map[string]archiveEntry{}
	kept := 0
	err := r.api.Stream(ctx, base+"tarball/"+sha.String(), maxArchive, func(body io.Reader) error {
		gz, err := gzip.NewReader(body)
		if err != nil {
			return err
		}
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			_, p, ok := strings.Cut(h.Name, "/") // the archive's top directory is <owner>-<repo>-<sha>
			if !ok || p == "" || h.Typeflag == tar.TypeXGlobalHeader {
				continue
			}
			p = strings.TrimSuffix(p, "/")
			e := archiveEntry{typ: h.Typeflag, link: h.Linkname}
			regular := h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA
			if !(h.Typeflag == tar.TypeSymlink || regular && definitionLike(p)) {
				continue // a directory or another file: no definition reads it
			}
			if len(entries) >= maxEntries {
				return errTooManyEntries
			}
			if regular && h.Size <= maxDefinition && kept+int(h.Size) <= maxKept {
				b, err := io.ReadAll(io.LimitReader(tr, maxDefinition))
				if err != nil {
					return err
				}
				e.data, kept = b, kept+len(b)
			}
			entries[p] = e
		}
	})
	if err == nil {
		r.mu.Lock()
		over := r.archiveKept+kept > maxRunKept
		if !over {
			r.archiveKept += kept
		}
		r.mu.Unlock()
		if over {
			i.why = "github: " + what + " is not read: the archives read so far in this run hold " + strconv.Itoa(maxRunKept>>20) + " MiB of the files of actions in all"
			return
		}
	}
	var se *githubapi.StatusError
	switch {
	case err == nil:
		i.entries = entries
	case errors.Is(err, errTooManyEntries):
		i.why = "github: " + what + " has more than " + strconv.Itoa(maxEntries) + " entries that the linter keeps (symlinks, Dockerfiles and YAML files); the linter does not read the archive"
	case errors.Is(err, githubapi.ErrRateLimited):
		r.setLimited(false)
		i.why = err.Error()
	case errors.Is(err, githubapi.ErrTooLarge):
		i.why = "github: " + what + " is larger than " + strconv.Itoa(maxArchive>>20) + " MiB"
	case errors.As(err, &se) && (se.Status == http.StatusNotFound || se.Status == http.StatusUnauthorized || se.Status == http.StatusForbidden):
		i.why = "github: " + what + " is not there, or the token cannot read it (HTTP " + strconv.Itoa(se.Status) + ")"
	case ctx.Err() != nil:
		i.why = "github: not asked: " + ctx.Err().Error()
	default:
		i.why = "github: " + what + " could not be read: " + err.Error()
	}
}

// errTooManyEntries is an archive past maxEntries.
var errTooManyEntries = errors.New("too many entries")

// definitionLike is whether p is a file a definition may be read from: a
// file of a definition's names, or a YAML file a symlink of one names.
func definitionLike(p string) bool {
	b := path.Base(p)
	return b == "Dockerfile" || b == "dockerfile" || strings.HasSuffix(b, ".yml") || strings.HasSuffix(b, ".yaml")
}

// resolve follows the symlinks of p within the archive, those of the
// directories on its path too (the runner reads the extracted archive
// through the file system), to an entry that is not one; false when p is
// not there, a symlink leaves the repository, or the symlinks loop.
// followed is whether a symlink was followed: its target may be a file
// the archive does not keep (not a YAML file).
func (i *archiveInfo) resolve(p string) (real string, e archiveEntry, ok, followed bool) {
	for range 40 {
		parts := strings.Split(p, "/")
		moved := false
		for k := 1; k <= len(parts); k++ {
			prefix := strings.Join(parts[:k], "/")
			e, ok := i.entries[prefix]
			if !ok || e.typ != tar.TypeSymlink {
				continue
			}
			if path.IsAbs(e.link) {
				return "", archiveEntry{}, false, followed
			}
			p = path.Join(path.Dir(prefix), e.link, strings.Join(parts[k:], "/"))
			if p == ".." || strings.HasPrefix(p, "../") {
				return "", archiveEntry{}, false, followed
			}
			moved, followed = true, true
			break
		}
		if moved {
			continue
		}
		e, ok := i.entries[p]
		if !ok {
			return "", archiveEntry{}, false, followed
		}
		return p, e, true, followed
	}
	return "", archiveEntry{}, false, true // the symlinks loop
}

// definition is the file that defines the action at dir of the archive,
// as the runner looks for it: action.yml when it is a file (through its
// symlinks), else action.yaml, else a Dockerfile or dockerfile. It gives
// the file's name, its path once its symlinks are followed, and its bytes
// (nil for a Dockerfile); why is a file found but not kept.
func (i *archiveInfo) definition(dir string) (name facts.ActionFileName, real string, data []byte, found bool, why string) {
	for _, n := range []facts.ActionFileName{facts.ActionFileYML, facts.ActionFileYAML, facts.ActionFileDockerfile, facts.ActionFileDockerfileLower} {
		p, e, ok, followed := i.resolve(path.Join(dir, n.String()))
		if !ok && followed {
			return n, "", nil, true, "github: " + path.Join(dir, n.String()) + " of the archive is a symlink whose target the linter cannot read: the target is not there, is a file that the linter does not read from the archive (the linter reads only symlinks, Dockerfiles and YAML files), or the symlinks leave the repository or loop"
		}
		if !ok || e.typ != tar.TypeReg && e.typ != tar.TypeRegA {
			continue // not there, or not a file (a directory): the runner looks further
		}
		if n == facts.ActionFileDockerfile || n == facts.ActionFileDockerfileLower {
			return n, p, nil, true, ""
		}
		if e.data == nil {
			return n, p, nil, true, "github: " + p + " of the archive is larger than the files read"
		}
		return n, p, e.data, true, ""
	}
	return facts.ActionFileNameUnset, "", nil, false, ""
}

// definitionAt is the file that defines the action uses: <repo>/<path>@<ref>
// runs, from the archive of the commit of ref. A RawAnswer that is not
// found (the ref is not there, the archive is not read) is the answer.
func (r *resolver) definitionAt(ctx context.Context, repo facts.Repo, p facts.UsesPath, ref string, k facts.Kind) (facts.SHA, facts.ActionFileName, string, []byte, facts.RawAnswer) {
	at := r.refCommitOf(ctx, facts.GitRefCommit{Repo: repo, Ref: ref}, k)
	if at.State != facts.StateFound {
		return facts.SHA{}, 0, "", nil, at
	}
	var rc facts.RefCommit
	if err := json.Unmarshal(at.Value, &rc); err != nil {
		return facts.SHA{}, 0, "", nil, unknown("github: the commit of the ref could not be read")
	}
	i := r.archive(ctx, repo, rc.SHA, k)
	if i.why != "" {
		return facts.SHA{}, 0, "", nil, unknown(i.why)
	}
	dir := "."
	if !p.IsZero() {
		dir = p.String()
	}
	name, real, data, found, why := i.definition(dir)
	switch {
	case why != "":
		return facts.SHA{}, 0, "", nil, unknown(why)
	case !found:
		return facts.SHA{}, 0, "", nil, facts.RawAnswer{State: facts.StateAbsent}
	}
	return rc.SHA, name, real, data, facts.RawAnswer{State: facts.StateFound}
}

// actionDefinition answers action.definition: the file that defines the
// action, as the archive has it, and whether the archive's metadata
// differs from its blob (export-subst).
func (r *resolver) actionDefinition(ctx context.Context, q facts.ActionDefinition) facts.RawAnswer {
	repo, why := r.repoPath(q.Repo)
	if why != "" {
		return unknown(why)
	}
	sha, name, real, data, ans := r.definitionAt(ctx, q.Repo, q.Path, q.Ref, facts.KindActionDefinition)
	if ans.State != facts.StateFound {
		return ans
	}
	v := facts.ActionFile{Commit: sha, File: name, Content: string(data)}
	if data != nil {
		var parts []string
		for _, s := range strings.Split(real, "/") {
			parts = append(parts, url.PathEscape(s))
		}
		resp, why := r.get(ctx, facts.KindActionDefinition, repo+"contents/"+strings.Join(parts, "/")+"?ref="+sha.String(), "application/vnd.github.raw+json", maxDefinition+1)
		switch {
		case why != "":
			return unknown(why)
		case resp.status != http.StatusOK:
			return unknown("github: the blob of " + real + " could not be read to compare with the archive: HTTP " + strconv.Itoa(resp.status))
		}
		// export-subst puts the names of refs created after the commit into $Format:
		// placeholders; other conversions of git archive (eol, ident) do not
		// change later, so the archive read is the one the runner runs
		v.ArchiveSubstituted = !bytes.Equal(resp.body, data) && bytes.Contains(resp.body, []byte("$Format:"))
	}
	b, err := json.Marshal(v)
	if err != nil {
		return unknown("github: " + err.Error())
	}
	return facts.RawAnswer{State: facts.StateFound, Value: b}
}
