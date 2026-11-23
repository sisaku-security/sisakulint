package facts

import (
	"slices"
	"strings"
)

// derived answers from the facts of s what follows from them. There is one
// such thing, written here as it is, not declared in the schema: when a
// second one comes, a way to declare them is to be made.
//
// git.commit-ref{repo, sha} from git.ref-commit{repo, ref} whose answer is
// sha found as a branch or a tag: the runner runs that ref's tip, and a
// ref has its tip. This is what makes the SHA a fix of commit-sha writes
// known in a replay, and so in lint.ApplyFixes, which runs again on the
// facts of the report.
// Only a file derives: a Recorder that did would answer by what was asked
// before, and a report would not be the same bytes from one run to the
// next.
func (s *Store) derived(q Query) (RawAnswer, bool) {
	c, ok := q.(GitCommitRef)
	if !ok {
		return RawAnswer{}, false
	}
	var best RefName
	for k, r := range s.values {
		d, ref, ok := commitRefOf(k, r)
		if !ok || d != c {
			continue
		}
		if best.IsZero() || strings.Compare(ref.s, best.s) < 0 {
			best = ref
		}
	}
	if best.IsZero() {
		return RawAnswer{}, false
	}
	v, _ := best.MarshalJSON()
	return RawAnswer{State: StateFound, Value: v}, true
}

// commitRefOf is the git.commit-ref that the found git.ref-commit q, of
// the answer r, derives, and its answer: false when r has no ref (a full
// SHA found as a commit only). It is the one place of the rule of derived.
func commitRefOf(q Query, r RefCommit) (GitCommitRef, RefName, bool) {
	g, ok := q.(GitRefCommit)
	if !ok || r.Ref.IsZero() {
		return GitCommitRef{}, RefName{}, false
	}
	return GitCommitRef{Repo: g.Repo, SHA: r.SHA}, r.Ref, true
}

// AnsweredKinds are the kinds of the facts that s answers with found or
// absent: those of its entries (AnsweredKindsOf), and git.commit-ref when
// s derives an answer of it. A DefaultRun of facts reads these: a file
// that derives git.commit-ref answers it, as a replay and lint.ApplyFixes
// ask it.
func (s *Store) AnsweredKinds() []Kind {
	out := AnsweredKindsOf(s.Entries())
	if slices.Contains(out, KindGitCommitRef) {
		return out
	}
	for k, r := range s.values {
		if _, _, ok := commitRefOf(k, r); ok {
			return append(out, KindGitCommitRef)
		}
	}
	return out
}

// AnsweredKindsOf are the kinds of the facts of entries that have an
// answer, found or absent, each once, in the order of entries. Entries
// derive nothing: --fact gives its entries alone.
func AnsweredKindsOf(entries []Entry) []Kind {
	var out []Kind
	for _, e := range entries {
		if st := e.RawAnswer.State; (st == StateFound || st == StateAbsent) && !slices.Contains(out, e.Query.Kind()) {
			out = append(out, e.Query.Kind())
		}
	}
	return out
}
