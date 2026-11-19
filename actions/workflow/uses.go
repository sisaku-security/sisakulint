package workflow

import (
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/expr"
)

// UsesKind is what a uses refers to.
type UsesKind uint8

const (
	UsesInvalid UsesKind = iota // none of the forms below
	UsesLocal                   // ./path, in the same repository
	UsesDocker                  // docker://image, with :tag or @digest
	UsesRemote                  // owner/repo[/path]@ref
	UsesSelf                    // $/path: the workflow's own repository at the workflow's commit; no @ref (PipelineConstants.TryParseSelfRepository)
	// UsesFolded is exactly ${{ 'string' }}, which the template reader
	// folds into the string; AsString is the string.
	// Folded is what the string is, and the pieces are the string's, in the
	// value: the bytes of the literal are the string's.
	UsesFolded
)

var usesKindNames = [...]string{"UsesInvalid", "UsesLocal", "UsesDocker", "UsesRemote", "UsesSelf", "UsesFolded"}

func (k UsesKind) String() string { return usesKindNames[k] }

// Piece is a part of a uses: its text and where it is in the value. A part
// that is not there has no text.
type Piece struct {
	Text string
	Span expr.Span
}

// Uses is the value of a step's or a job's uses. A fix that pins a ref
// replaces the bytes of Source(Ref.Span).
type Uses struct {
	String
	Kind UsesKind
	// Folded is, when Kind is UsesFolded, the kind of the folded string.
	// A literal with an escaped quote ('') is not the value's bytes one
	// for one, so it has no pieces, and Folded is UsesInvalid.
	Folded                 UsesKind
	Owner, Repo, Path, Ref Piece // Remote; Path also for Local and Self
	Image, Tag, Digest     Piece // Docker: an ImageReference's pieces

	// What GitHub runs for a uses, which the runner reads apart from
	// what is written:
	// it drops the empty parts of owner/repo/path, reads a backslash of the
	// path as /, and resolves . and .. as text from its directory of
	// actions, _actions/<owner>/<repo>/<ref>.

	// Outside is where the path goes above with ..: the root of its
	// repository or of the workspace; OutsideNone when it does not. The
	// uses then runs the action of another directory, which may be of
	// owner/repo at another ref.
	Outside UsesOutside
	// Target is, for OutsideRepository, the directory the path names, from
	// the runner's directory of actions; "" when the path leaves that
	// directory or names one with no action (fewer than three parts).
	Target string
	// Runs are the readings of the action that runs: the one of
	// owner/repo/path@ref, or, Outside, those of Target, which is
	// <owner>/<repo>/<ref>/<path> where a ref may hold a /. Matched is
	// whether Runs is the one that another uses of the same steps
	// downloads; else every way to split Target into a ref and a path is
	// a reading.
	Runs    []UsesAction
	Matched bool
	// ReadByOutside is whether another uses of the same steps goes above
	// the root of its repository into the directory of this uses: pinning
	// this uses' ref moves that directory, and that uses then runs no
	// action of this one.
	ReadByOutside bool
	// LocalPath is the path of ./ from the workspace and of $/ from the
	// repository, resolved, when HasLocalPath; the zero ActionPath is the root.
	LocalPath    ActionPath
	HasLocalPath bool
	normalized   string // the uses as GitHub reads it; "" when Outside
	written      string // the uses as written: the value, or the literal it folds
}

// UsesOutside is where the path of a uses goes with .., above the root it
// starts from.
type UsesOutside uint8

const (
	OutsideNone       UsesOutside = iota
	OutsideRepository             // a remote or $/ uses: above the root of the repository
	OutsideWorkspace              // a ./ uses: above the root of the workspace
)

var usesOutsideNames = [...]string{"none", "repository", "workspace"}

func (o UsesOutside) String() string { return usesOutsideNames[o] }

// UsesAction is a reading of the action a step's uses runs: the repository
// owner/repo, as written, at Ref, and the path in it.
type UsesAction struct {
	Owner, Repo, Ref string
	Path             ActionPath
}

// Is is whether a is the action owner/repo at path, in any case.
func (a UsesAction) Is(owner, repo string, path ActionPath) bool {
	return strings.EqualFold(a.Owner, owner) && strings.EqualFold(a.Repo, repo) && strings.EqualFold(a.Path.s, path.s)
}

// ActionPath is the path of an action in its repository, or of ./ in the
// workspace, as the runner reads it: parts with / between them, none
// empty, . or .. (a uses' Path is as written). The zero ActionPath is the
// root. Only the reader of uses makes one; facts.UsesPath, the path a fact
// asks about, also refuses white space and a backslash.
type ActionPath struct{ s string }

// IsZero is whether p is the root.
func (p ActionPath) IsZero() bool { return p.s == "" }

func (p ActionPath) String() string { return p.s }

// RootActionPath is the root of a repository, as the path of the action at
// it.
var RootActionPath = ActionPath{}

// Actions are the readings of the action u runs (Runs), or of what u folds
// to.
func (u Uses) Actions() []UsesAction { return u.Runs }

// Normalized is u as GitHub reads it: owner/repo[/path]@ref, ./path or
// $/path, with owner, repo and ref as written; false when u goes outside
// (Outside) or is none of those.
func (u Uses) Normalized() (string, bool) { return u.normalized, u.normalized != "" }

func (r *reader) uses(e *entry, p pos) Field[Uses] {
	s := r.str(e, p)
	f := Field[Uses]{Status: s.Status, Key: s.Key, Expr: s.Expr}
	if s.Status != Present {
		return f
	}
	if _, ok := s.Value.literal(); ok {
		f.Value = foldedUses(s.Value)
		return f
	}
	f.Value = parseUses(s.Value)
	if f.Value.Kind == UsesInvalid {
		r.report(InvalidValue, s.Value.Node.ContentSpan(), s.Value.pos(p), "uses %q is none of ./path, $/path, docker://image and owner/repo[/path]@ref", s.Value.Text())
		f.Status = Invalid
	}
	return f
}

// foldedUses reads the uses s, which is exactly ${{ 'string' }}: the pieces
// of the string, moved to where the literal's bytes are in the value.
func foldedUses(s String) Uses {
	u := Uses{String: s, Kind: UsesFolded}
	p := s.Parts[0]
	l := p.Tree.(*expr.Literal) // s.literal() holds
	if l.Raw != "'"+l.Str+"'" {
		return u
	}
	inner := splitUses(l.Str, p.InValue(l.Span()).Start+1)
	inner.String, inner.Folded, inner.Kind = s, inner.Kind, UsesFolded
	return inner
}

func parseUses(s String) Uses {
	u := splitUses(s.Text(), 0)
	u.String = s
	return u
}

// splitUses reads v as a uses. The spans of the pieces are in v, moved by
// at.
func splitUses(v string, at int) Uses {
	u := Uses{written: v}
	piece := func(start, end int) Piece {
		return Piece{Text: v[start:end], Span: expr.Span{Start: at + start, End: at + end}}
	}
	switch {
	case strings.HasPrefix(v, "$/"):
		start := len("$/")
		for start < len(v) && v[start] == '/' {
			start++
		}
		if strings.IndexByte(v, '@') >= 0 {
			return Uses{}
		}
		u.Kind = UsesSelf
		if start < len(v) {
			u.Path = piece(start, len(v))
		}
		u.readSelf(v[start:])
	case strings.HasPrefix(v, "./"):
		u.Kind, u.Path = UsesLocal, piece(0, len(v))
		u.readLocal(v[len("./"):])
	case strings.HasPrefix(v, "docker://"):
		start := len("docker://")
		ref, ok := imageReference(v[start:], at+start)
		if !ok {
			return Uses{}
		}
		u.Kind, u.Image, u.Tag, u.Digest = UsesDocker, ref.Name, ref.Tag, ref.Digest
	default:
		at := strings.IndexByte(v, '@')
		if at < 0 || at+1 == len(v) {
			return Uses{}
		}
		parts := partsOf(v[:at], "/\\")
		if len(parts) < 2 || strings.ContainsRune(v[:parts[1][1]], '\\') {
			return Uses{} // the runner drops empty parts; GitHub refuses a backslash in owner/repo
		}
		repoEnd := parts[1][1]
		if repoEnd < at {
			u.Path = piece(repoEnd+1, at)
		}
		u.Kind = UsesRemote
		u.Owner, u.Repo, u.Ref = piece(parts[0][0], parts[0][1]), piece(parts[1][0], repoEnd), piece(at+1, len(v))
		var path []string
		for _, p := range parts[2:] {
			path = append(path, v[p[0]:p[1]])
		}
		u.readRemote(path)
	}
	return u
}

// partsOf are the start and the end in s of each part between the bytes
// of seps, empty parts left out.
func partsOf(s, seps string) [][2]int {
	var out [][2]int
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && strings.IndexByte(seps, s[i]) < 0 {
			continue
		}
		if i > start {
			out = append(out, [2]int{start, i})
		}
		start = i + 1
	}
	return out
}

// resolve resolves the parts path from the directory base as text: . is
// dropped and .. drops the part before it. above is whether a .. found no
// part left to drop: the path went above the directory that the first
// part of base is in.
func resolve(base, path []string) (out []string, above bool) {
	out = append([]string(nil), base...)
	for _, p := range path {
		switch p {
		case ".":
		case "..":
			if len(out) == 0 {
				return nil, true
			}
			out = out[:len(out)-1]
		default:
			out = append(out, p)
		}
	}
	return out, false
}

// texts are the parts of s between the bytes of seps, empty parts left out.
func texts(s, seps string) []string {
	var out []string
	for _, p := range partsOf(s, seps) {
		out = append(out, s[p[0]:p[1]])
	}
	return out
}

// actionPath is parts, resolved, as an ActionPath.
func actionPath(parts []string) ActionPath { return ActionPath{strings.Join(parts, "/")} }

// readRemote reads path, the parts after owner/repo, from the runner's
// directory of the action, _actions/<owner>/<repo>/<ref parts>.
func (u *Uses) readRemote(path []string) {
	base := append([]string{u.Owner.Text, u.Repo.Text}, texts(u.Ref.Text, "/")...)
	got, above := resolve(base, path)
	if !above && len(got) >= len(base) && slices.Equal(got[:len(base)], base) {
		rest := got[len(base):]
		u.normalized = u.Owner.Text + "/" + u.Repo.Text
		if len(rest) > 0 {
			u.normalized += "/" + strings.Join(rest, "/")
		}
		u.normalized += "@" + u.Ref.Text
		u.Runs = []UsesAction{{Owner: u.Owner.Text, Repo: u.Repo.Text, Ref: u.Ref.Text, Path: actionPath(rest)}}
		return
	}
	u.Outside = OutsideRepository
	if !above {
		u.setTarget(got)
	}
}

// setTarget sets Target to the directory dir of the runner's directory of
// actions, and Runs to its readings, when dir may hold an action.
func (u *Uses) setTarget(dir []string) {
	if len(dir) < 3 {
		return
	}
	u.Target = strings.Join(dir, "/")
	u.Runs = nil
	rest := dir[2:]
	for k := 1; k <= len(rest); k++ {
		u.Runs = append(u.Runs, UsesAction{Owner: dir[0], Repo: dir[1], Ref: strings.Join(rest[:k], "/"), Path: actionPath(rest[k:])})
	}
}

// readLocal reads path, after ./, from the workspace, whose place among the
// runner's directories the input does not tell.
func (u *Uses) readLocal(path string) {
	got, above := resolve(nil, texts(path, "/"))
	if above {
		u.Outside = OutsideWorkspace
		return
	}
	u.normalized = "./" + strings.Join(got, "/")
	u.LocalPath, u.HasLocalPath = actionPath(got), true
}

// readSelf reads path, after $/, from the root of the repository, which the
// runner puts in _actions/<owner>/<repo>/<commit>, whose names the input
// does not tell: those stand as parts no path has.
func (u *Uses) readSelf(path string) {
	unknown := []string{"\x00owner", "\x00repo", "\x00commit"}
	got, above := resolve(unknown, texts(path, "/"))
	switch {
	case !above && len(got) >= 3 && slices.Equal(got[:3], unknown):
		u.normalized = "$/" + strings.Join(got[3:], "/")
		u.LocalPath, u.HasLocalPath = actionPath(got[3:]), true
	case !above && !slices.ContainsFunc(got, func(p string) bool { return strings.HasPrefix(p, "\x00") }):
		u.Outside = OutsideRepository
		u.setTarget(got) // above _actions/<owner>/<repo>/<commit>, into another action's
	default:
		u.Outside = OutsideRepository // a directory of _actions the input does not name, or above _actions
	}
}

// matchOutside reads the uses of steps that go above the root of their
// repository as the actions that the other uses of steps download, when
// any does: the runner puts each owner/repo@ref that a uses names, one
// that goes outside too, in _actions/<owner>/<repo>/<ref>, and runs the
// directory the path names. Each uses that downloads into the
// directory gives a reading.
func matchOutside(steps []Step) {
	for i := range steps {
		u := &steps[i].Uses.Value
		if steps[i].Uses.Status != Present || u.Target == "" {
			continue
		}
		dir := strings.Split(u.Target, "/")
		var runs []UsesAction
		for k := range steps {
			o := &steps[k]
			w := o.Uses.Value
			if k == i || o.Uses.Status != Present || w.Owner.Text == "" || !strings.EqualFold(w.Owner.Text, dir[0]) || !strings.EqualFold(w.Repo.Text, dir[1]) {
				continue
			}
			ref := texts(w.Ref.Text, "/")
			if len(dir)-2 < len(ref) || !slices.Equal(dir[2:2+len(ref)], ref) {
				continue
			}
			a := UsesAction{Owner: dir[0], Repo: dir[1], Ref: w.Ref.Text, Path: actionPath(dir[2+len(ref):])}
			if !slices.Contains(runs, a) {
				runs = append(runs, a)
			}
			o.Uses.Value.ReadByOutside = true
		}
		if runs != nil {
			u.Runs, u.Matched = runs, true
		}
	}
}
