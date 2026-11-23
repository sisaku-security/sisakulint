package lint

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gh-intel/sisakulint/actions/facts"
	"io/fs"
	"path"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/gh-intel/sisakulint/actions/workflow"
	"github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// InputState is whether an input could be read ($defs/input-state of
// schema/report-v0.json). The zero InputState is InputStateRead.
type InputState uint8

// Input is one file to check.
type Input struct {
	Name           facts.InputPath
	InputKind      InputKind // InputKindWorkflow or InputKindActionMetadata
	State          InputState
	Tree           *cst.Tree
	Workflow       *workflow.Workflow       // when InputKind is InputKindWorkflow and there is a tree
	ActionMetadata *workflow.ActionMetadata // when InputKind is InputKindActionMetadata and there is a tree
	Diagnostics    []workflow.Diagnostic
	Reason         string // why it is Unreadable or Invalid, when not the diagnostics
	// calls is how many of the last Diagnostics are of its calls of other
	// inputs (withCallDiagnostics), which reading the file alone does not
	// give
	calls int
}

// fileDiagnostics are the diagnostics of reading the file alone: those a
// fix is checked against, since the fixed file is read alone.
func (in Input) fileDiagnostics() []workflow.Diagnostic {
	return in.Diagnostics[:len(in.Diagnostics)-in.calls]
}

// LookupState is what is known of an input in a set of inputs.
type LookupState uint8

const (
	LookupUnknown LookupState = iota // not in the set, and the set is not the whole repository
	LookupFound
	LookupAbsent // not in the set, and the set is the whole repository
)

// InputSet finds the other inputs of a run.
type InputSet interface {
	Lookup(name facts.InputPath) (Input, LookupState)
}

// Inputs are the inputs of a run, by Name. Complete is whether they are
// every workflow and action.yml of the repository (Enumerate); Excluded,
// the paths left out, whose inputs are InputStateExcluded (EnumerateExcept).
type Inputs struct {
	List     []Input
	Complete bool
	Excluded []Exclude // in the order of their paths, each once
	// Reported are the inputs whose places a run reports (--read-all of the
	// CLI, WithReported); the rules read the others too, for what the
	// places of the reported ones depend on. Nil is every input.
	Reported []facts.InputPath
	// Submodules are the paths of the submodules of the repository (a
	// remote run reads them from the tree): what is under one, a job's
	// checkout may fetch, and the run did not read it. Lookup is
	// LookupUnknown under them, as under Excluded.
	Submodules []facts.InputPath
	// Repo is the repository the inputs are of (--repo): the rules name it
	// in the facts about the repository they ask. The zero Repo is none,
	// and those facts name none.
	Repo facts.Repo
	// Root is the repository the inputs were read from when they are the
	// whole of it (EnumerateExcept): the analysis reads files of it that
	// are not inputs, such as the configuration of actions/labeler. It is
	// nil for Files and Single.
	Root fs.FS
}

// Lookup finds the input name. It is LookupAbsent only when the inputs are
// the whole repository, and LookupUnknown for a name under Excluded or
// Submodules: it was not read.
func (in Inputs) Lookup(name facts.InputPath) (Input, LookupState) {
	if !name.IsZero() {
		for _, e := range in.Excluded {
			if e.covers(name.String()) {
				return Input{}, LookupUnknown
			}
		}
		for _, sub := range in.Submodules {
			if strings.HasPrefix(name.String(), sub.String()+"/") {
				return Input{}, LookupUnknown
			}
		}
		i, ok := slices.BinarySearchFunc(in.List, name, func(x Input, n facts.InputPath) int { return facts.CompareInputPaths(x.Name, n) })
		if ok {
			return in.List[i], LookupFound
		}
		if in.Complete {
			return Input{}, LookupAbsent
		}
	}
	return Input{}, LookupUnknown
}

// WithReported is in with the inputs names as the ones whose places a run
// reports (Inputs.Reported). Each name is to be an input of in, not
// excluded, and given once; names is not to be empty.
func (in Inputs) WithReported(names []facts.InputPath) (Inputs, error) {
	if len(names) == 0 {
		return Inputs{}, errors.New("no input to report")
	}
	seen := map[facts.InputPath]bool{}
	for _, n := range names {
		if seen[n] {
			return Inputs{}, fmt.Errorf("%s is given twice", n)
		}
		seen[n] = true
		for _, e := range in.Excluded {
			if e.covers(n.String()) {
				return Inputs{}, fmt.Errorf("%s is under %s, a path left out (--exclude)", n, e)
			}
		}
		if _, state := in.Lookup(n); state != LookupFound {
			return Inputs{}, fmt.Errorf("%s is not a workflow or an action.yml of the inputs (a workflow is right under .github/workflows; a path through a symlink to a directory is not one)", n)
		}
	}
	in.Reported = slices.Clone(names)
	slices.SortFunc(in.Reported, facts.CompareInputPaths)
	return in, nil
}

// InputBytes is one input given as bytes: an editor's buffer not saved, the
// text an agent passes, stdin. Name is its logical path, / separated; a
// fingerprint depends on it, so the same file must get the same Name each
// time.
type InputBytes struct {
	Name      facts.InputPath
	InputKind InputKind // InputKindUnset: action.yml and action.yaml are action metadata, the rest workflows
	Bytes     []byte
}

const workflowsDir = ".github/workflows"

// Exclude is a path of the repository left out of a run with what is
// under it (--exclude of the CLI). It never covers .github/workflows,
// whose workflows GitHub runs.
type Exclude struct{ p string }

// ParseExclude reads s as facts.CleanInputPath does, and refuses .github/workflows,
// a path under it and one above it.
func ParseExclude(s string) (Exclude, error) {
	c, err := facts.CleanInputPath(s)
	if err != nil {
		return Exclude{}, err
	}
	n := c.String()
	if under(n, workflowsDir) || under(workflowsDir, n) {
		return Exclude{}, fmt.Errorf("%s: the workflows of %s cannot be left out: GitHub runs them", n, workflowsDir)
	}
	return Exclude{n}, nil
}

func (e Exclude) String() string               { return e.p }
func (e Exclude) MarshalJSON() ([]byte, error) { return json.Marshal(e.p) }

// covers is whether the path p is left out by e.
func (e Exclude) covers(p string) bool { return under(p, e.p) }

// Covers is whether e leaves the path p out.
func (e Exclude) Covers(p facts.InputPath) bool { return e.covers(p.String()) }

// Enumerate is EnumerateExcept with nothing left out.
func Enumerate(fsys fs.FS) (Inputs, error) { return EnumerateExcept(fsys, nil) }

// EnumerateExcept lists every workflow and action.yml of the repository at the
// root of fsys, the way GitHub and the runner find them (seen on GitHub,
// 2026-09-24):
//   - a workflow is a file right under .github/workflows whose extension is
//     .yml or .yaml, in lower case. A symlink there is Invalid:
//     GitHub makes a run of it that fails without a job;
//   - an action is action.yml, or action.yaml when there is no action.yml
//     in any directory; a symlink to one is followed, as the runner's
//     File.Exists does.
//
// Nothing under .git is read. A symlink to a directory is not followed
// (one right under .github/workflows named as a workflow is Invalid, as
// above): when the walk is done, one that leads, within fsys, to a
// directory out of .git with no input, no directory not read and no
// symlink under it is left out, since there is nothing more through it; any other, and one that cannot be looked at (out of an
// os.Root), is an Unreadable input named by the link, and the inputs are
// not complete, as is a directory that cannot be read. The error is only
// for a root that cannot be read.
//
// What ex covers is walked too: its action.yml (by the rule of action.yaml
// above) are InputStateExcluded, not read; a symlink in it and a
// directory in it that cannot be read are not inputs, though a symlink in
// it counts when a symlink out of it that leads there is judged.
func EnumerateExcept(fsys fs.FS, ex []Exclude) (Inputs, error) {
	if _, err := fs.ReadDir(fsys, "."); err != nil {
		return Inputs{}, err
	}
	ex = slices.Clone(ex)
	slices.SortFunc(ex, func(a, b Exclude) int { return strings.Compare(a.p, b.p) })
	in := Inputs{Complete: true, Excluded: slices.Compact(ex), Root: fsys}
	excludedBy := func(p string) (Exclude, bool) {
		for _, e := range in.Excluded {
			if e.covers(p) {
				return e, true
			}
		}
		return Exclude{}, false
	}
	var links []string    // symlinks to directories, judged when the walk is done
	var symlinks []string // every symlink the walk sees
	var unread []string   // what the walk could not read in what is excluded: not inputs
	addUnreadable := func(p, why string) {
		in.Complete = false
		k := InputKindActionMetadata
		if p == ".github" || p == workflowsDir {
			k = InputKindWorkflow
		}
		in.List = append(in.List, Input{Name: facts.WalkedInputPath(p), InputKind: k, State: InputStateUnreadable, Reason: why})
	}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if p != "." {
			// a path no InputPath can hold (an fs.FS that lists ../x) is left out;
			// below, facts.WalkedInputPath(p) holds only paths facts.CleanInputPath keeps as they are
			if n, perr := facts.CleanInputPath(p); perr != nil || n.String() != p {
				in.Complete = false
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}
		e, isEx := excludedBy(p)
		if err != nil {
			if isEx {
				unread = append(unread, p)
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			addUnreadable(p, "not read: "+err.Error())
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		dir, base := path.Split(p)
		dir = strings.TrimSuffix(dir, "/")
		workflowName := dir == workflowsDir && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml"))
		if d.Type()&fs.ModeSymlink != 0 {
			symlinks = append(symlinks, p)
		}
		// a symlink right under .github/workflows that is not named as a
		// workflow is not one, but uses: ./.github/workflows/x reaches it
		if d.Type()&fs.ModeSymlink != 0 && isEx && base != "action.yml" && base != "action.yaml" {
			return nil // not judged, but counted in symlinks
		}
		if d.Type()&fs.ModeSymlink != 0 && !workflowName && !isEx {
			st, err := fs.Stat(fsys, p)
			switch {
			case err == nil && st.IsDir():
				if p == ".github" || p == workflowsDir { // how GitHub reads these is not known
					addUnreadable(p, "a symlink to a directory: not followed, so what is in it is not known")
				} else {
					links = append(links, p)
				}
				return nil
			case err != nil && !errors.Is(err, fs.ErrNotExist):
				// an os.Root refuses a symlink out of it: it may be a directory
				addUnreadable(p, "a symlink that cannot be followed: "+err.Error())
				return nil
			case err != nil && base == "action.yml" && dir != workflowsDir:
				return nil // the runner's File.Exists is false for it: action.yaml runs
			}
		}
		add := func(k InputKind) {
			if isEx {
				in.List = append(in.List, Input{Name: facts.WalkedInputPath(p), InputKind: k, State: InputStateExcluded, Reason: "--exclude " + e.String()})
				return
			}
			in.List = append(in.List, readFile(fsys, p, k))
		}
		switch {
		case workflowName:
			if d.Type()&fs.ModeSymlink != 0 {
				in.List = append(in.List, Input{Name: facts.WalkedInputPath(p), InputKind: InputKindWorkflow, State: InputStateInvalid,
					Reason: "a symlink: GitHub makes a run of it that fails without running a job"})
				return nil
			}
			in.List = append(in.List, readFile(fsys, p, InputKindWorkflow))
		case dir != workflowsDir && base == "action.yml":
			add(InputKindActionMetadata)
		case dir != workflowsDir && base == "action.yaml":
			// the runner reads action.yml when File.Exists is true for it,
			// which is false for a directory and a symlink to nothing
			if st, err := fs.Stat(fsys, path.Join(dir, "action.yml")); err == nil && st.Mode().IsRegular() {
				return nil
			}
			add(InputKindActionMetadata)
		}
		return nil
	})
	if err != nil {
		return Inputs{}, err
	}
	walked := slices.Clone(in.List)
	for _, p := range links {
		if why, unknown := linkUnknown(fsys, p, walked, symlinks, unread); unknown {
			addUnreadable(p, why)
		}
	}
	sortInputs(in.List)
	return in, nil
}

// Files reads the files paths of fsys, and only those. A path under
// .github/workflows that GitHub would not run is still read as a workflow:
// it was asked for. Kinds are by the basename.
func Files(fsys fs.FS, paths []string) (Inputs, error) {
	var in Inputs
	seen := map[string]bool{}
	for _, p := range paths {
		c, err := facts.CleanInputPath(p)
		if err != nil {
			return Inputs{}, err
		}
		n := c.String()
		if seen[n] {
			return Inputs{}, fmt.Errorf("%s is given twice", n)
		}
		seen[n] = true
		if _, err := fs.Stat(fsys, n); err != nil {
			return Inputs{}, err
		}
		in.List = append(in.List, readFile(fsys, n, kindByName(n)))
	}
	sortInputs(in.List)
	return in, nil
}

// Single reads one Source.
func Single(s InputBytes) (Inputs, error) {
	if s.Name.IsZero() {
		return Inputs{}, errors.New("an InputBytes needs a Name")
	}
	k := s.InputKind
	if k == InputKindUnset {
		k = kindByName(s.Name.String())
	}
	return Inputs{List: []Input{read(s.Name, k, s.Bytes)}}, nil
}

func kindByName(n string) InputKind {
	if b := path.Base(n); b == "action.yml" || b == "action.yaml" {
		return InputKindActionMetadata
	}
	return InputKindWorkflow
}

func readFile(fsys fs.FS, name string, k InputKind) Input {
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return Input{Name: facts.WalkedInputPath(name), InputKind: k, State: InputStateUnreadable, Reason: err.Error()}
	}
	return read(facts.WalkedInputPath(name), k, b)
}

func read(name facts.InputPath, k InputKind, b []byte) Input {
	in := Input{Name: name, InputKind: k}
	if !utf8.ValidString(name.String()) {
		in.State, in.Reason = InputStateUnreadable, "the name is not UTF-8"
		return in
	}
	if !utf8.Valid(b) {
		in.State, in.Reason = InputStateUnreadable, "not UTF-8"
		return in
	}
	return readTree(name, k, cst.ParseMode(b, cst.ModeGitHub))
}

// readTree reads the model of t, a tree of the bytes of an input.
func readTree(name facts.InputPath, k InputKind, t *cst.Tree) Input {
	in := Input{Name: name, InputKind: k, Tree: t}
	if k == InputKindActionMetadata {
		in.ActionMetadata, in.Diagnostics = workflow.ParseActionMetadata(in.Tree)
	} else {
		in.Workflow, in.Diagnostics = workflow.Parse(in.Tree)
	}
	if len(in.Diagnostics) > 0 {
		in.State = InputStateInvalid
	}
	return in
}

func sortInputs(l []Input) {
	slices.SortFunc(l, func(a, b Input) int { return facts.CompareInputPaths(a.Name, b.Name) })
}

// maxLinks is how many symlinks realPath follows for one path, as Linux
// does before ELOOP.
const maxLinks = 40

// realPath is the directory p leads to in fsys, every symlink on the way
// followed: a target is read from the directory of its link. ok is false
// when fsys cannot read links, or the way goes out of fsys (an absolute
// target, a .. above the root), is not there, has more than maxLinks
// links, or ends at what is not a directory.
func realPath(fsys fs.FS, p string) (string, bool) {
	if _, ok := fsys.(fs.ReadLinkFS); !ok {
		return "", false // fs.Lstat would be fs.Stat, and a link would look like its target
	}
	var done []string
	todo := strings.Split(p, "/")
	hops := 0
	for len(todo) > 0 {
		e := todo[0]
		todo = todo[1:]
		switch e {
		case "", ".":
			continue
		case "..":
			if len(done) == 0 {
				return "", false
			}
			done = done[:len(done)-1]
			continue
		}
		cur := path.Join(append(slices.Clone(done), e)...)
		fi, err := fs.Lstat(fsys, cur)
		if err != nil {
			return "", false
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			done = append(done, e)
			continue
		}
		if hops++; hops > maxLinks {
			return "", false
		}
		target, err := fs.ReadLink(fsys, cur)
		if err != nil || target == "" || path.IsAbs(target) {
			return "", false
		}
		todo = append(strings.Split(target, "/"), todo...)
	}
	if len(done) == 0 {
		return ".", true
	}
	t := path.Join(done...)
	if fi, err := fs.Lstat(fsys, t); err != nil || !fi.IsDir() {
		return "", false
	}
	return t, true
}

// linkUnknown is why the symlink p to a directory is an Unreadable input,
// or false when it leads within fsys to a directory out of .git with no
// input under it, not under an input not read, and with no symlink under
// it: then there is nothing more to read through it. inputs are those the
// walk found; links, every symlink it saw, of whatever kind; unread, what
// it could not read in what is excluded, which is no input.
func linkUnknown(fsys fs.FS, p string, inputs []Input, links, unread []string) (string, bool) {
	t, ok := realPath(fsys, p)
	switch {
	case !ok:
		return "a symlink to a directory that cannot be followed within the root", true
	case slices.Contains(strings.Split(t, "/"), ".git"):
		return "a symlink into .git, which is not read", true
	}
	for _, i := range inputs {
		if under(i.Name.String(), t) {
			return "a symlink to a directory with inputs in it: they may be used by names through the link, which are not known", true
		}
		if i.State == InputStateUnreadable && under(t, i.Name.String()) {
			return "a symlink into a directory not read: what is in it is not known", true
		}
	}
	for _, u := range unread {
		if under(u, t) || under(t, u) {
			return "a symlink into a directory not read: what is in it is not known", true
		}
	}
	for _, l := range links {
		if under(l, t) {
			return "a symlink to a directory with a symlink in it: not followed, so what is in it is not known", true
		}
	}
	return "", false
}

// under is whether the path p is d or under it; every path is under ".".
func under(p, d string) bool { return d == "." || p == d || strings.HasPrefix(p, d+"/") }
