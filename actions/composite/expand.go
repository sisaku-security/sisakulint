package composite

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// MaxDepth is how deep Reader reads: the action of the step is at depth 1,
// the actions its steps run at depth 2 (the upstream's
// maxCompositeActionDepth).
const MaxDepth = 4

// Hop is a uses on the way to an action: as written, and the commit the
// answer of action.definition names; zero for an input.
type Hop struct {
	Uses   string
	Commit facts.SHA
}

// Origin is the file an action is read from: an input of the run, or the
// value of a fact (Query, an action.definition), with its tree.
type Origin struct {
	Input facts.InputPath // zero for the value of a fact
	Query facts.Query     // nil for an input
	Tree  *cst.Tree
}

// Action is an action read: the uses from the step to it (Chain, its own
// last), the file that defines it, its metadata (nil for a Dockerfile, or
// a file that is not an action.yml), where it is read from, and whether
// the archive the runner downloads differs from the blob of its file
// (export-subst; facts.ActionFile.ArchiveSubstituted).
type Action struct {
	Chain       []Hop
	File        facts.ActionFileName // unset for an input
	Metadata    *workflow.ActionMetadata
	Origin      Origin
	Substituted bool
}

// Step is a step of a composite action read: the step, the action it is
// of, the uses from the step Expand reads to that action, the file, and
// whether that action is Substituted.
type Step struct {
	Step        *workflow.Step
	Action      *workflow.ActionMetadata
	Chain       []Hop
	Origin      Origin
	Substituted bool
	// Ifs are the ifs of the steps of the composite actions between the
	// step Expand reads and this one (each runs the next action): the
	// step runs only past them, and past its own if.
	Ifs []workflow.Field[workflow.If]
}

// Unanswered is a uses of another repository that action.definition does
// not answer: the uses from the step to it (its own last, with no
// commit), whether someone asked could not answer (an unknown with a
// source: --online, or a file of facts that records one) or no one
// answered, and the reason of the answer.
type Unanswered struct {
	// Deep is whether the call is deeper than the linter reads, which no one
	// asks of a fact (Asked is true: the run reads no answer of it)
	Deep   bool
	Chain  []Hop
	Asked  bool
	Reason string
}

// Expansion is what Expand reads of a step: the actions, in the order
// read (depth first, in the order of the steps), the steps of the
// composite ones, and the uses not answered.
type Expansion struct {
	Actions    []Action
	Steps      []Step
	Unanswered []Unanswered
}

// Local looks up the action at target in the inputs of the run (a path
// from the root of the repository, "" the root; calls.TargetPaths): its
// name, tree and metadata; false when no input is an action there.
type Local func(target string) (facts.InputPath, *cst.Tree, *workflow.ActionMetadata, bool)

// Reader reads the actions steps run, asking r about the actions of other
// repositories. It may be used at once by several goroutines.
type Reader struct {
	local Local
	r     facts.Resolver

	mu        sync.Mutex
	parsed    map[facts.ActionDefinition]*parsed
	workflows map[facts.WorkflowDefinition]*parsedWorkflow
}

// parsed is the answer of an action.definition, read once.
type parsed struct {
	once   sync.Once
	answer facts.RawAnswer
	file   facts.ActionFile
	tree   *cst.Tree
	meta   *workflow.ActionMetadata
	err    bool // the value does not fit ActionFile
}

// NewReader is a Reader of the inputs local looks up and of the facts r
// answers.
func NewReader(local Local, r facts.Resolver) *Reader {
	return &Reader{local: local, r: r, parsed: map[facts.ActionDefinition]*parsed{}, workflows: map[facts.WorkflowDefinition]*parsedWorkflow{}}
}

// Expand reads the action s runs, and what the steps of a composite one
// run, to MaxDepth. inAction is whether s is a step of a composite action
// (an action.yml of the inputs), whose ./ Expand does not follow.
func (x *Reader) Expand(ctx context.Context, s *workflow.Step, inAction bool) Expansion {
	var out Expansion
	seen := map[string]bool{}
	x.expand(ctx, &out, seen, s, inAction, nil, nil)
	return out
}

// beyondDepth is the reason of an Unanswered past MaxDepth.
const beyondDepth = "deeper than the 4 levels of actions the linter reads"

func (x *Reader) expand(ctx context.Context, out *Expansion, seen map[string]bool, s *workflow.Step, inAction bool, chain []Hop, ifs []workflow.Field[workflow.If]) {
	if s.Uses.Status != workflow.Present {
		return
	}
	u := s.Uses.Value
	kind := u.Kind
	if kind == workflow.UsesFolded {
		kind = u.Folded
	}
	text := u.AsString()
	if len(chain) >= MaxDepth {
		if kind == workflow.UsesRemote {
			// an action of another repository the linter does not read: as
			// one asked with no answer, not as one with nothing in it
			out.Unanswered = append(out.Unanswered, Unanswered{Chain: hops(chain, Hop{Uses: text}), Asked: true, Reason: beyondDepth})
		}
		return
	}
	switch kind {
	case workflow.UsesLocal, workflow.UsesSelf:
		if kind == workflow.UsesLocal && inAction || !u.HasLocalPath {
			return // ./ in a composite action is the job's workspace
		}
		name, tree, meta, ok := x.local(u.LocalPath.String())
		if !ok || seen["input:"+name.String()] {
			return
		}
		seen["input:"+name.String()] = true
		a := Action{Chain: hops(chain, Hop{Uses: text}), Metadata: meta, Origin: Origin{Input: name, Tree: tree}}
		x.read(ctx, out, seen, a, ifs)
	case workflow.UsesRemote:
		for _, run := range u.Actions() {
			q, ok := definitionOf(run)
			if !ok {
				continue // not a path a fact asks about (white space, a backslash)
			}
			p := x.answer(ctx, q)
			switch {
			case p.err:
				out.Unanswered = append(out.Unanswered, Unanswered{Chain: hops(chain, Hop{Uses: text}), Asked: true, Reason: "the value of " + q.Kind().String() + " is not an action file"})
				continue
			case p.answer.State == facts.StateAbsent:
				continue // no action there: the runner fails the job
			case p.answer.State != facts.StateFound:
				out.Unanswered = append(out.Unanswered, Unanswered{Chain: hops(chain, Hop{Uses: text}), Asked: p.answer.Source != facts.SourceUnset, Reason: p.answer.Reason})
				continue
			}
			key := "remote:" + strings.ToLower(q.Repo.String()) + "/" + q.Path.String() + "@" + p.file.Commit.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			a := Action{Chain: hops(chain, Hop{Uses: text, Commit: p.file.Commit}), File: p.file.File, Metadata: p.meta,
				Origin: Origin{Query: q, Tree: p.tree}, Substituted: p.file.ArchiveSubstituted}
			x.read(ctx, out, seen, a, ifs)
		}
	}
}

// read adds a and the steps of it when it is composite, and reads what
// they run; ifs are those of the steps between (Step.Ifs).
func (x *Reader) read(ctx context.Context, out *Expansion, seen map[string]bool, a Action, ifs []workflow.Field[workflow.If]) {
	out.Actions = append(out.Actions, a)
	m := a.Metadata
	if m == nil || m.Runs.Status != workflow.Present || m.Runs.Value.Kind != workflow.RunsComposite {
		return
	}
	steps := m.Runs.Value.Steps.Value.Items
	for i := range steps {
		out.Steps = append(out.Steps, Step{Step: &steps[i], Action: m, Chain: a.Chain, Origin: a.Origin, Substituted: a.Substituted, Ifs: ifs})
		x.expand(ctx, out, seen, &steps[i], true, a.Chain, append(slices.Clone(ifs), steps[i].If))
	}
}

// answer is the answer of q, asked and parsed once for the Reader.
func (x *Reader) answer(ctx context.Context, q facts.ActionDefinition) *parsed {
	x.mu.Lock()
	p, ok := x.parsed[q]
	if !ok {
		p = &parsed{}
		x.parsed[q] = p
	}
	x.mu.Unlock()
	p.once.Do(func() {
		p.answer = facts.Checked(q, x.r.Resolve(ctx, q))
		if p.answer.State != facts.StateFound {
			return
		}
		if err := json.Unmarshal(p.answer.Value, &p.file); err != nil {
			p.err = true
			return
		}
		if p.file.File == facts.ActionFileYML || p.file.File == facts.ActionFileYAML {
			p.tree = cst.Parse([]byte(p.file.Content))
			p.meta, _ = workflow.ParseActionMetadata(p.tree)
		}
	})
	return p
}

// definitionOf is the action.definition of the action run.
func definitionOf(run workflow.UsesAction) (facts.ActionDefinition, bool) {
	repo, err := facts.ParseRepo(run.Owner + "/" + run.Repo)
	if err != nil {
		return facts.ActionDefinition{}, false
	}
	q := facts.ActionDefinition{Repo: repo, Ref: run.Ref}
	if !run.Path.IsZero() {
		if q.Path, err = facts.ParseUsesPath(run.Path.String()); err != nil {
			return facts.ActionDefinition{}, false
		}
	}
	return q, true
}

// hops is chain and h, in a new slice.
func hops(chain []Hop, h Hop) []Hop {
	out := make([]Hop, len(chain), len(chain)+1)
	copy(out, chain)
	return append(out, h)
}
