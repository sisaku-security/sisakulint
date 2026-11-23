package workflow

import (
	"os"
	"testing"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/internal/corpus"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// TestCorpusRobust reads every file of the corpus: Parse must not panic,
// and every span of the diagnostics and of the model must lie in the
// input.
func TestCorpusRobust(t *testing.T) {
	files := corpus.Files(t)
	for _, f := range files {
		src, err := os.ReadFile(f.Path)
		if err != nil {
			t.Fatal(err)
		}
		w, diags := Parse(cst.ParseMode(src, cst.ModeGitHub))
		for _, d := range diags {
			for _, s := range append([]cst.Span{d.Span}, d.Related...) {
				checkSpan(t, f.Rel, len(src), s)
			}
		}
		walkModel(w, func(s cst.Span) { checkSpan(t, f.Rel, len(src), s) })
		a, diags := ParseActionMetadata(cst.ParseMode(src, cst.ModeGitHub))
		for _, d := range diags {
			for _, s := range append([]cst.Span{d.Span}, d.Related...) {
				checkSpan(t, f.Rel, len(src), s)
			}
		}
		walkAction(a, func(s cst.Span) { checkSpan(t, f.Rel, len(src), s) })
	}
	t.Logf("%d files", len(files))
}

// TestCorpusNoFalseDiagnostics reads the workflows and the action.yml files
// that run on GitHub: the model must not report what GitHub accepts.
// Syntax errors are cst's. The group sisakuintel is not read here: it has
// workflows that GitHub rejects (yaml/corpus/README.md).
func TestCorpusNoFalseDiagnostics(t *testing.T) {
	files := corpus.Files(t, "files/real-world/", "files/org/")
	n := 0
	for _, f := range files {
		if f.Kind != corpus.KindWorkflow && f.Kind != corpus.KindAction {
			continue
		}
		n++
		src, err := os.ReadFile(f.Path)
		if err != nil {
			t.Fatal(err)
		}
		tr := cst.ParseMode(src, cst.ModeGitHub)
		var diags []Diagnostic
		if f.Kind == corpus.KindAction {
			_, diags = ParseActionMetadata(tr)
		} else {
			_, diags = Parse(tr)
		}
		for _, d := range diags {
			p := tr.Position(d.Span.Start)
			t.Errorf("%s:%d:%d: %v %s", f.Rel, p.Line, p.Column, d.Code, d.Msg)
		}
	}
	t.Logf("%d workflows and actions", n)
}

func checkSpan(t *testing.T, file string, n int, s cst.Span) {
	t.Helper()
	if s.Start < 0 || s.End > n || s.Start > s.End {
		t.Errorf("%s: span %v outside the input of %d bytes", file, s, n)
	}
}

// walkModel calls f with the spans of the elements of w that rules report
// at: nodes, aliases, and the input ranges of values and their pieces.
func walkModel(w *Workflow, f func(cst.Span)) {
	m := spanWalker(f)
	m.base(w.Base)
	m.str(w.Name.Value)
	m.str(w.RunName.Value)
	m.strMap(w.Env.Value)
	for _, e := range w.On.Value.Events {
		m.base(e.Base)
		m.str(e.Name)
	}
	for _, s := range w.Permissions.Value.Scopes {
		m.str(s.Name)
		m.str(s.Access)
	}
	for _, je := range w.Jobs.Value.Entries {
		j := je.Value.Value
		m.base(j.Base)
		m.str(j.ID)
		m.str(j.If.Value.String)
		m.strMap(j.Env.Value)
		m.strMap(j.With.Value)
		m.uses(j.Uses.Value)
		m.steps(j.Steps.Value)
		cs := []Container{j.Container.Value}
		for _, e := range j.Services.Value.Entries {
			m.str(e.Key)
			cs = append(cs, e.Value.Value)
		}
		for _, c := range cs {
			m.base(c.Base)
			m.str(c.Image.Value)
			m.str(c.Username.Value)
			m.str(c.Password.Value)
		}
	}
}

// walkAction is walkModel for an action.
func walkAction(a *ActionMetadata, f func(cst.Span)) {
	m := spanWalker(f)
	m.base(a.Base)
	m.str(a.Name.Value)
	m.str(a.Description.Value)
	for _, e := range a.Inputs.Value.Entries {
		in := e.Value.Value
		m.str(e.Key)
		m.base(in.Base)
		for _, s := range []Field[String]{in.Description, in.Required, in.Default, in.DeprecationMessage} {
			m.str(s.Value)
		}
	}
	for _, e := range a.Outputs.Value.Entries {
		m.str(e.Key)
		m.base(e.Value.Value.Base)
		m.str(e.Value.Value.Value.Value)
	}
	r := a.Runs.Value
	m.base(r.Base)
	for _, s := range []Field[String]{r.Using, r.Main, r.Pre, r.Post, r.Image, r.Entrypoint, r.PreEntrypoint, r.PostEntrypoint, r.PreIf, r.PostIf, r.Plugin} {
		m.str(s.Value)
	}
	for _, s := range r.Args.Value.Items {
		m.str(s)
	}
	m.strMap(r.Env.Value)
	m.steps(r.Steps.Value)
}

type walker struct {
	base   func(Base)
	str    func(String)
	strMap func(Map[String])
	uses   func(Uses)
	steps  func(List[Step])
}

func spanWalker(f func(cst.Span)) walker {
	base := func(b Base) {
		if b.Node != (cst.Node{}) {
			f(b.Node.Span())
		}
		for _, v := range b.Via {
			f(v.Span())
		}
	}
	str := func(s String) {
		base(s.Base)
		if s.Node == (cst.Node{}) {
			return
		}
		sp, _ := s.Source(expr.Span{Start: 0, End: len(s.Text())})
		f(sp)
		for _, p := range s.Parts {
			sp, _ := s.Source(p.Span)
			f(sp)
		}
	}
	strMap := func(m Map[String]) {
		base(m.Base)
		for _, e := range m.Entries {
			str(e.Key)
			str(e.Value.Value)
		}
	}
	uses := func(u Uses) {
		str(u.String)
		for _, p := range []Piece{u.Owner, u.Repo, u.Path, u.Ref, u.Image, u.Tag, u.Digest} {
			if p.Text != "" {
				sp, _ := u.Source(p.Span)
				f(sp)
			}
		}
	}
	steps := func(l List[Step]) {
		base(l.Base)
		for _, s := range l.Items {
			base(s.Base)
			str(s.Run.Value)
			str(s.If.Value.String)
			uses(s.Uses.Value)
			strMap(s.With.Value)
			strMap(s.Env.Value)
		}
	}
	return walker{base, str, strMap, uses, steps}
}
