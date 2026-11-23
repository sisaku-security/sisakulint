package workflow

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/expr"
)

func TestCondition(t *testing.T) {
	for _, tt := range []struct {
		ifv  string
		form IfForm
		expr string // the input under the expression, "" for none
		want []Code
	}{
		{"${{ github.a == 'b' }}", IfExpr, "github.a == 'b'", nil},
		// white space around one expression is no text.
		{"\"${{ false }} \"", IfExpr, "false", nil},
		{"github.a == 'b'", IfBare, "github.a == 'b'", nil},
		{"\"  github  \"", IfBare, "github", nil},
		// GitHub reads it as format(), a string that is true.
		{"x ${{ github }}", IfMixed, "", nil},
		{"", IfEmpty, "", nil},
		{"\"\"", IfEmpty, "", nil},
		{"a ==", IfBare, "", []Code{ExprSyntax}},
		{"${{ a == }}", IfExpr, "", []Code{ExprSyntax}},
	} {
		src := "steps:\n  - if: " + tt.ifv + "\n    run: a\n"
		f, diags := readSteps(t, src)
		wantCodes(t, tt.ifv, diags, tt.want...)
		c := f.Value.Items[0].If.Value
		if c.Form != tt.form {
			t.Errorf("if: %s: form %v, want %v", tt.ifv, c.Form, tt.form)
			continue
		}
		if tt.expr == "" {
			continue
		}
		if c.Expr == nil || c.Expr.Tree == nil {
			t.Errorf("if: %s: no expression", tt.ifv)
			continue
		}
		sp, _ := c.Source(c.Expr.InValue(c.Expr.Tree.Span()))
		if text(src, sp) != tt.expr {
			t.Errorf("if: %s: expression at %q, want %q", tt.ifv, text(src, sp), tt.expr)
		}
	}
}

func TestConditionTree(t *testing.T) {
	src := "steps:\n  - if: github.event.pull_request.head.repo.fork\n    run: a\n"
	f, _ := readSteps(t, src)
	c := f.Value.Items[0].If.Value
	p, ok := expr.AccessPath(c.Expr.Tree)
	if !ok || len(p) != 6 {
		t.Errorf("path %+v", p)
	}
}

// TestConditionFolded: GitHub folds an if of exactly ${{ 'x' }} into the
// string x and reads x as the expression, in a job and in a step of a
// workflow as in an action.yml; with text around the ${{ }}, it does not fold
// the literal.
func TestConditionFolded(t *testing.T) {
	type tree uint8
	const (
		anyTree tree = iota
		falseTree
		alwaysCall
		stringTree
	)
	for _, tt := range []struct {
		job    bool
		ifv    string
		form   IfForm
		folded bool
		tree   tree
		want   []Code
	}{
		{true, `"${{ 'false' }}"`, IfBare, true, falseTree, nil},
		{false, `"${{ 'false' }}"`, IfBare, true, falseTree, nil},
		{true, `"${{ 'always()' }}"`, IfBare, true, alwaysCall, nil},
		{false, `"${{ 'always()' }}"`, IfBare, true, alwaysCall, nil},
		{true, `"${{ 'abc' }}"`, IfBare, true, anyTree, []Code{ExprSyntax}},
		{false, `"${{ 'abc' }}"`, IfBare, true, anyTree, []Code{ExprSyntax}},
		// a step's if has no secrets context (step-if)
		{false, `"${{ 'secrets.X != ''''' }}"`, IfBare, true, anyTree, []Code{ExprSyntax}},
		{true, `"${{ ' ' }}"`, IfEmpty, false, anyTree, nil},
		{true, `"${{ '' }}"`, IfEmpty, false, anyTree, nil},
		{true, `" ${{ 'false' }} "`, IfExpr, false, stringTree, nil},
		{true, `${{ false }}`, IfExpr, false, falseTree, nil},
		// a bare if is IfBare, and its spans are in the value
		{true, `github.actor == 'a'`, IfBare, false, anyTree, nil},
	} {
		src := "on: push\njobs:\n  a:\n    runs-on: x\n"
		if tt.job {
			src += "    if: " + tt.ifv + "\n    steps:\n      - run: a\n"
		} else {
			src += "    steps:\n      - run: a\n        if: " + tt.ifv + "\n"
		}
		w, diags, _ := parse(t, src)
		wantCodes(t, src, diags, tt.want...)
		if len(diags) == 1 {
			if got := text(src, diags[0].Span); got != tt.ifv {
				t.Errorf("%s: reported at %q, want the whole value", tt.ifv, got)
			}
		}
		j := w.Jobs.Value.Entries[0].Value.Value
		f := j.If
		if !tt.job {
			f = j.Steps.Value.Items[0].If
		}
		c := f.Value
		if c.Form != tt.form || c.Folded() != tt.folded {
			t.Errorf("job %v, if: %s: form %v, folded %v; want %v, %v", tt.job, tt.ifv, c.Form, c.Folded(), tt.form, tt.folded)
			continue
		}
		var got expr.Node
		if c.Expr != nil {
			got = c.Expr.Tree
		}
		ok := true
		switch tt.tree {
		case falseTree:
			l, isLit := got.(*expr.Literal)
			ok = isLit && l.Kind == expr.LitBool && l.Raw == "false"
		case alwaysCall:
			call, isCall := got.(*expr.Call)
			ok = isCall && call.Name == "always"
		case stringTree:
			l, isLit := got.(*expr.Literal)
			ok = isLit && l.Kind == expr.LitString
		}
		if !ok {
			t.Errorf("job %v, if: %s: tree %#v", tt.job, tt.ifv, got)
		}
	}
}
