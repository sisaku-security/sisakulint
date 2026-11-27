package ir

import (
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

func (x *IR) allSinks() []*Sink {
	x.once(SummarySink, func() {
		a := taint.AnalyzeIn(x.callersOf(), x.name, x.workflow, x.action, x.scripts)
		x.analyzed++
		var out []*Sink
		for _, s := range a.Sinks {
			out = append(out, x.projectSink(s))
		}
		x.analysis, x.sinks = a, out
	})
	return x.sinks
}

// projectSink is the projection of the projectSink s: its values without their
// positions and pointers, which the handles keep.
func (x *IR) projectSink(s taint.Sink) *Sink {
	text := s.Value.Text()
	out := &Sink{key: keyOf(x.paths, x.input, x.tree, s.Value.Base),
		alwaysSkipped: x.alwaysSkipped(s.Value.Base), forkPullRequestOnly: x.forkPullRequestOnly(s.Value.Base), at: x.handleOf(s.Value.Base), kind: s.Kind}
	var places []shell.Place // of the ${{ }} of the script, read once
	for _, r := range s.Refs {
		e := x.exprRefOf(r, text[r.Span.Start:r.Span.End], x.spanOf(s.Value, r.Span))
		e.QuotedJSON = r.Verdict == analysis.Controlled && x.quotedJSON(s, r, &places)
		out.refs = append(out.refs, e)
	}
	for _, w := range s.EnvironmentFileWrites {
		o := EnvironmentFileWrite{File: w.File, Side: w.Side, Text: text[w.Span.Start:w.Span.End], RefIndex: w.RefIndex, At: x.spanOf(s.Value, w.Span), start: w.Span.Start}
		r := w.Env
		if w.RefIndex >= 0 {
			r = s.Refs[w.RefIndex]
		} else {
			o.Var = x.exprRefOf(w.Env, o.Text, o.At)
		}
		o.Reach = taint.Reach(w.Side, r)
		out.environmentFileWrites = append(out.environmentFileWrites, o)
	}
	for _, g := range s.InconclusiveWrites {
		out.inconclusiveWrites = append(out.inconclusiveWrites, InconclusiveWrite{File: g.File, Kind: g.Kind, At: x.spanOf(s.Value, g.Span)})
	}
	for _, a := range s.Arguments {
		out.arguments = append(out.arguments, x.commandArgumentOf(s, a, text))
	}
	for _, c := range s.AuthoredCommands {
		out.authoredCommands = append(out.authoredCommands, AuthoredCommand{Command: c.Name, At: x.spanOf(s.Value, expr.Span{Start: c.Span.Start, End: c.Span.End})})
	}
	for _, r := range s.Requests {
		out.requests = append(out.requests, x.requestSiteOf(s, r, text))
	}
	for _, l := range s.SecretLeaks {
		out.secretLeaks = append(out.secretLeaks, x.secretLeakOf(s, l))
	}
	out.unsecureFlag, out.unsecureFlagPlace = s.UnsecureFlag.State, s.UnsecureFlag.Place
	out.hasStepId, out.hasStepAfter = s.HasStepID, s.HasStepAfter
	for _, w := range s.LogWrites {
		out.logWrites = append(out.logWrites, x.logWriteOf(s, w, text))
	}
	for _, v := range s.VariableCodes {
		out.variableCodes = append(out.variableCodes, x.variableCodeOf(s, v, text))
	}
	if n := s.CallsNotRead; n.OK {
		out.callsNotRead = []CallsNotRead{{At: x.spanOf(s.Value, expr.Span{Start: n.At.Start, End: n.At.End})}}
	}
	return out
}

// variableCodeOf is the projection of v, a variable the run s, whose text
// is text, reads as code.
func (x *IR) variableCodeOf(s taint.Sink, v taint.VariableCode, text string) VariableCode {
	o := VariableCode{Text: text[v.Span.Start:v.Span.End], Reading: v.Reading, At: x.spanOf(s.Value, v.Span), Path: expr.PathString(v.Ref.Source)}
	o.Ref = x.exprRefOf(v.Ref, o.Text, o.At)
	return o
}

// commandArgumentOf is the projection of a, an argument of the run s whose
// text is text.
func (x *IR) commandArgumentOf(s taint.Sink, a taint.CommandArgument, text string) CommandArgument {
	at := x.spanOf(s.Value, a.Span)
	// a value not analyzed may hold blanks; a ${{ }} the runner writes into
	// the script before the shell reads it, so that an attacker writes
	// quotes and blanks too, and any spelling: the same or
	// more than the variable code-injection's fix moves it into
	inconclusive := a.Ref.Verdict == analysis.Inconclusive
	blanks := len(a.Ref.Lines) > 0 || inconclusive
	// a repository's name holds neither blanks nor quotes, and splits into
	// no words
	repoName := !inconclusive && len(a.Ref.LeadingDash) > 0 && slices.Equal(a.Ref.DashRepoName, a.Ref.LeadingDash)
	split := !repoName && (!a.Quoted && blanks || a.RefIndex >= 0) // the words after the first are at the place of options
	o := CommandArgument{Command: a.Command, Known: a.Entry != nil, Word: a.Word, Path: expr.PathString(a.Path),
		LeadingDash: a.Ref.LeadingDash, DashUndecided: a.Ref.DashUndecided, Head: a.Head, Blanks: blanks, Quoted: a.Quoted, At: at,
		Ref:       x.exprRefOf(a.Ref, text[a.Span.Start:a.Span.End], at),
		Undecided: a.Role == shell.ArgumentRoleUndecided}
	switch a.Role {
	case shell.ArgumentRoleOption, shell.ArgumentRoleUndecided:
		o.OptionPlace = a.Head || split
	case shell.ArgumentRoleOptionValue:
		o.OptionPlace = split
	}
	o.RepoName = repoName
	if a.Entry != nil {
		can := spellingsOf(blanks, a.Quoted)
		switch {
		case o.RepoName:
			// a repository's name holds no = and no blanks: wherever the
			// value is, the attacker writes only
			// letters, digits, ., - and _
			can = []shell.AttackSpelling{shell.AttackSpellingNameCharacters}
		case a.RefIndex >= 0:
			can = []shell.AttackSpelling{shell.AttackSpellingWithBlanks, shell.AttackSpellingWithoutBlanks, shell.AttackSpellingTwoWords}
		}
		o.Spelled, o.Remote, o.Unverified, o.Runs = judgeOptions(a.Entry.Options, can, a.Remote)
		o.RemoteSSH = o.Remote && a.Remote == shell.RemoteKindSSH
	}
	return o
}

// spellingsOf are the attack spellings an attacker writes with a value
// that can hold blanks or not, inside quotes or not: a value inside quotes
// stays one word; one outside quotes splits at its blanks into words with
// none.
func spellingsOf(blanks, quoted bool) []shell.AttackSpelling {
	switch {
	case !blanks:
		return []shell.AttackSpelling{shell.AttackSpellingWithoutBlanks}
	case quoted:
		return []shell.AttackSpelling{shell.AttackSpellingWithBlanks, shell.AttackSpellingWithoutBlanks}
	}
	return []shell.AttackSpelling{shell.AttackSpellingWithoutBlanks, shell.AttackSpellingTwoWords}
}

// judgeOptions is what the options of a command that run a program make of
// a value an attacker writes in the spellings can: those seen to run the
// program in one of them, as the attacker writes them (the long spelling
// with = for one word, the spelling alone for two), with those whose
// program runs on the remote side only for a repository on a local path
// (at), where it runs on the runner; whether such an option can be written
// where the repository is not on a local path nor of HTTPS (remote);
// whether some spelling of an option is neither seen to run the program
// nor seen not to; and whether any option runs a program. The spelling of
// a repository's name (AttackSpellingNameCharacters) writes no long
// option, which needs =, and no two words: only a short option with its
// value joined to it.
func judgeOptions(options []shell.CommandOption, can []shell.AttackSpelling, at shell.RemoteKind) (spelled []string, remote, unverified, runs bool) {
	for i := range options {
		o := &options[i]
		if !o.Runs() {
			continue
		}
		runs = true
		for _, sp := range can {
			name := sp == shell.AttackSpellingNameCharacters
			if name && (!o.Joined || !slices.ContainsFunc(o.Spellings, isShortSpelling)) {
				continue
			}
			switch {
			case o.Remote && at == shell.RemoteKindHTTPS:
				// git does not use the program for HTTPS, in any spelling
			case slices.Contains(o.Attack, sp) && o.Remote && at != shell.RemoteKindLocal:
				remote = true
			case slices.Contains(o.Attack, sp):
				w := o.Spellings[0]
				if name {
					w = o.Spellings[slices.IndexFunc(o.Spellings, isShortSpelling)]
				}
				if sp != shell.AttackSpellingTwoWords && strings.HasPrefix(w, "--") {
					w += "="
				}
				if !slices.Contains(spelled, w) {
					spelled = append(spelled, w)
				}
			case !slices.Contains(o.Harmless, sp):
				unverified = true
			}
		}
	}
	return spelled, remote, unverified, runs
}

// isShortSpelling is whether s is a short option (-e), which takes its
// value joined in the same word without =.
func isShortSpelling(s string) bool { return len(s) == 2 && s[0] == '-' && s[1] != '-' }

// exprRefOf is the projection of r, whose text is t at at.
func (x *IR) exprRefOf(r taint.ExprRef, t string, at Handle) ExprRef {
	e := ExprRef{Text: t, Verdict: r.Verdict, ControlledOn: r.ControlledOn, InconclusiveKind: r.InconclusiveKind, At: at, part: r.Part}
	for _, v := range r.Env {
		e.Env = append(e.Env, x.envAt(v))
	}
	for _, v := range r.With {
		e.With = append(e.With, x.viaAt(v))
	}
	for _, v := range r.OtherCallers {
		e.OtherCallers = append(e.OtherCallers, x.viaAt(v))
	}
	return e
}

// viaAt is where the value of v is: its ${{ }}, or the whole value, in
// the input v is of. It makes no edit.
func (x *IR) viaAt(v taint.Via) Handle {
	f, _ := x.callersOf().Graph().File(v.Node)
	h := Handle{input: v.Node.String(), tree: f.Tree, base: v.Value.Base, exact: true}
	if r, ok := v.Node.Remote(); ok {
		h.input, h.query = "", r.Called.Origin.Query
	}
	for _, p := range v.Value.Parts {
		if p.Expr {
			h.value, h.span, h.spanned = v.Value.Value, p.Span, true
			h.src, h.exact = v.Value.Source(p.Span)
			break
		}
	}
	return h
}

// envAt is where the value v of an env is: its ${{ }}, or the whole value.
func (x *IR) envAt(v workflow.String) Handle {
	for _, p := range v.Parts {
		if p.Expr {
			return x.spanOf(v, p.Span)
		}
	}
	return x.handleOf(v.Base)
}

// quotedJSON is jsonInQuotedHeredoc of code-injection, moved here: whether
// the ${{ }} of r is toJson(...) as a whole, in the body of a heredoc of a
// bash or sh run whose delimiter is quoted:
// the shell takes the body as it is, and no line toJson writes can be the
// delimiter that would end it. toJson escapes a string's line breaks, and
// every line of it but the first and the last starts with spaces; the first
// is {, [ or one value, and the last } or ]. places is filled on the first
// call for s.
func (x *IR) quotedJSON(s taint.Sink, r taint.ExprRef, places *[]shell.Place) bool {
	pt := s.Value.Parts[r.Part]
	call, ok := pt.Tree.(*expr.Call)
	if !ok || !expr.EqualName(call.Name, "toJson") || len(call.Args) != 1 || s.Kind != analysis.SinkRun || s.Shell != taint.ShellBash && s.Shell != taint.ShellSh {
		return false
	}
	if *places == nil {
		*places = taint.ReadScript(x.scripts, s.Value).Places
	}
	i := 0 // the index of pt among the ${{ }} of the value
	for _, p := range s.Value.Parts[:r.Part] {
		if p.Expr {
			i++
		}
	}
	p := (*places)[i]
	d := p.Delim.String()
	return p.Quoting == shell.QuotedHeredoc && d != "" && !strings.ContainsRune(" \t{}[]\"", rune(d[0]))
}
