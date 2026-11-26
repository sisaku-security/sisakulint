package taint

import (
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/shell"
)

// CommandArgument is a word of a simple command of a run of bash or sh with
// a value an attacker may control in it, and how the command reads the word.
type CommandArgument struct {
	Command  string              // the command and its subcommands, such as git fetch
	Entry    *shell.CommandEntry // nil when the table does not have the command
	Word     int                 // the index of the word among the command's words
	Role     shell.ArgumentRole
	Span     expr.Span       // in the run: the ${{ }} or the variable
	Ref      ExprRef         // the reference; for a variable, what env gives it
	Path     []expr.PathElem // the reference the value comes from (ExprRef.Source): the same for a ${{ }} and for the variable a fix moves it into
	RefIndex int             // of the Sink's Refs for a ${{ }}; -1 for a variable
	Var      shell.VarName   // the variable, for one
	Head     bool            // the value is at the head of the word: nothing before it in the word, nor in each env value it went through, nor in the expression
	Quoted   bool            // the word is inside quotes, so that blanks do not split it
	// Remote is the RemoteKind of the repository the command names, for
	// a command with an option whose program runs on the remote side (git
	// fetch, clone, pull, ls-remote); RemoteKindUnknown when the command
	// names none, or its text is not known.
	Remote shell.RemoteKind
}

// arguments reads the simple commands of the run of s, a run of bash or
// sh, for the words with a ${{ }} or a variable of env in them whose value
// an attacker may control, into s.Arguments. A word read as the command or
// a wrapper is not one of them, nor an assignment.
func (c scope) arguments(s *Sink) {
	text := s.text()
	var holes []hole
	for i, p := range s.Value.Parts {
		if p.Expr {
			holes = append(holes, hole{shell.Span{Start: p.Span.Start, End: p.Span.End}, i})
		}
	}
	sc := c.readSink(s).Script
	shell.WalkSimple(sc.List, func(x *shell.Simple) {
		words := make([]shell.CommandWord, len(x.Words))
		var found []CommandArgument
		for i, w := range x.Words {
			args := c.argumentsIn(s, text, holes, w, i)
			if t, ok := shell.Literal(text, w); ok && !overlaps(w.Span, holes) {
				words[i] = shell.CommandWord{Text: t, Known: true}
			}
			for _, a := range args {
				if a.Head || !a.Quoted && len(a.Ref.Lines) > 0 {
					words[i].MayBeOption = true
				}
			}
			found = append(found, args...)
		}
		roles := shell.ArgumentRoles(words)
		for i := range found {
			// another value in the same word ("$X$Y") may hold = and blanks:
			// the word is not a repository's name alone
			if slices.ContainsFunc(found, func(o CommandArgument) bool { return o.Word == found[i].Word && o.Span != found[i].Span }) {
				found[i].Ref.DashRepoName = nil
			}
		}
		// an attacker's value in one word, inside quotes, is an option word
		// when the value begins with -, not the repository
		oneWord := func(i int) bool {
			return slices.ContainsFunc(found, func(a CommandArgument) bool { return a.Word == i && a.Head && !splits(a) })
		}
		for _, a := range found {
			a.Command, a.Entry, a.Role = roles.Name, roles.Entry, roles.Roles[a.Word]
			a.Remote = remoteOf(roles, words, oneWord, a)
			if a.Role == shell.ArgumentRoleUnread || a.Role == shell.ArgumentRoleCommand {
				continue
			}
			s.Arguments = append(s.Arguments, a)
		}
	})
}

// splits is whether the attacker may write more words than one with the
// value of a: a ${{ }}, which the runner writes into the script before the
// shell reads it, or a value outside quotes that may hold blanks; not the
// name of a repository, which holds neither blanks nor quotes.
func splits(a CommandArgument) bool {
	repoName := len(a.Ref.LeadingDash) > 0 && slices.Equal(a.Ref.DashRepoName, a.Ref.LeadingDash)
	blanks := len(a.Ref.Lines) > 0 || a.Ref.Verdict == analysis.Inconclusive
	return !repoName && (a.RefIndex >= 0 || !a.Quoted && blanks)
}

// remoteOf is the RemoteKind of the repository that the command of roles
// reads, for the argument a, when the entry of the command has an option
// whose program runs on the remote side: the first operand, past the
// attacker's values in one word (oneWord). When the first operand is not
// before a, and the attacker may write more words than one with the value
// of a, the attacker writes the repository too, and writes a local path.
func remoteOf(roles shell.CommandRoles, words []shell.CommandWord, oneWord func(int) bool, a CommandArgument) shell.RemoteKind {
	if roles.Entry == nil || !slices.ContainsFunc(roles.Entry.Options, func(o shell.CommandOption) bool { return o.Remote }) {
		return shell.RemoteKindUnknown
	}
	i, ok := roles.FirstOperand(words, oneWord)
	switch {
	case ok && i < a.Word && words[i].Known:
		return shell.RemoteKindOf(words[i].Text)
	case ok && i < a.Word:
		return shell.RemoteKindUnknown // a word before the value names the repository at run time
	case splits(a):
		return shell.RemoteKindLocal
	case ok && words[i].Known:
		return shell.RemoteKindOf(words[i].Text)
	}
	return shell.RemoteKindUnknown
}

// hole is a ${{ }} of a run: its bytes, which Masked makes letters, and the
// part of the value it is.
type hole struct {
	span shell.Span
	part int
}

func overlaps(sp shell.Span, holes []hole) bool {
	for _, h := range holes {
		if h.span.Start < sp.End && sp.Start < h.span.End {
			return true
		}
	}
	return false
}

// argumentsIn are the references of the word w, the i-th of its command,
// whose value an attacker may control: those of each ${{ }} in a literal
// part, and what env gives each variable (with an operator only when it
// keeps the value, such as ${NAME:-x}), also in the words of a ${ } that
// may become its value (shell.ParamExpansion.ValueWords).
func (c scope) argumentsIn(s *Sink, text string, holes []hole, w shell.Word, i int) []CommandArgument {
	var out []CommandArgument
	// parts reads ps, which start the word when first and are inside the
	// quotes of a ${ } when inQuotes: the parts of w, and the words of a
	// ${ } that may become its value (${X:-$V} is $V when X is empty)
	var parts func(ps []shell.Part, first, inQuotes bool)
	parts = func(ps []shell.Part, first, inQuotes bool) {
		for k, p := range ps {
			quoted := inQuotes || p.Quote != shell.QuoteNone
			starts := first && k == 0
			switch p.Kind {
			case shell.PartLiteral:
				for _, h := range holes {
					if h.span.Start < p.Span.Start || h.span.End > p.Span.End {
						continue
					}
					for ri, r := range s.Refs {
						if r.Part != h.part || r.Verdict == analysis.NotControlled {
							continue
						}
						head := starts && h.span.Start == p.Span.Start && headOf(s.Value.Parts[h.part].Tree, expr.PathString(r.Path)) && (len(r.Env) == 0 || chainHead(r))
						out = append(out, CommandArgument{Word: i, Span: expr.Span{Start: h.span.Start, End: h.span.End}, Ref: r, Path: r.Source, RefIndex: ri,
							Head: head, Quoted: quoted})
					}
				}
			case shell.PartParam, shell.PartParamOp:
				if x := p.Param; x != nil {
					for _, vw := range x.ValueWords() {
						parts(vw.Parts, starts && x.Op != shell.ParamOpReplace && x.Op != shell.ParamOpReplaceAll && x.Op != shell.ParamOpReplaceSuffix, quoted)
					}
				}
				name := p.Name.String()
				if !wholeValue(p) {
					continue
				}
				r, ok := c.varRef(name)
				if !ok || r.Verdict == analysis.NotControlled {
					continue
				}
				// a value not analyzed (Inconclusive) has no chain of env read:
				// it may start the word
				head := starts && (r.Verdict == analysis.Inconclusive || chainHead(r))
				out = append(out, CommandArgument{Word: i, Span: expr.Span{Start: p.Span.Start, End: p.Span.End}, Ref: r, Path: r.Source, RefIndex: -1, Var: p.Name,
					Head: head, Quoted: quoted})
			}
		}
	}
	parts(w.Parts, true, false)
	return out
}

// headOf is whether the value of the expression n may start with the
// value of a reference whose path is want ("" for any), or with a part of
// it: n is the reference, a || or && of operands one of which is, whose
// value is that of an operand, the value of case, a property, an index or
// a star taken of such a value, the first argument of join (whose first
// item starts the text), the argument a format string that a literal
// begins with {N} names, or the argument of fromJSON, whose value is read
// of its text.
func headOf(n expr.Node, want string) bool {
	if p, ok := expr.AccessPath(n); ok {
		return want == "" || expr.PathString(p) == want
	}
	switch x := n.(type) {
	case *expr.Logical:
		for _, o := range x.Xs {
			if headOf(o, want) {
				return true
			}
		}
	case *expr.Group:
		return headOf(x.X, want)
	case *expr.Property:
		return headOf(x.X, want)
	case *expr.Index:
		return headOf(x.X, want)
	case *expr.Star:
		return headOf(x.X, want)
	case *expr.Call:
		args := x.Args
		switch strings.ToLower(x.Name) {
		case "join", "fromjson":
			return len(args) > 0 && headOf(args[0], want)
		case "case":
			for i := 1; i < len(args); i += 2 {
				if headOf(args[i], want) {
					return true
				}
			}
			return len(args)%2 == 1 && headOf(args[len(args)-1], want)
		case "format":
			if len(args) == 0 {
				return false
			}
			l, ok := args[0].(*expr.Literal)
			if !ok || l.Kind != expr.LitString {
				return slices.ContainsFunc(args[1:], func(a expr.Node) bool { return headOf(a, want) })
			}
			i := formatHead(l.Str)
			return i >= 0 && i+1 < len(args) && headOf(args[i+1], want)
		}
	}
	return false
}

// formatHead is the number of the placeholder a format string begins
// with ({N} or {N:specifiers}), or -1 when it begins with another text.
func formatHead(f string) int {
	if !strings.HasPrefix(f, "{") || strings.HasPrefix(f, "{{") {
		return -1
	}
	n := 0
	i := 1
	for ; i < len(f) && f[i] >= '0' && f[i] <= '9'; i++ {
		if n = n*10 + int(f[i]-'0'); n > 255 {
			return -1
		}
	}
	if i == 1 || i >= len(f) || f[i] != '}' && f[i] != ':' {
		return -1
	}
	return n
}

// chainHead is whether each env value r went through starts with the
// ${{ }} of the next, and the last with that of the reference it comes
// from (r.Source), so that the variable's value starts with the attacker's.
func chainHead(r ExprRef) bool {
	if len(r.Env) == 0 {
		// a variable the runner writes (RunnerVariable) is the whole value
		// of its context
		return len(r.Source) > 0
	}
	for i, v := range r.Env {
		if len(v.Parts) == 0 || !v.Parts[0].Expr || v.Parts[0].Tree == nil {
			return false
		}
		want := ""
		if i == len(r.Env)-1 {
			want = expr.PathString(r.Source)
		}
		if !headOf(v.Parts[0].Tree, want) {
			return false
		}
	}
	return true
}
