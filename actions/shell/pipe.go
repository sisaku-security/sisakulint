package shell

import "slices"

// PipePassage is how the commands of a pipeline between a command and a
// later one pass what the first writes on to the later one.
type PipePassage uint8

const (
	PipePassageUnset PipePassage = iota
	// PipePassageVerbatim: none between, or each writes its input as it is
	// (cat with no word, tee).
	PipePassageVerbatim
	// PipePassageChanged: one between changes or cuts its input
	// (CommandTraitTransformsInput), and each other writes it as it is.
	PipePassageChanged
	// PipePassageUnknown: what one between writes of its input is not known.
	PipePassageUnknown
)

var pipePassageNames = [...]string{"PipePassageUnset", "PipePassageVerbatim", "PipePassageChanged", "PipePassageUnknown"}

func (p PipePassage) String() string { return pipePassageNames[p] }

// PipeSource is a command of a pipeline whose standard output reaches a
// later command through the pipes: its index, and how the commands between
// pass it.
type PipeSource struct {
	Element int
	Passage PipePassage
}

// elementFds is where the descriptors of the command i of p point, after
// its own redirects (those of a compound command itself, not of the
// commands in it): 0 and 1 start at the pipes, the others where the shell
// that runs the pipeline points them (not followed here: 2 to the log,
// 3 and up not open), and |& joins 2 to 1 after the redirects (bashref,
// "Pipelines").
func elementFds(s string, p *Pipeline, i int) (stdin, stdout dests) {
	r := newFdReading(s)
	if i > 0 {
		r.fds[0] = dests{{pipe: true}}
	}
	if i < len(p.Commands)-1 {
		r.fds[1] = dests{{pipe: true}}
	}
	t := r.table(ownRedirects(p.Commands[i]))
	return r.at(t, 0), r.at(t, 1)
}

// toPipe is whether one of ds is a pipe.
func toPipe(ds dests) bool {
	return slices.ContainsFunc(ds, func(d dest) bool { return d.pipe })
}

// ownRedirects are the redirects of c itself.
func ownRedirects(c Command) []Redirect {
	switch x := c.(type) {
	case *Simple:
		return x.Redirects
	case *Compound:
		return x.Redirects
	}
	return nil
}

// PipeSources are the commands of p whose standard output reaches the
// pipe into the command i, nearest first; which commands of i read that
// pipe is PipeReaders (none in bash < /dev/null, bash in
// echo $(bash) < /dev/null, whose words are expanded before its
// redirects). Going back from i, a
// command whose standard output is not the pipe (echo x > f) and a coproc,
// whose output goes to the shell, stop it, and nothing before them
// reaches; a command that digests its input (sha256sum), or does not read
// the pipe (its standard input redirected, or cat with operands none of
// which is -, /dev/stdin or /dev/fd/0), reaches, and nothing before it.
// Any other command is taken to pass its input on.
func PipeSources(script string, p *Pipeline, i int) []PipeSource {
	var out []PipeSource
	passage := PipePassageVerbatim
	for j := i - 1; j >= 0; j-- {
		c := p.Commands[j]
		if x, ok := c.(*Compound); ok && x.Kind.PipesToShell() {
			break
		}
		stdin, stdout := elementFds(script, p, j)
		if !toPipe(stdout) {
			break
		}
		out = append(out, PipeSource{Element: j, Passage: passage})
		if digests(script, c) || !toPipe(stdin) || !readsStdin(script, c) {
			break
		}
		passage = max(passage, passes(script, c))
	}
	return out
}

// entry is what the command table declares of the simple command c.
func entry(script string, c Command) *CommandEntry {
	x, ok := c.(*Simple)
	if !ok || len(x.Words) == 0 {
		return nil
	}
	return LookupCommand(WordsOf(script, x)).Entry
}

// digests is whether c writes a digest of its input, not the input.
func digests(script string, c Command) bool {
	e := entry(script, c)
	return e != nil && e.Has(CommandTraitDigestsInput)
}

// passes is how c passes its input on.
func passes(script string, c Command) PipePassage {
	if x, ok := c.(*Simple); ok && len(x.Words) > 0 {
		if n, lit := literalOf(script, x.Words[0]); lit && (base(n) == "tee" || base(n) == "cat" && len(x.Words) == 1) {
			return PipePassageVerbatim // as logwrite's copiesInput
		}
	}
	if e := entry(script, c); e != nil && e.Has(CommandTraitTransformsInput) {
		return PipePassageChanged
	}
	return PipePassageUnknown
}

// readsStdin is whether c may read its standard input: not cat with
// operands none of which is -, /dev/stdin or /dev/fd/0.
func readsStdin(script string, c Command) bool {
	x, ok := c.(*Simple)
	if !ok || len(x.Words) == 0 {
		return true
	}
	if n, lit := literalOf(script, x.Words[0]); !lit || base(n) != "cat" {
		return true
	}
	operands := false
	for _, w := range x.Words[1:] {
		n, lit := literalOf(script, w)
		switch {
		case !lit, n == "-", n == "/dev/stdin", n == "/dev/fd/0":
			return true
		case len(n) > 1 && n[0] == '-':
			continue // an option
		}
		operands = true
	}
	return !operands
}

// PipeReaders are the simple commands of c, a command of a pipeline after
// a pipe, that read the pipe on their standard input, in the order bash
// runs them: c itself, the commands in it when it is a compound command,
// and those in the scripts of their substitutions, whose standard input
// is the pipe still where bash expands them. A simple command's words and
// assignments are expanded before its own redirects (echo $(bash) <
// /dev/null: bash reads the pipe), each redirect's target after the
// redirects before it, a compound command's commands after its redirects.
// Not the commands of a coproc, whose input is a pipe from the shell, nor
// those after the first of a pipeline inside c, nor an exec with no
// command.
//
// A command reads the pipe when its standard input may be the pipe on a
// path that reaches it (fdReading): an exec that points the standard input
// elsewhere on some paths leaves the pipe on the others.
//
// unread is whether c may read the pipe otherwise, where the reading is
// not followed: case, whose words the tree does not read; the words of for
// and select and the expressions of (( )), which the tree reads but which
// are kept unread here (reading them gives new safe fixes, which no
// decision has made); a part not read (PartOpaque); and a function c
// defines, whose body runs where c calls it.
func PipeReaders(script string, c Command) (readers []*Simple, unread bool) {
	r := newFdReading(script)
	r.fds[0] = dests{{input: true}}
	Walk(script, []Command{c}, Enclosing{}, Visitor{
		Descriptors: &DescriptorReading{reading: r},
		Command: func(c Command, at Enclosing) bool {
			switch x := c.(type) {
			case *FuncDef:
				unread = true
				return false
			case *Compound:
				switch x.Kind {
				case CompoundFor, CompoundSelect, CompoundCase, CompoundArith:
					unread = true
				}
			case *Simple:
				if len(x.Words) > 0 && !isExec(script, x) && slices.ContainsFunc(r.at(r.table(x.Redirects), 0), func(d dest) bool { return d.input }) {
					readers = append(readers, x)
				}
			}
			return true
		},
		Part: func(p *Part, _ Enclosing) {
			if p.Kind == PartOpaque { // the ( ) of an array's assignment, a heredoc's body not read
				unread = true
			}
		},
	})
	return readers, unread
}
