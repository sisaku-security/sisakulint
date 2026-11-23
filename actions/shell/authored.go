package shell

import "strings"

// AuthoredCommand is a workflow command whose name is in the text of a
// script, written to the log of the step: Name is the index of its name in
// the names AuthoredCommands reads, and Span is the name in the script.
type AuthoredCommand struct {
	Name int
	Span Span
}

// AuthoredCommands are the workflow commands named by names (lowercase) of
// the writes ws of script, of a WriteOptions with Log, that the runner reads
// from the log: a line whose text starts, after white space, with ::<name>
// followed by a space or ::, or that has ##[<name> followed by a space or ]
// anywhere, the name in any case. A line begins where a command's output
// begins and after a line break of its text. The :: or ##[ and the name are
// text of the script; a value of a parameter, a ${{ }} or a command's output
// before the name is not read.
func AuthoredCommands(script string, ws []Write, names []string) []AuthoredCommand {
	var out []AuthoredCommand
	for _, w := range ws {
		if !w.Log {
			continue
		}
		head := true // only white space since the line began
		for _, o := range w.Out {
			if o.Kind != OutLit {
				head = false
				continue
			}
			at := func(i, n int) Span {
				if o.Exact && o.Span.End-o.Span.Start == len(o.Text) {
					return Span{Start: o.Span.Start + i, End: o.Span.Start + i + n}
				}
				return o.Span
			}
			text := o.Text
			for i := 0; i < len(text); i++ {
				switch {
				case text[i] == '\n':
					head = true
					continue
				case head && (text[i] == ' ' || text[i] == '\t'):
					continue
				case head && strings.HasPrefix(text[i:], "::"):
					if name, n := commandName(names, text[i+2:], "::"); n > 0 {
						out = append(out, AuthoredCommand{Name: name, Span: at(i+2, n)})
					}
				}
				if strings.HasPrefix(text[i:], "##[") {
					if name, n := commandName(names, text[i+3:], "]"); n > 0 {
						out = append(out, AuthoredCommand{Name: name, Span: at(i+3, n)})
					}
				}
				head = false
			}
		}
	}
	return out
}

// commandName is the index of the name of names that s starts with, in any
// case, followed by a space or end, and the length of the name; length 0
// for none.
func commandName(names []string, s, end string) (int, int) {
	for i, name := range names {
		if len(s) < len(name) || !strings.EqualFold(s[:len(name)], name) {
			continue
		}
		if rest := s[len(name):]; strings.HasPrefix(rest, " ") || strings.HasPrefix(rest, end) {
			return i, len(name)
		}
	}
	return 0, 0
}
