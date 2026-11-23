package shell

import "strings"

// CommandWord is a word of a simple command, for LookupCommand: its text as
// the shell makes it, when the word is of literals only. A word with an
// expansion in it ($x, $( ), or a place the caller fills, such as a ${{ }})
// is not Known.
type CommandWord struct {
	Text  string
	Known bool
	// MayBeOption: the text is not known and may begin with -, as a value
	// an attacker writes may. ArgumentRoles reads it; LookupCommand does not.
	MayBeOption bool
	// Prefix is, for a word whose text is not known, the literal text
	// before what is not known (-H in -H"$X"): RequestRoles reads an option
	// joined to its value by it.
	Prefix string
}

// WordsOf is the words of the simple command s of script, for
// LookupCommand.
func WordsOf(script string, s *Simple) []CommandWord {
	out := make([]CommandWord, len(s.Words))
	for i, w := range s.Words {
		t, ok := literalOf(script, w)
		out[i] = CommandWord{Text: t, Known: ok}
	}
	return out
}

// MatchExtent is how far LookupCommand read the words of a command.
type MatchExtent uint8

const (
	MatchNone     MatchExtent = iota // commands.json has no entry of the command's name
	MatchStopped                     // a word not known, an option not declared, or no command after the wrappers: it read no further
	MatchComplete                    // it read every word
)

var matchExtentNames = [...]string{"MatchNone", "MatchStopped", "MatchComplete"}

func (x MatchExtent) String() string { return matchExtentNames[x] }

// CommandMatch is what LookupCommand found in the words of a command.
type CommandMatch struct {
	Entry    *CommandEntry   // the deepest entry of the command run, after the wrappers; nil when it read none
	Wrappers []*CommandEntry // the runs-operand entries taken off, in order
	Extent   MatchExtent
	Readings []ArgumentReading // by the index of the words: how the command reads each; unset for data
	// Command is the index of the word that names the command run after
	// the wrappers, the last LookupCommand looked at, known or not; -1 when
	// no word is left after them
	Command int
}

// LookupCommand finds, in the words of a simple command, the entry of the
// command it runs: it takes the runs-operand entries off with their
// options, operands and assignments (timeout 30 npm test runs npm test),
// passes over the declared options of a command (git -C dir push), and goes
// down to the subcommand the next word names. It stops at a word not known
// and at an option the entry does not declare, as it cannot tell whether
// the word after such an option is its value. The words of a command name
// are matched by their last element (/usr/bin/git is git).
func LookupCommand(words []CommandWord) CommandMatch {
	m := CommandMatch{Readings: make([]ArgumentReading, len(words))}
	i := 0
	for {
		m.Command = i
		if i >= len(words) {
			m.Command = -1
		}
		if i >= len(words) || !words[i].Known {
			m.Extent = MatchStopped
			return m
		}
		name := base(words[i].Text)
		e := commandNamed(name)
		if e == nil {
			m.Extent = MatchNone
			return m
		}
		i++
		for {
			j, ok := m.options(e, words, i)
			if !ok {
				m.Entry, m.Extent = e, MatchStopped
				return m
			}
			i = j
			if i < len(words) && words[i].Known {
				if sub := subcommandOf(name, e, words[i].Text); sub != nil {
					e = sub
					i++
					continue
				}
			}
			break
		}
		if !e.Has(CommandTraitRunsOperand) {
			m.Entry = e
			if i < len(words) && hasSubcommands(name, e) {
				m.Extent = MatchStopped // a subcommand commands.json does not declare (git rebase)
				return m
			}
			return m.rest(e, words, i)
		}
		m.Wrappers = append(m.Wrappers, e)
		for n := 0; n < e.Operands; n++ {
			if i >= len(words) || !words[i].Known {
				m.Extent = MatchStopped
				return m
			}
			i++
		}
		for e.Assignments && i < len(words) && words[i].Known && envAssignment(words[i].Text) {
			i++
		}
	}
}

// options reads the declared options of e from words[i] on, and is where
// they end; false when it meets a word not known or an option e does not
// declare.
func (m *CommandMatch) options(e *CommandEntry, words []CommandWord, i int) (int, bool) {
	for i < len(words) {
		w := words[i]
		if !w.Known {
			return i, false
		}
		if w.Text == "--" || !strings.HasPrefix(w.Text, "-") || w.Text == "-" {
			return i, true
		}
		o, holds := e.option(w.Text)
		if o == nil {
			return i, false
		}
		i = m.read(o, holds, i, len(words))
	}
	return i, true
}

// read gives the value of the option o at the word i its reading: the word
// itself when it holds the value, else the next; and is the index after
// them.
func (m *CommandMatch) read(o *CommandOption, holds bool, i, n int) int {
	switch {
	case holds:
		m.Readings[i] = o.Reading
		return i + 1
	case o.Value:
		if i+1 < n {
			m.Readings[i+1] = o.Reading
		}
		return i + 2
	}
	return i + 1
}

// rest reads the words of e from words[i] on: its options, wherever they
// are, until --; its arguments, code for code-arguments.
func (m CommandMatch) rest(e *CommandEntry, words []CommandWord, i int) CommandMatch {
	operands := false // after --
	for i < len(words) {
		w := words[i]
		if !w.Known {
			m.Extent = MatchStopped
			return m
		}
		switch {
		case !operands && w.Text == "--":
			operands = true
			i++
			continue
		case !operands && strings.HasPrefix(w.Text, "-") && w.Text != "-":
			o, holds := e.option(w.Text)
			if o == nil {
				m.Extent = MatchStopped
				return m
			}
			i = m.read(o, holds, i, len(words))
			continue
		}
		if e.Has(CommandTraitCodeArguments) {
			m.Readings[i] = ArgumentReadingCode
		}
		i++
	}
	m.Extent = MatchComplete
	return m
}
