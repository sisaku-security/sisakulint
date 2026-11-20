package shell

import (
	"slices"
	"strings"
)

// ArgumentRole is how a command reads one of its words, as ArgumentRoles
// tells.
type ArgumentRole uint8

const (
	ArgumentRoleUnread      ArgumentRole = iota // the command is not known: a word before could not be read
	ArgumentRoleCommand                         // the command's name, a wrapper or a subcommand, or an option or operand of a wrapper, or an option before a subcommand
	ArgumentRoleOption                          // where the command reads a word that begins with - as an option
	ArgumentRoleOptionValue                     // the value of the option before it, which the table says takes the next word
	ArgumentRoleOperand                         // after -- (or git's --end-of-options), after the first operand of a command whose options end there, or the code of -c of a shell or python
	ArgumentRoleUndecided                       // after an option the table does not declare, with no = in it: maybe its value
)

var argumentRoleNames = [...]string{"ArgumentRoleUnread", "ArgumentRoleCommand", "ArgumentRoleOption", "ArgumentRoleOptionValue", "ArgumentRoleOperand", "ArgumentRoleUndecided"}

func (r ArgumentRole) String() string { return argumentRoleNames[r] }

// CommandRoles is what ArgumentRoles found in the words of a simple
// command.
type CommandRoles struct {
	Name  string        // the command and its subcommands as the table names them, such as git ls-remote; "" when no word names it
	Entry *CommandEntry // the deepest entry, after the wrappers; nil when the table does not have the command
	Roles []ArgumentRole
}

// ArgumentRoles is how the command of words reads each of them. It
// takes the wrappers off and goes down to the subcommand as LookupCommand
// does, but past a word whose text is not known: such a word is an argument,
// which begins with - only when the caller says it may (MayBeOption). A
// command reads options up to -- and, unless the table says it reads them
// after its operands too (OptionsAfterOperands), up to its first operand.
func ArgumentRoles(words []CommandWord) CommandRoles {
	r := CommandRoles{Roles: make([]ArgumentRole, len(words))}
	i := 0
	for {
		if i >= len(words) || !words[i].Known {
			return r // the command is not known: Unread from i on
		}
		name := base(words[i].Text)
		names := []string{name}
		r.Roles[i] = ArgumentRoleCommand
		e := commandNamed(name)
		i++
		if e == nil {
			r.Name = name
			return r.rest(nil, words, i)
		}
		if !hasSubcommands(name, e) && !e.Has(CommandTraitRunsOperand) {
			r.Name, r.Entry = name, e
			return r.rest(e, words, i) // a command of its own options and operands
		}
		// the options of e, then its subcommand (a wrapper's options, then
		// the command it runs)
		for {
			j, ok := r.options(e, words, i)
			if !ok { // an option not declared, or a word that may become one
				r.Name, r.Entry = strings.Join(names, " "), e
				return r.rest(e, words, i)
			}
			i = j
			if i < len(words) && words[i].Known {
				if sub := subcommandOf(name, e, words[i].Text); sub != nil {
					r.Roles[i] = ArgumentRoleCommand
					names = append(names, words[i].Text)
					e = sub
					i++
					if !hasSubcommands(name, e) && !e.Has(CommandTraitRunsOperand) {
						r.Name, r.Entry = strings.Join(names, " "), e
						return r.rest(e, words, i) // the subcommand's options and operands
					}
					continue
				}
			}
			break
		}
		if !e.Has(CommandTraitRunsOperand) { // a subcommand the table does not have
			r.Name, r.Entry = strings.Join(names, " "), e
			return r.rest(e, words, i)
		}
		for n := 0; n < e.Operands; n++ { // a wrapper's operands, before the command it runs
			if i >= len(words) || !words[i].Known {
				return r
			}
			r.Roles[i] = ArgumentRoleCommand
			i++
		}
		for e.Assignments && i < len(words) && words[i].Known && envAssignment(words[i].Text) {
			r.Roles[i] = ArgumentRoleCommand
			i++
		}
	}
}

// options gives the declared options of e and their values from words[i]
// on, before e's subcommand or the command a wrapper runs, the role
// Command, and is where they end; false at a word that may become an option
// or is one e does not declare (the words from there are e's own, which
// rest reads).
func (r *CommandRoles) options(e *CommandEntry, words []CommandWord, i int) (int, bool) {
	for i < len(words) {
		w := words[i]
		if w.MayBeOption {
			return i, false
		}
		if w.Known && w.Text == "--" && e.Has(CommandTraitRunsOperand) {
			r.Roles[i] = ArgumentRoleCommand // the end of a wrapper's options (sudo --)
			return i + 1, true
		}
		if !w.Known || w.Text == "--" || !strings.HasPrefix(w.Text, "-") || w.Text == "-" {
			return i, true
		}
		o, holds := e.option(w.Text)
		if o == nil {
			return i, false
		}
		r.Roles[i] = ArgumentRoleCommand
		i++
		if o.Value && !holds && i < len(words) {
			r.Roles[i] = ArgumentRoleCommand
			i++
		}
	}
	return i, true
}

// rest gives the roles of e's words from words[i] on: options before --
// (and git's --end-of-options) and before e's first operand, or after it
// too when e reads them there; e nil is a command the table does not have,
// whose options end at its first operand. The value of an option that ends
// the options (EndsOptions) ends them, and a command that reads its
// arguments by their number (OperandsOnly) has operands only. An option
// the table does not declare takes no value when the table declares every
// option of e that takes one (ValueOptionsComplete).
func (r CommandRoles) rest(e *CommandEntry, words []CommandWord, i int) CommandRoles {
	end := e != nil && e.OperandsOnly // after -- or the first operand of a command whose options end there
	value := false                    // the word is the value of the option before it
	endAfter := false                 // and the options end after it (-c of a shell or python)
	afterOptions := false             // and the value is the first word after it that is not an option (-c of a shell: bash -c -x code)
	var code *CommandOption           // that option
	values := 0                       // the words before it that are the values of other options (bash -c -o pipefail code)
	undecided := false
	for ; i < len(words); i++ {
		w := words[i]
		switch {
		case end:
			r.Roles[i] = ArgumentRoleOperand
		case value && afterOptions && values > 0:
			r.Roles[i], values = ArgumentRoleOptionValue, values-1
		case value && afterOptions && shellOptionWord(w):
			r.Roles[i] = ArgumentRoleOption // bash -c -x code: -x is an option, and the code is still to come
			if w.Text == "--" || w.Text == "-" {
				afterOptions = false // the next word is the code
			} else {
				values = e.optionValues(w.Text, code)
			}
		case value && endAfter:
			// the code of -c of a shell or python: the operand the options
			// end at, whose words are code, not options
			r.Roles[i], value, end = ArgumentRoleOperand, false, true
		case value:
			r.Roles[i], value = ArgumentRoleOptionValue, false
		case undecided:
			// the value of an option the table does not declare, or not: a
			// -- here may end the options or be that value, so what comes
			// after it is not decided either
			// and for a command whose options end at its first operand, it
			// may be that operand: what comes after is not decided either
			r.Roles[i] = ArgumentRoleUndecided
			undecided = w.Known && (w.Text == "--" || w.Text == "--end-of-options") || e == nil || !e.OptionsAfterOperands
		case w.Known && (w.Text == "--" || w.Text == "--end-of-options" && e != nil && slices.Contains(e.Names, "git")):
			r.Roles[i], end = ArgumentRoleOption, true
		case w.Known && strings.HasPrefix(w.Text, "-") && w.Text != "-":
			r.Roles[i] = ArgumentRoleOption
			var o *CommandOption
			holds := false
			if e != nil {
				o, holds = e.option(w.Text)
			}
			switch {
			case o != nil && o.Value && !holds:
				value, endAfter, afterOptions = true, o.EndsOptions, o.Cluster && !o.Joined
				if afterOptions {
					code, values = o, e.optionValues(w.Text, o)
				}
			case o != nil && holds && o.EndsOptions:
				end = true
			case o == nil && !strings.Contains(w.Text, "=") && (e == nil || !e.ValueOptionsComplete):
				undecided = true
			}
		default: // an operand, or a word whose text is not known
			r.Roles[i] = ArgumentRoleOption
			if !w.MayBeOption && (e == nil || !e.OptionsAfterOperands) {
				end = true
			}
		}
	}
	return r
}

// WalkSimple calls f with each simple command of cs, in the order bash
// runs them (Walk): those in lists, pipelines, and-or lists, the bodies of
// compound commands and functions, and the scripts inside $( ), <( ) and
// >( ) of their words, of the targets of their redirects and of their
// heredocs' bodies.
func WalkSimple(cs []Command, f func(*Simple)) {
	Walk("", cs, Enclosing{}, Visitor{Command: func(c Command, _ Enclosing) bool {
		if x, ok := c.(*Simple); ok {
			f(x)
		}
		return true
	}})
}
