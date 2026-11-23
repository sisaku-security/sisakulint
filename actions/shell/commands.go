package shell

//go:generate go run github.com/gh-intel/sisakulint/actions/internal/enumgen -pkg shell -out enum_gen.go schema/commands.json
//go:generate go run ./internal/commandgen

import (
	"regexp"
	"slices"
	"strings"
)

// CommandTrait is what a command does when it runs, as commands.json
// declares it for an entry. Its values are $defs/command-trait of
// schema/commands.json.
type CommandTrait uint8

// ArgumentReading is how a command reads the value of one of its options:
// as code, or as the program to run. A value with no reading is data. Its
// values are $defs/argument-reading of schema/commands.json.
type ArgumentReading uint8

// AttackSpelling is how an attacker writes an option with its value: in one
// word with blanks in it (a value inside quotes), in one word without (a
// branch's name, or a value outside quotes, which the shell splits at
// blanks), or as two words (a value outside quotes split at a blank). Its
// values are $defs/attack-spelling of schema/commands.json.
type AttackSpelling uint8

// RequestReading is what a word of a command that sends a request is to
// the request: the URL it goes to, the path of an API of the command's
// host (gh api), the host, or what it carries there. Its values are
// $defs/request-reading of schema/commands.json.
type RequestReading uint8

// CodeReading is how bash, or a program bash gives a value to, reads the
// value of a variable as code: as an argument the command reads as code,
// as the command word outside quotes (split into words), as the input of a
// command that reads its input as code, or as arithmetic (a subscript of
// the value runs its command substitutions). Its values are
// $defs/code-reading of schema/commands.json.
type CodeReading uint8

// CommandEntry is an element of commands.json: what one command, or one
// subcommand of it, reads and does.
type CommandEntry struct {
	Names       []string        // the names it runs by
	Pattern     *regexp.Regexp  // a name with a version in it, such as python3.12; nil when there is none
	Subcommand  []string        // the words after the command that name the subcommand; nil for the command itself
	Options     []CommandOption // before the subcommand for the command itself, after it for a subcommand
	Operands    int             // for runs-operand: the arguments before the command it runs
	Assignments bool            // for runs-operand: NAME=value words come before the command it runs
	Traits      []CommandTrait
	// OptionsAfterOperands: it reads a word that begins with - as an
	// option after its first operand too, up to -- (getopt's permutation);
	// without it, its options end at its first operand (ArgumentRoles).
	OptionsAfterOperands bool
	// OperandsOnly: it reads its arguments by their number and place, not
	// as options (test and [): ArgumentRoles reads them all as operands.
	OperandsOnly bool
	// ValueOptionsComplete: Options has every option of it that takes a
	// value, so an option it does not have takes none.
	ValueOptionsComplete bool
	// LongOptionPrefixes are prefixes a long option may take and stay the
	// same option: curl's --expand-header is --header, its value expanded.
	LongOptionPrefixes []string
	// OperandRequest is what its operands are to the request it sends:
	// unset for a command that sends none.
	OperandRequest RequestReading
	// ValueReading is how it reads the value of a variable expanded in
	// one of its operands as code, as a test saw (VariableCodes); unset
	// where no test saw the value run.
	ValueReading CodeReading
	// InputValueCode: it runs as code the value of a variable its standard
	// input carries (a pipe, a heredoc whose delimiter is not quoted, a
	// here-string), as a test saw (VariableCodes).
	InputValueCode bool
}

// CommandOption is an option a CommandEntry declares.
type CommandOption struct {
	Spellings []string        // such as -c and --eval; deno's eval works as one
	Value     bool            // it takes the next word as its value, or one joined to it
	Reading   ArgumentReading // how its value is read; unset for data
	Cluster   bool            // other short options may come before it in the same word (-ec for -c)
	Joined    bool            // its value may be joined to it: -eCODE, and --eval=CODE for a long spelling
	// Attack is the spellings of it with its value by which an
	// attacker's word was seen to run a program;
	// Remote, that the program runs on the remote side: by a local path or
	// SSH, not HTTPS.
	Attack   []AttackSpelling
	Harmless []AttackSpelling // the spellings an attacker's word was seen not to run a program by
	Remote   bool
	// EndsOptions: after its value the command reads no option; the value
	// is the code it runs (-c of a shell or python).
	EndsOptions bool
	Request     RequestReading // what its value is to the request the command sends; unset for none
	// ValueReading is how the command reads the value of a variable
	// expanded in its value as code, as a test saw (VariableCodes); unset
	// where no test saw the value run.
	ValueReading CodeReading
}

// Runs is whether o runs a program its value names or holds: by an attack
// spelling seen to, or as commands.json reads its value (code, program).
func (o *CommandOption) Runs() bool {
	return len(o.Attack) > 0 || o.Reading == ArgumentReadingCode || o.Reading == ArgumentReadingProgram
}

// Has is whether e declares t.
func (e *CommandEntry) Has(t CommandTrait) bool { return slices.Contains(e.Traits, t) }

// spell is whether the word w is o, and whether w holds o's value too: one
// of its spellings; with Cluster, among other short options in the same
// word (-ec, -cx for -c; without Joined, the value is the next word); with
// Joined, with the value after it (-cCODE, --eval=CODE).
func (o *CommandOption) spell(w string) (match, holdsValue bool) {
	for _, s := range o.Spellings {
		switch {
		case w == s:
			return true, false
		case strings.HasPrefix(s, "--"):
			if o.Joined && strings.HasPrefix(w, s+"=") {
				return true, true
			}
		case o.Cluster && len(s) == 2 && len(w) > 1 && w[0] == s[0]: // -ec for -c, +xo for +o
			for i := 1; i < len(w) && isLetter(w[i]); i++ {
				if w[i] != s[1] {
					continue
				}
				if i == len(w)-1 {
					return true, false
				}
				// joined: the rest of the word is the value; otherwise the
				// rest are other options and the value is the next word
				// (bash -cx code: -c and -x)
				return true, o.Joined
			}
		case o.Joined && strings.HasPrefix(w, s):
			return true, true
		}
	}
	return false, false
}

func isLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

// option is the option of e the word w spells, and whether w holds its
// value too. A short option with a value joined to it that is the first
// letter of w takes the rest of w as its value, before the letters after
// it are read as options run together: getopt and pflag read a word's
// letters from the first (-HX: y is -H with X: y).
func (e *CommandEntry) option(w string) (*CommandOption, bool) {
	w, _ = e.unprefixed(w)
	if len(w) > 2 && w[0] == '-' && w[1] != '-' {
		for i := range e.Options {
			o := &e.Options[i]
			if o.Value && o.Joined && slices.Contains(o.Spellings, w[:2]) {
				return o, true
			}
		}
	}
	for i := range e.Options {
		if ok, holds := e.Options[i].spell(w); ok {
			return &e.Options[i], holds
		}
	}
	return nil, false
}

// optionValues is how many of the words after w the options in w take as
// their values, but code, the option whose value is the first word after
// the options (-c of a shell): bash -co pipefail CODE gives pipefail to -o.
func (e *CommandEntry) optionValues(w string, code *CommandOption) int {
	n := 0
	for i := range e.Options {
		o := &e.Options[i]
		if o == code || !o.Value {
			continue
		}
		m, holds := o.spell(w)
		switch {
		case !m || holds:
		case o.Cluster && w != o.Spellings[0]:
			// each letter of the option in the word takes a value (bash -c
			// -oo pipefail errexit code)
			for _, s := range o.Spellings {
				if len(s) == 2 && len(w) > 1 && w[0] == s[0] {
					n += strings.Count(w[1:], s[1:])
				}
			}
		default:
			n++
		}
	}
	return n
}

// shellOptionWord is whether w is an option word of a shell before the
// code of -c: - or + and letters, or - or -- alone, which end the options.
func shellOptionWord(w CommandWord) bool {
	return w.Known && (strings.HasPrefix(w.Text, "-") || strings.HasPrefix(w.Text, "+"))
}

// unprefixed is w without a prefix of LongOptionPrefixes (--expand-header
// is --header), and the number of bytes taken off.
func (e *CommandEntry) unprefixed(w string) (string, int) {
	for _, p := range e.LongOptionPrefixes {
		if strings.HasPrefix(w, p) && len(w) > len(p) {
			return "--" + w[len(p):], len(p) - 2
		}
	}
	return w, 0
}

// commandsByName are the entries of the commands themselves, by name;
// commandsByPattern those with a Pattern; subcommandsByKey the entries of
// subcommands, by subcommandKey.
var commandsByName, commandsByPattern, subcommandsByKey = indexCommands(commandEntries)

func indexCommands(es []CommandEntry) (map[string]*CommandEntry, []*CommandEntry, map[string]*CommandEntry) {
	byName, bySub := map[string]*CommandEntry{}, map[string]*CommandEntry{}
	var byPattern []*CommandEntry
	for i := range es {
		e := &es[i]
		for _, n := range e.Names {
			if len(e.Subcommand) == 0 {
				byName[n] = e
			} else {
				bySub[subcommandKey(n, e.Subcommand)] = e
			}
		}
		if e.Pattern != nil && len(e.Subcommand) == 0 {
			byPattern = append(byPattern, e)
		}
	}
	return byName, byPattern, bySub
}

func subcommandKey(name string, sub []string) string {
	return name + "\x00" + strings.Join(sub, "\x00")
}

// commandNamed is the entry of the command itself that runs by name, or
// nil.
func commandNamed(name string) *CommandEntry {
	if e, ok := commandsByName[name]; ok {
		return e
	}
	for _, e := range commandsByPattern {
		if e.Pattern.MatchString(name) {
			return e
		}
	}
	return nil
}

// hasSubcommands is whether commands.json declares a subcommand of e, run
// by name: then a word after e that names none of them is a subcommand it
// does not declare.
func hasSubcommands(name string, e *CommandEntry) bool {
	prefix := subcommandKey(name, e.Subcommand)
	if len(e.Subcommand) == 0 {
		prefix = name
	}
	for k := range subcommandsByKey {
		if strings.HasPrefix(k, prefix+"\x00") && strings.Count(k, "\x00") == len(e.Subcommand)+1 {
			return true
		}
	}
	return false
}

// subcommandOf is the entry of the subcommand word of e, run by name, or
// nil.
func subcommandOf(name string, e *CommandEntry, word string) *CommandEntry {
	return subcommandsByKey[subcommandKey(name, append(slices.Clone(e.Subcommand), word))]
}

// Subcommands are the entries of the subcommands under e, at any depth,
// run by e's first name, in the order of their words.
func Subcommands(e *CommandEntry) []*CommandEntry {
	if e == nil || len(e.Names) == 0 {
		return nil
	}
	prefix := subcommandKey(e.Names[0], e.Subcommand) + "\x00"
	if len(e.Subcommand) == 0 {
		prefix = e.Names[0] + "\x00"
	}
	var keys []string
	for k := range subcommandsByKey {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	var out []*CommandEntry
	for _, k := range keys {
		if s := subcommandsByKey[k]; !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}
