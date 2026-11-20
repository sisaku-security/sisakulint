package shell

import "strings"

// RequestWord is what a word of a command that sends a request is to the
// request.
type RequestWord struct {
	Reading RequestReading // unset for a word that is nothing to the request
	// ValueAt is where in the word the value begins: after --url= or -H
	// for a value joined to its option, 0 for a whole word.
	ValueAt int
}

// RequestRoles is what each of words is to the request its command sends,
// read with the roles ArgumentRoles found (r): the value of an option with
// a RequestReading, a value joined to such an option (in a word whose text
// is known, or whose literal prefix spells the option), or an operand of a
// command with an OperandRequest. A command with no OperandRequest sends
// no request: every word is the zero RequestWord.
func RequestRoles(r CommandRoles, words []CommandWord) []RequestWord {
	out := make([]RequestWord, len(words))
	e := r.Entry
	if e == nil || e.OperandRequest == RequestReadingUnset {
		return out
	}
	for i, w := range words {
		switch r.Roles[i] {
		case ArgumentRoleOptionValue:
			if o, holds := e.option(words[i-1].Text); o != nil && !holds {
				out[i].Reading = o.Request
			}
		case ArgumentRoleOperand:
			out[i].Reading = e.OperandRequest
		case ArgumentRoleOption:
			text := w.Text
			if !w.Known {
				text = w.Prefix
			}
			if !strings.HasPrefix(text, "-") || text == "-" {
				out[i].Reading = e.OperandRequest // an operand, read where options may be
				continue
			}
			if o, at := joinedOption(e, text, w.Known); o != nil {
				out[i] = RequestWord{Reading: o.Request, ValueAt: at}
			}
		}
	}
	return out
}

// joinedOption is the option of e whose value is joined to it in text, and
// where the value begins: -HValue, -sHValue after short options that take
// no value, or --url=Value. A text not known (the literal before what is not
// known) may end at the option: -H$H.
func joinedOption(e *CommandEntry, text string, known bool) (*CommandOption, int) {
	text, off := e.unprefixed(text)
	if len(text) > 2 && text[0] == '-' && text[1] != '-' {
		for i := 1; i < len(text); i++ {
			o, _ := e.option("-" + text[i:i+1])
			switch {
			case o == nil && e.ValueOptionsComplete:
				continue // an option the table does not declare takes no value
			case o == nil:
				return nil, 0
			case o.Value && o.Joined && (i+1 < len(text) || !known):
				return o, i + 1
			case o.Value:
				return nil, 0 // its value is the next word
			}
		}
		return nil, 0
	}
	for i := range e.Options {
		o := &e.Options[i]
		if !o.Value || !o.Joined {
			continue
		}
		for _, s := range o.Spellings {
			switch {
			case strings.HasPrefix(s, "--") && strings.HasPrefix(text, s+"="):
				return o, off + len(s) + 1
			case !strings.HasPrefix(s, "--") && (len(text) > len(s) || !known) && strings.HasPrefix(text, s):
				return o, len(s)
			}
		}
	}
	return nil, 0
}
