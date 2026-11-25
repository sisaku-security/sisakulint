package shell

import "strings"

// NestedScript is the script another shell runs from the code after -c of
// a simple command (bash -c 'code', sh -c 'code'), where the code is one
// word in single quotes: the shell that runs the command passes those
// bytes as they are, and the shell it starts reads them as a script of its
// own, with the variables the first one exports.
type NestedScript struct {
	Command *Simple
	Shell   string // bash or sh, as commands.json names it
	Code    Span   // the code, inside its quotes
	// Assigns are the names the command gives the shell a value of its
	// own: the assignments before the command word (T=x bash -c ...) and
	// those of env (env T=x bash -c ...). Clears: env takes an option
	// (env -i, env -u T), so the shell may not have the variables at all.
	Assigns []VarName
	Clears  bool
}

// NestedScripts are the nested scripts of the simple commands of script,
// whose tree is sc, in the order Walk gives the commands. Code that is not
// one word in single quotes (bash -c "$X", bash -c 'a'"b") is not given:
// the first shell expands it first.
func NestedScripts(script string, sc *Script) []NestedScript {
	var out []NestedScript
	WalkSimple(sc.List, func(x *Simple) {
		words := WordsOf(script, x)
		r := ArgumentRoles(words)
		if r.Entry == nil || r.Name != "bash" && r.Name != "sh" {
			return
		}
		var assigns []VarName
		for _, a := range x.Assigns {
			if n, _, _, ok := AssignedName(script, a); ok {
				assigns = append(assigns, VarName{n})
			}
		}
		clears, inEnv := false, false
		for i := range x.Words {
			if r.Roles[i] != ArgumentRoleCommand {
				break
			}
			t := words[i].Text
			switch {
			case base(t) == "env":
				inEnv = true
			case !inEnv:
			case strings.HasPrefix(t, "-"):
				clears = true
			case strings.Contains(t, "="):
				if n, ok := NameOf(t[:strings.IndexByte(t, '=')]); ok {
					assigns = append(assigns, n)
				}
			}
		}
		code := false // a word before is -c, whose value is the code
		for i, w := range x.Words {
			switch r.Roles[i] {
			case ArgumentRoleOption:
				if words[i].Known && strings.HasPrefix(words[i].Text, "-") && !strings.HasPrefix(words[i].Text, "--") {
					if o, holds := r.Entry.option(words[i].Text); o != nil && o.Reading == ArgumentReadingCode && o.EndsOptions && !holds {
						code = true
					}
				}
				continue
			case ArgumentRoleOperand:
			default:
				continue
			}
			if code && len(w.Parts) == 1 && w.Parts[0].Quote == QuoteSingle && w.Parts[0].Kind == PartLiteral {
				out = append(out, NestedScript{Command: x, Shell: r.Name, Code: w.Parts[0].Span, Assigns: assigns, Clears: clears})
			}
			return // the first operand after -c is the code
		}
	})
	return out
}

// Text is script with every byte outside the code of n made a blank, and
// the code as it is: a script of the same length, whose positions are
// those of script.
func (n NestedScript) Text(script string) string {
	b := []byte(strings.Repeat(" ", len(script)))
	copy(b[n.Code.Start:n.Code.End], script[n.Code.Start:n.Code.End])
	return string(b)
}
