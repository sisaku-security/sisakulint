package ir

import (
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/job"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// PasswordForm is how the password of a registry is given.
type PasswordForm uint8

const (
	passwordFormUnset   PasswordForm = iota
	PasswordFormLiteral              // written in the workflow: no ${{ }}, ${FOO}, or a ${{ }} of no context
	PasswordFormSecret               // read from secrets and no other context
	PasswordFormOther                // read from another context: env, vars, inputs, matrix
)

var passwordFormNames = [...]string{"", "literal", "secret", "other"}

func (f PasswordForm) String() string { return passwordFormNames[f] }

func (x *IR) allRegistryCredentials() []*RegistryCredentials {
	x.once(SummaryRegistryCredentials, func() {
		var out []*RegistryCredentials
		add := func(c workflow.Container, name string) {
			var pw workflow.String
			switch c.Password.Status {
			case workflow.Present:
				pw = c.Password.Value
			case workflow.Dynamic: // credentials is a ${{ }}
				pw = *c.Password.Expr
			default:
				return
			}
			out = append(out, &RegistryCredentials{key: keyOf(x.paths, x.input, x.tree, c.Base), passwordAt: x.handleOf(pw.Base),
				passwordForm: passwordFormOf(pw), passwordText: pw.Text(), container: name})
		}
		// other is a container, or the services, written as a whole ${{ }}
		// that may hold credentials
		other := func(e workflow.String, name string) {
			out = append(out, &RegistryCredentials{key: keyOf(x.paths, x.input, x.tree, e.Base), passwordAt: x.handleOf(e.Base),
				passwordForm: PasswordFormOther, passwordText: e.Text(), container: name})
		}
		if w := x.workflow; w != nil {
			for _, je := range w.Jobs.Value.Entries {
				if je.Value.Status != workflow.Present {
					continue
				}
				j := je.Value.Value
				if j.Container.Status == workflow.Present {
					if e, ok := wholeExpr(j, j.Container.Value); ok {
						other(e, "container")
					} else {
						add(j.Container.Value, "container")
					}
				}
				if j.Services.Status == workflow.Dynamic && j.Services.Expr != nil {
					other(*j.Services.Expr, "services")
				}
				if j.Services.Status == workflow.Present {
					for _, se := range j.Services.Value.Entries {
						if se.Value.Status != workflow.Present {
							continue
						}
						name := "services." + se.Key.AsString()
						if e, ok := wholeExpr(j, se.Value.Value); ok {
							other(e, name)
						} else {
							add(se.Value.Value, name)
						}
					}
				}
			}
		}
		x.registryCredentials = out
	})
	return x.registryCredentials
}

// wholeExpr is c, a container or a service written as a whole ${{ }},
// when its value may be a mapping with credentials: not when it is the
// values of the matrix, all strings.
func wholeExpr(j workflow.Job, c workflow.Container) (workflow.String, bool) {
	img := c.Image.Value
	if c.Image.Status != workflow.Present || img.Parts == nil || c.Node != img.Node {
		return workflow.String{}, false
	}
	if _, ok := job.MatrixValues(j, img); ok {
		return workflow.String{}, false
	}
	return img, true
}

// passwordFormOf is how s gives a password. GitHub evaluates ${{ }} alone
// and the runner gives the password to docker login on its standard input,
// so ${FOO} is the password as written. A ${{ }} whose
// value is known before the run is written in the workflow too.
func passwordFormOf(s workflow.String) PasswordForm {
	secret := false
	for _, p := range s.Parts {
		if !p.Expr || p.Tree == nil {
			continue
		}
		if literalOperand(p.Tree) {
			return PasswordFormLiteral
		}
		if expr.Partial(p.Tree, func([]expr.PathElem) (expr.Value, bool) { return expr.Value{}, false }).Known() {
			continue
		}
		for _, name := range contextsOf(p.Tree) {
			if !expr.EqualName(name, "secrets") {
				return PasswordFormOther
			}
			secret = true
		}
	}
	if secret {
		return PasswordFormSecret
	}
	return PasswordFormLiteral
}

// literalOperand is whether n has a string written as an operand of && or
// ||, which may be the value: secrets.PW || 'hunter2' is hunter2 where the
// secret is not set.
func literalOperand(n expr.Node) bool {
	if l, ok := n.(*expr.Logical); ok {
		for _, x := range l.Xs {
			if lit, ok := x.(*expr.Literal); ok && lit.Kind == expr.LitString && lit.Str != "" {
				return true
			}
		}
	}
	for _, c := range expr.Children(n) {
		if literalOperand(c) {
			return true
		}
	}
	return false
}

// contextsOf are the names of the contexts n reads; github.token, whose
// value is not in the file either, is read as secrets.
func contextsOf(n expr.Node) []string {
	if p, ok := expr.AccessPath(n); ok {
		if len(p) == 2 && expr.EqualName(p[0].Name, "github") && expr.EqualName(p[1].Name, "token") {
			return []string{"secrets"}
		}
		return []string{p[0].Name}
	}
	var out []string
	for _, c := range expr.Children(n) {
		out = append(out, contextsOf(c)...)
	}
	return out
}
