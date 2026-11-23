package job

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// Secrets are the secrets a job reads: by name, once each by
// expr.FoldName, GITHUB_TOKEN not among them; All when it reads secrets
// whose names it does not write out: toJSON(secrets), secrets[x], or a job
// that calls a reusable workflow with secrets: inherit when the reusable
// workflow reads them so, or when the linter does not have its contents.
// For a job that calls, the secrets are those that the jobs of the called
// workflow read of what the job passes (calledReader); All also when a
// value of the job itself, such as its with, reads the secrets without a
// name.
type Secrets struct {
	All   bool
	Token bool // it reads the job's token: secrets.GITHUB_TOKEN or github.token
	Names []string
}

// jobValues are the values of the job j where a job reads the secrets, but the env
// of its workflow: the env and the outputs of the job, the credentials and
// the env of its container and of each of its services, the with and the
// secrets of a job that calls, the name, the env, the with, the run, the
// working-directory, the timeout-minutes and the continue-on-error of its
// steps.
func jobValues(j workflow.Job) []workflow.String { return jobValuesOf(j, true) }

// jobValuesOf are jobValues, the values of the secrets of a job that calls
// only when secrets.
func jobValuesOf(j workflow.Job, secrets bool) []workflow.String {
	var vs []workflow.String
	vs = append(vs, MapValues(j.Env)...)
	vs = append(vs, MapValues(j.Outputs)...)
	vs = append(vs, containerValues(j.Container)...)
	if j.Services.Status == workflow.Present {
		for _, e := range j.Services.Value.Entries {
			vs = append(vs, containerValues(e.Value)...)
		}
	}
	vs = append(vs, MapValues(j.With)...)
	if secrets {
		vs = append(vs, MapValues(j.Secrets)...)
	}
	if j.Steps.Status == workflow.Present {
		for _, st := range j.Steps.Value.Items {
			vs = append(vs, fieldValue(st.Name)...)
			vs = append(vs, MapValues(st.Env)...)
			vs = append(vs, MapValues(st.With)...)
			vs = append(vs, fieldValue(st.Run)...)
			vs = append(vs, fieldValue(st.WorkingDirectory)...)
			vs = append(vs, fieldValue(st.TimeoutMinutes)...)
			vs = append(vs, fieldValue(st.ContinueOnError)...)
		}
	}
	return vs
}

// containerValues are the values of the container c where the secrets
// context may be used: the username and the password of its credentials,
// or the ${{ }} of the credentials, and its env.
func containerValues(c workflow.Field[workflow.Container]) []workflow.String {
	if c.Status != workflow.Present {
		return nil
	}
	var vs []workflow.String
	vs = append(vs, fieldValue(c.Value.Username)...)
	vs = append(vs, fieldValue(c.Value.Password)...)
	return append(vs, MapValues(c.Value.Env)...)
}

// fieldValue is the value of f, or its ${{ }} when f is one; none when f
// is absent.
func fieldValue(f workflow.Field[workflow.String]) []workflow.String {
	switch {
	case f.Status == workflow.Present:
		return []workflow.String{f.Value}
	case f.Status == workflow.Dynamic && f.Expr != nil:
		return []workflow.String{*f.Expr}
	}
	return nil
}

// SecretsOf are the secrets the values vs read.
func SecretsOf(vs ...workflow.String) Secrets {
	var s Secrets
	seen := map[string]bool{}
	for _, v := range vs {
		s.read(v, seen)
	}
	return s
}

// MapValues are the values of the map f, or its ${{ }} when f is one.
func MapValues(f workflow.Field[workflow.Map[workflow.String]]) []workflow.String {
	if f.Status == workflow.Dynamic && f.Expr != nil {
		return []workflow.String{*f.Expr}
	}
	if f.Status != workflow.Present {
		return nil
	}
	var out []workflow.String
	for _, e := range f.Value.Entries {
		if e.Value.Status == workflow.Present {
			out = append(out, e.Value.Value)
		}
	}
	return out
}

// Without is what s reads that held does not: no name when held reads all
// the secrets; the names compared by expr.FoldName.
func (s Secrets) Without(held Secrets) Secrets {
	if held.All {
		return Secrets{} // the secrets context has GITHUB_TOKEN too
	}
	out := Secrets{Token: s.Token && !held.Token}
	out.All = s.All
	for _, n := range s.Names {
		if !slices.ContainsFunc(held.Names, func(h string) bool { return expr.FoldName(h) == expr.FoldName(n) }) {
			out.Names = append(out.Names, n)
		}
	}
	return out
}

// readsWholeContext is whether p, a reference that starts at secrets,
// names no secret: secrets itself, secrets.*, or secrets[x] whose x is not
// a string literal. GitHub sends the job every secret for it, even when x
// is made of literals only.
func readsWholeContext(p []expr.PathElem) bool { return len(p) == 1 || p[1].Name == "" }

// read adds the secrets the ${{ }} of v read.
func (s *Secrets) read(v workflow.String, seen map[string]bool) {
	for _, p := range v.Parts {
		if p.Expr && p.Tree != nil {
			s.walk(p.Tree, seen)
		}
	}
}

// walk adds the secrets n reads (taint.SecretRefs). The job's token is
// Token, not a name, through secrets or the github context.
func (s *Secrets) walk(n expr.Node, seen map[string]bool) {
	taint.SecretRefs(n, func(r taint.SecretRef) {
		switch {
		case r.Whole:
			s.All = true
		case r.Token:
			s.Token = true
		default:
			if f := expr.FoldName(r.Name); !seen[f] {
				seen[f] = true
				s.Names = append(s.Names, r.Name)
			}
		}
	})
}
