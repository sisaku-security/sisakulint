package workflow

import cst "github.com/gh-intel/sisakulint/yaml/cst/v1"

// Permissions are the permissions of the GITHUB_TOKEN: All for read-all or
// write-all, or else the scopes in the order written. The schema checks
// the names of the scopes and their access (id-token is write or none).
type Permissions struct {
	Base
	All    String
	Scopes []Scope
}

type Scope struct {
	Name   String
	Access String
}

func (r *reader) permissions(e *entry, p pos) Field[Permissions] {
	if e == nil {
		return Field[Permissions]{}
	}
	if r.peek(e.value).Kind() == cst.NodeScalar {
		s := r.str(e, p)
		f := Field[Permissions]{Status: s.Status, Key: s.Key, Expr: s.Expr}
		f.Value.Base = s.Value.Base
		if s.Status == Present {
			f.Value.All = s.Value
		}
		return f
	}
	v, ents := r.object(e, p)
	f := field[Permissions](e, v)
	f.Value.Base = Base{Node: v.n, Via: v.p.via}
	for i := range ents {
		if ents[i].dup || !ents[i].prop {
			continue
		}
		access := r.str(&ents[i], v.p)
		f.Value.Scopes = append(f.Value.Scopes, Scope{Name: ents[i].key, Access: access.Value})
	}
	return f
}
