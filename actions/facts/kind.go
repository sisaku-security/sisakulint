package facts

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Kind is a kind of fact: a member of $defs in schema/facts-v0.json. The
// constants are in query_gen.go; KindUnset is none, and is not written.
type Kind uint8

func (k Kind) valid() bool { return k != KindUnset && int(k) < len(kindNames) }

// String is the name of k, such as git.ref-commit.
func (k Kind) String() string {
	if k.valid() {
		return kindNames[k]
	}
	return fmt.Sprintf("Kind(%d)", k)
}

func (k Kind) MarshalJSON() ([]byte, error) {
	if !k.valid() {
		return nil, fmt.Errorf("%v is not a kind of fact", k)
	}
	return json.Marshal(kindNames[k])
}

func (k *Kind) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseKind(s)
	if err != nil {
		return err
	}
	*k = v
	return nil
}

// ParseKind is the kind named s.
func ParseKind(s string) (Kind, error) {
	for i := 1; i < len(kindNames); i++ {
		if kindNames[i] == s {
			return Kind(i), nil
		}
	}
	return KindUnset, fmt.Errorf("unknown kind of fact %q", s)
}

// Provider is where a kind of fact comes from (x-from; $defs/from of
// schema/facts-v0.json).
type Provider uint8

// Description is what the provider is, as the schema says.
func (v Provider) Description() string { return v.description() }

// Permission is a permission of a token that finding out a kind of fact
// needs (x-permission): a scope and its level, such as contents: read. The
// zero Permission is none.
type Permission struct {
	scope string
	write bool
}

// IsZero is whether no permission is needed.
func (p Permission) IsZero() bool { return p.scope == "" }

// String is the permission as x-permission writes it, or empty for none.
func (p Permission) String() string {
	if p.IsZero() {
		return ""
	}
	if p.write {
		return p.scope + ": write"
	}
	return p.scope + ": read"
}

func (p Permission) MarshalJSON() ([]byte, error) {
	if p.IsZero() {
		return nil, errors.New("no permission")
	}
	return json.Marshal(p.String())
}
