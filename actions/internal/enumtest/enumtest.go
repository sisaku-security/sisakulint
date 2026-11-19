// Package enumtest checks the types actions/internal/enumgen writes, for
// the tests of the packages that have them.
package enumtest

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Value is a type enumgen writes.
type Value interface {
	~uint8
	fmt.Stringer
	json.Marshaler
}

// Check checks that every value of T is written as its $defs has it
// (validate) and read back, by Parse and by UnmarshalJSON; and that the
// zero value, when it is Unset, and a number past the last value are not.
// names is how many names T has (with the empty one of Unset), and
// zeroValid whether its zero value is one of them (x-go-zero).
func Check[T Value, P interface {
	*T
	json.Unmarshaler
}](t *testing.T, names int, zeroValid bool, parse func(string) (T, error), validate func([]byte) error) {
	t.Helper()
	first := 1
	if zeroValid {
		first = 0
	}
	for i := first; i < names; i++ {
		v := T(i)
		b, err := v.MarshalJSON()
		if err != nil {
			t.Fatalf("%v: %v", v, err)
		}
		if err := validate(b); err != nil {
			t.Errorf("%s: %v", b, err)
		}
		if p, err := parse(v.String()); err != nil || p != v {
			t.Errorf("parse %q = %v, %v", v.String(), p, err)
		}
		var got T
		if err := P(&got).UnmarshalJSON(b); err != nil || got != v {
			t.Errorf("unmarshal %s = %v, %v", b, got, err)
		}
		for _, n := range []string{strings.ToUpper(v.String()), " " + v.String()} {
			if _, err := parse(n); err == nil && n != v.String() {
				t.Errorf("%q is read", n)
			}
		}
	}
	typ := fmt.Sprintf("%T", T(0))
	typ = typ[strings.LastIndex(typ, ".")+1:]
	bad := []T{T(names)}
	if !zeroValid {
		bad = append(bad, 0)
		if got := T(0).String(); got != typ+"Unset" {
			t.Errorf("the zero %s is %q", typ, got)
		}
	}
	for _, v := range bad {
		if _, err := v.MarshalJSON(); err == nil {
			t.Errorf("%v is written", v)
		}
	}
	for _, n := range []string{"", "nope", typ + "Unset"} {
		if _, err := parse(n); err == nil {
			t.Errorf("%q is read", n)
		}
	}
	for _, b := range []string{`null`, `""`, `"nope"`, `1`} {
		got := T(names - 1)
		if err := P(&got).UnmarshalJSON([]byte(b)); err == nil || got != T(names-1) {
			t.Errorf("unmarshal %s = %v, %v; want an error, and the value kept", b, got, err)
		}
	}
}
