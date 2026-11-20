package jsonorder

import (
	"slices"
	"testing"
)

func TestKeys(t *testing.T) {
	b := []byte(`{"a": 1, "$defs": {"z": {"q": 1}, "b": [1, {"x": 2}], "m": "s"}, "c": {}}`)
	if got, err := Keys(b, "$defs"); err != nil || !slices.Equal(got, []string{"z", "b", "m"}) {
		t.Errorf("Keys($defs) = %q, %v", got, err)
	}
	if got, err := Keys(b); err != nil || !slices.Equal(got, []string{"a", "$defs", "c"}) {
		t.Errorf("Keys() = %q, %v", got, err)
	}
	if _, err := Keys(b, "none"); err == nil {
		t.Error("Keys(none): no error")
	}
	if _, err := Keys(b, "a"); err == nil {
		t.Error("Keys(a): no error, and a is not an object")
	}
}
