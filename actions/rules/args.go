package rules

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Sink is where a value is written as code ($defs/sink of
// schema/findings-v0.json).
type Sink uint8

// Approval is what makes a person approve a run before it checks out the
// code of a pull request ($defs/approval of schema/findings-v0.json).
type Approval uint8

// marshalArgs writes the args of a finding as JSON without escaping <, >
// and &, as the report does: a ref may have them.
func marshalArgs(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// orEmpty is xs, or an empty slice for nil: the JSON of an array argument
// is [] then, not null.
func orEmpty[T any](xs []T) []T {
	if xs == nil {
		return []T{}
	}
	return xs
}

// joined is the texts of xs joined by a comma and a space, as a message
// writes an array.
func joined[T any](xs []T, text func(T) string) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = text(x)
	}
	return strings.Join(parts, ", ")
}
