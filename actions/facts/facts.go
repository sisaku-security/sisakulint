package facts

//go:generate go run ./internal/factsgen
//go:generate go run github.com/gh-intel/sisakulint/actions/internal/enumgen -pkg facts -out enum_gen.go schema/facts-v0.json

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/gh-intel/sisakulint/actions/internal/jsonschema"
)

// State is what is known of a fact ($defs/state of schema/facts-v0.json).
// The zero value is StateUnknown (x-go-zero), so that an answer nobody
// filled in is never taken for a known one.
type State uint8

// Source is where an answer comes from ($defs/source of
// schema/facts-v0.json). The zero value, SourceUnset, is an answer no one
// gave: nothing asked knew.
type Source uint8

// Query is one fact to ask about: its kind is its type, and its fields say
// what the fact is about. The types are those query_gen.go makes from
// schema/facts-v0.json; no other package can add one.
type Query interface {
	Kind() Kind
	query()
	encodeJSON() ([]byte, error)
}

// RawAnswer is an answer before it is read into the type of its kind.
type RawAnswer struct {
	State  State
	Value  json.RawMessage // when Found
	Reason string          // when Unknown, for people
	// Source is where the answer comes from: a file of facts, an argument
	// on the command line (Arguments), an API, or a file of the repository.
	// A report says so; a file of facts does not keep it.
	Source Source
}

// Resolver answers questions about facts. It returns no error: whatever
// kept it from knowing is an Unknown with a Reason, so that no one reads
// "could not find out" as "is not there".
type Resolver interface {
	Resolve(ctx context.Context, q Query) RawAnswer
}

// Answer is an answer read into the type of the value of its kind.
type Answer[T any] struct {
	State  State
	Value  T
	Reason string
}

// KindInfo describes a kind of fact (its member of $defs in
// schema/facts-v0.json).
type KindInfo struct {
	Kind        Kind
	Provider    Provider
	Permission  Permission // of a token, to find it out
	Description string
	// AssumedValue is the x-assume value of the kind, nil when the kind has
	// none: the answer with which the findings of the false positive forms
	// of the kind hold. No run answers a fact with it. AssumedReason says
	// when to write the other answer.
	AssumedValue  json.RawMessage
	AssumedReason string
}

// Kinds lists the kinds of facts, by name.
func Kinds() []KindInfo { return append([]KindInfo(nil), kinds...) }

//go:embed schema/facts-v0.json
var schemaJSON []byte

// SchemaName is the name the schema of facts is known by, in the $ref of
// the other schemas of sisakulint (facts-v0.json#/$defs/...).
const SchemaName = "facts-v0.json"

var loadSchema = sync.OnceValues(func() (*jsonschema.Set, error) {
	return jsonschema.Load(map[string][]byte{SchemaName: schemaJSON}, jsonschema.Options{SchemaAnnotations: []string{"x-value"}})
})

func schema() *jsonschema.Set {
	s, err := loadSchema()
	if err != nil {
		panic("facts: schema/facts-v0.json: " + err.Error())
	}
	return s
}

// DecodeQuery reads a fact written as JSON ({"kind": ..., ...}). What does
// not fit the schema of its kind, and a kind this package does not know,
// is an error.
func DecodeQuery(data []byte) (Query, error) {
	if err := schema().Validate(SchemaName, "#/$defs/query", data); err != nil {
		return nil, fmt.Errorf("not a fact: %w", err)
	}
	var k struct {
		Kind Kind `json:"kind"`
	}
	if err := json.Unmarshal(data, &k); err != nil {
		return nil, err
	}
	return decoders[k.Kind](data)
}

// EncodeQuery writes q as JSON: kind first, then the other properties in
// the order of the schema. The same fact is always the same bytes. A value
// that does not fit the schema (a zero Repo, an empty name) is an error.
func EncodeQuery(q Query) ([]byte, error) {
	k, ok := kindOf(q)
	if !ok {
		return nil, notAFact(q)
	}
	b, err := q.encodeJSON()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", k, err)
	}
	if err := schema().Validate(SchemaName, "#/$defs/query", b); err != nil {
		return nil, fmt.Errorf("%s: %w", k, err)
	}
	return b, nil
}

// QueryText is q for people: its kind, then key=value in the order of its
// JSON. A q that EncodeQuery refuses is what fmt prints of it.
func QueryText(q Query) string {
	b, err := EncodeQuery(q)
	if err != nil {
		return fmt.Sprint(q)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var parts []string
	kind := ""
	if _, err := d.Token(); err != nil { // {
		return string(b)
	}
	for d.More() {
		k, err := d.Token()
		if err != nil {
			return string(b)
		}
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			return string(b)
		}
		var s string
		if json.Unmarshal(v, &s) != nil {
			s = string(v)
		}
		if k == "kind" {
			kind = s
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", k, s))
	}
	return strings.Join(append([]string{kind}, parts...), " ")
}

// notAFact is the error for a Query that is not one of the generated
// types: a pointer to one, or a type that embeds one.
func notAFact(q Query) error {
	return fmt.Errorf("%T is not a fact of package facts", q)
}

// Checked is r as an answer about q can be: a found value that fits the
// x-value of the kind, with a Repo or a SHA in it in lower case, in the
// canonical form of RFC 8785; an Absent without a value; an Unknown with a
// reason. Anything else is an Unknown that says what was wrong. Where it
// comes from (Source) is kept; Assumed holds only of a found value.
func Checked(q Query, r RawAnswer) RawAnswer {
	c := checked(q, r)
	c.Source = r.Source
	return c
}

// checked is Checked without the Source.
func checked(q Query, r RawAnswer) RawAnswer {
	unknown := func(format string, a ...any) RawAnswer {
		return RawAnswer{State: StateUnknown, Reason: fmt.Sprintf(format, a...)}
	}
	k, ok := kindOf(q)
	if !ok {
		return unknown("%v", notAFact(q))
	}
	switch r.State {
	case StateFound:
		if len(r.Value) == 0 {
			return unknown("found without a value")
		}
		if err := schema().Validate(SchemaName, "#/$defs/"+k.String()+"/x-value", r.Value); err != nil {
			return unknown("the value does not fit %s: %v", k, err)
		}
		n, err := normalizers[k](r.Value)
		if err != nil {
			return unknown("the value does not fit %s: %v", k, err)
		}
		c, err := jsonschema.Canonical(n)
		if err != nil {
			return unknown("the value does not fit %s: %v", k, err)
		}
		return RawAnswer{State: StateFound, Value: c}
	case StateAbsent:
		if len(r.Value) != 0 {
			return unknown("absent, but with a value")
		}
		return RawAnswer{State: StateAbsent}
	case StateUnknown:
		if r.Reason == "" {
			return unknown("unknown, and no reason was given")
		}
		return RawAnswer{State: StateUnknown, Reason: r.Reason}
	}
	return unknown("the answer has the state %v", r.State)
}

func ask[T any](ctx context.Context, r Resolver, q Query) Answer[T] {
	if err := ctx.Err(); err != nil {
		return Answer[T]{State: StateUnknown, Reason: "not asked: " + err.Error()}
	}
	raw := Checked(q, r.Resolve(ctx, q))
	a := Answer[T]{State: raw.State, Reason: raw.Reason}
	if raw.State == StateFound {
		if err := json.Unmarshal(raw.Value, &a.Value); err != nil {
			return Answer[T]{State: StateUnknown, Reason: "the value does not fit " + q.Kind().String() + ": " + err.Error()}
		}
	}
	return a
}

// normalize reads b into T and writes it again.
func normalize[T any](b []byte) ([]byte, error) {
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

type field struct {
	name  string
	value any
}

// encodeFields writes {"kind": kind, name: value, ...} in the order given,
// without escaping <, > and &.
func encodeFields(kind string, fs ...field) ([]byte, error) {
	var b bytes.Buffer
	put := func(v any) error {
		if s, ok := v.(string); ok && !utf8.ValidString(s) {
			return errors.New("not UTF-8")
		}
		var one bytes.Buffer
		enc := json.NewEncoder(&one)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return err
		}
		b.Write(bytes.TrimSuffix(one.Bytes(), []byte("\n")))
		return nil
	}
	b.WriteString(`{"kind":`)
	if err := put(kind); err != nil {
		return nil, err
	}
	for _, f := range fs {
		b.WriteByte(',')
		if err := put(f.name); err != nil {
			return nil, err
		}
		b.WriteByte(':')
		if err := put(f.value); err != nil {
			return nil, fmt.Errorf("%s: %w", f.name, err)
		}
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
