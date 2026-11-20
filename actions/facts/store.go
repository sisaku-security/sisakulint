package facts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
)

// FileSchema is the value of schema in a file of facts.
const FileSchema = "sisakulint/facts/v0"

// Store answers from a file of facts: answers found before (by a Recorder,
// in a run that could reach GitHub), given back without asking again. A
// fact the file does not have is Unknown; Absent comes only from a file
// that says absent. What follows from what it has (derived) it answers
// too, when the file does not have it.
type Store struct {
	m      map[Query]RawAnswer
	values map[Query]RefCommit // the found git.ref-commit, for derived
}

// LoadStore reads a file of facts ($defs/file of schema/facts-v0.json). An
// entry that is not a fact this package knows, an answer that does not fit
// its kind, and a fact written twice (after normalizing, such as the case
// of a repository) are errors.
func LoadStore(data []byte) (*Store, error) {
	if err := schema().Validate(SchemaName, "#/$defs/file", data); err != nil {
		return nil, fmt.Errorf("not a file of facts: %w", err)
	}
	var f struct {
		Facts []struct {
			Query  json.RawMessage `json:"query"`
			State  State           `json:"state"`
			Value  json.RawMessage `json:"value"`
			Reason string          `json:"reason"`
			Source Source          `json:"source"` // a report's: the store answers as the file
		} `json:"facts"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	s := &Store{m: map[Query]RawAnswer{}, values: map[Query]RefCommit{}}
	for i, e := range f.Facts {
		fail := func(format string, a ...any) error {
			return fmt.Errorf("facts/%d: %s", i, fmt.Sprintf(format, a...))
		}
		q, err := DecodeQuery(e.Query)
		if err != nil {
			return nil, fail("%v", err)
		}
		if _, dup := s.m[q]; dup {
			return nil, fail("the fact %s is written twice", e.Query)
		}
		if e.Source == SourceAssumption {
			return nil, fail("an assumption is not a fact found out: a file of facts does not hold one")
		}
		raw := RawAnswer{State: e.State, Value: e.Value, Reason: e.Reason}
		if raw.State == StateUnknown && raw.Reason == "" {
			return nil, fail("unknown without a reason")
		}
		c := Checked(q, raw)
		if c.State != raw.State {
			return nil, fail("%s", c.Reason)
		}
		c.Source = SourceFile
		s.m[q] = c
		if _, ok := q.(GitRefCommit); ok && c.State == StateFound {
			var v RefCommit
			if err := json.Unmarshal(c.Value, &v); err != nil {
				return nil, fail("%v", err)
			}
			s.values[q] = v
		}
	}
	return s, nil
}

func (s *Store) Resolve(_ context.Context, q Query) RawAnswer {
	if r, ok := s.m[q]; ok {
		return r // an unknown too: a replay answers as the run it records
	}
	if r, ok := s.derived(q); ok {
		r.Source = SourceFile
		return r
	}
	return RawAnswer{State: StateUnknown, Reason: "not in the file of facts"}
}

// Entries are the facts of the file, each once, in the order of their
// EncodeQuery bytes: what EncodeFile writes back. What the store derives is
// not among them.
func (s *Store) Entries() []Entry {
	type kv struct {
		key []byte
		e   Entry
	}
	var all []kv
	for q, r := range s.m {
		k, _ := EncodeQuery(q) // the file had it
		r.Source = SourceUnset // where the store read it is no answer's source
		all = append(all, kv{k, Entry{Query: q, RawAnswer: r}})
	}
	slices.SortFunc(all, func(a, b kv) int { return bytes.Compare(a.key, b.key) })
	out := make([]Entry, len(all))
	for i, x := range all {
		out[i] = x.e
	}
	return out
}

// EncodeFile writes entries as a file of facts, one entry a line. An
// assumed answer is not written: a run that reads the file assumes again.
func EncodeFile(entries []Entry) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(`{"schema":`)
	s, _ := json.Marshal(FileSchema)
	b.Write(s)
	b.WriteString(`,"facts":[`)
	n := 0
	for _, e := range entries {
		if e.RawAnswer.Assumed() {
			continue
		}
		if n > 0 {
			b.WriteByte(',')
		}
		n++
		b.WriteString("\n")
		line, err := e.marshal(false)
		if err != nil {
			return nil, err
		}
		b.Write(line)
	}
	b.WriteString("\n]}\n")
	return b.Bytes(), nil
}

// Entry is a fact and its answer, as a file of facts and the facts of a
// report write them.
type Entry struct {
	Query     Query
	RawAnswer RawAnswer
}

func (e Entry) MarshalJSON() ([]byte, error) { return e.marshal(true) }

// marshal writes e, with where the answer comes from when source.
func (e Entry) marshal(source bool) ([]byte, error) {
	q, err := EncodeQuery(e.Query)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(`{"query":`)
	b.Write(q)
	b.WriteString(`,"state":`)
	st, err := json.Marshal(e.RawAnswer.State)
	if err != nil {
		return nil, err
	}
	b.Write(st)
	switch e.RawAnswer.State {
	case StateFound:
		b.WriteString(`,"value":`)
		b.Write(e.RawAnswer.Value)
	case StateUnknown:
		b.WriteString(`,"reason":`)
		r, _ := json.Marshal(e.RawAnswer.Reason)
		b.Write(r)
	}
	if source && e.RawAnswer.Source != SourceUnset {
		b.WriteString(`,"source":`)
		src, _ := json.Marshal(e.RawAnswer.Source)
		b.Write(src)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
