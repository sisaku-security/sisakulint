package facts

import (
	"bytes"
	"context"
	"slices"
	"sync"
)

// First asks rs in order and gives the first answer that is not Unknown,
// or the last Unknown. It is how a file of facts is laid over GitHub.
func First(rs ...Resolver) Resolver { return first(rs) }

type first []Resolver

func (rs first) Resolve(ctx context.Context, q Query) RawAnswer {
	last := RawAnswer{State: StateUnknown, Reason: "nothing to ask"}
	for _, r := range rs {
		a := Checked(q, r.Resolve(ctx, q))
		if a.State != StateUnknown {
			return a
		}
		last = a
	}
	return last
}

// Recorder asks the Resolver below it once for each fact and keeps the
// answer: the same fact gets the same answer for the whole run, and the
// answers can be written as a file of facts and put in a report.
type Recorder struct {
	below Resolver
	mu    sync.Mutex
	m     map[Query]recorded
}

type recorded struct {
	key []byte // EncodeQuery
	raw RawAnswer
}

func NewRecorder(r Resolver) *Recorder {
	return &Recorder{below: r, m: map[Query]recorded{}}
}

// Resolve answers q. A Query that cannot be written (a zero Repo) is not
// asked and not kept: it is Unknown.
func (r *Recorder) Resolve(ctx context.Context, q Query) RawAnswer {
	key, err := EncodeQuery(q)
	if err != nil {
		return RawAnswer{State: StateUnknown, Reason: "not a fact: " + err.Error()}
	}
	r.mu.Lock()
	got, ok := r.m[q]
	r.mu.Unlock()
	if ok {
		return got.raw
	}
	a := Checked(q, r.below.Resolve(ctx, q))
	r.mu.Lock()
	defer r.mu.Unlock()
	if got, ok := r.m[q]; ok {
		return got.raw
	}
	r.m[q] = recorded{key, a}
	return a
}

// Entries are the facts asked, in the order of their EncodeQuery bytes.
func (r *Recorder) Entries() []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	type kv struct {
		q Query
		recorded
	}
	all := make([]kv, 0, len(r.m))
	for q, v := range r.m {
		all = append(all, kv{q, v})
	}
	slices.SortFunc(all, func(a, b kv) int { return bytes.Compare(a.key, b.key) })
	out := make([]Entry, len(all))
	for i, v := range all {
		out[i] = Entry{v.q, v.raw}
	}
	return out
}

// WriteFile writes the facts asked as a file of facts (EncodeFile).
func (r *Recorder) WriteFile() ([]byte, error) { return EncodeFile(r.Entries()) }

// Asked is the answer the Recorder keeps for q, and whether q was asked.
func (r *Recorder) Asked(q Query) (RawAnswer, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	got, ok := r.m[q]
	return got.raw, ok
}
