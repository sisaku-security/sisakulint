package boundary

import (
	"fmt"
	"slices"
	"sync"
)

// tables are the rows the dimensions are read from.
type tables struct {
	grants    []RunGrant
	baselines []RoleBaseline
	channels  []Channel
	pathways  []Pathway
	barriers  []BarrierPass
	writes    []WriteRow
}

// check checks every row.
func (t tables) check() error {
	for _, g := range t.grants {
		if err := g.check(); err != nil {
			return fmt.Errorf("a run grant: %w", err)
		}
	}
	for _, b := range t.baselines {
		if err := b.check(); err != nil {
			return fmt.Errorf("a role baseline: %w", err)
		}
	}
	for _, c := range t.channels {
		if err := c.check(); err != nil {
			return fmt.Errorf("a channel: %w", err)
		}
	}
	for _, p := range t.pathways {
		if err := p.check(); err != nil {
			return fmt.Errorf("a pathway: %w", err)
		}
	}
	for _, b := range t.barriers {
		if err := b.check(); err != nil {
			return fmt.Errorf("a barrier pass: %w", err)
		}
	}
	for _, w := range t.writes {
		if err := w.check(); err != nil {
			return fmt.Errorf("a write row: %w", err)
		}
	}
	return nil
}

var (
	once sync.Once
	all  tables
)

// rows are the tables of grants.go and baselines.go, checked once: a row
// that does not fit its basis is a mistake of this package, so it panics.
func rows() tables {
	once.Do(func() {
		all = tables{grants: grantRows, baselines: baselineRows, channels: channelRows, pathways: pathwayRows, barriers: barrierRows, writes: writeRows}
		if err := all.check(); err != nil {
			panic("boundary: " + err.Error())
		}
	})
	return all
}

// Grants are the RunGrant rows.
func Grants() []RunGrant { return slices.Clone(rows().grants) }

// Baselines are the RoleBaseline rows.
func Baselines() []RoleBaseline { return slices.Clone(rows().baselines) }

// Channels are the Channel rows.
func Channels() []Channel { return slices.Clone(rows().channels) }

// Pathways are the Pathway rows.
func Pathways() []Pathway { return slices.Clone(rows().pathways) }

// BarrierRows are the BarrierPass rows.
func BarrierRows() []BarrierPass { return slices.Clone(rows().barriers) }

// WriteRows are the WriteRow rows.
func WriteRows() []WriteRow { return slices.Clone(rows().writes) }
