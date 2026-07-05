// pkg/core/chain/collector_test.go
package chain

import (
	"sync"
	"testing"
)

func TestSinkCollectorAddRecords(t *testing.T) {
	c := NewSinkCollector()
	c.Add(SinkRecord{JobID: "build", SinkKind: SinkLog, RuleName: "secret-in-log"})
	c.Add(SinkRecord{JobID: "deploy", SinkKind: SinkNetwork, RuleName: "secret-exfiltration"})

	got := c.Records()
	if len(got) != 2 {
		t.Fatalf("Records() len = %d, want 2", len(got))
	}
	// Records() はコピーを返す: 変更しても内部に影響しない
	got[0].JobID = "mutated"
	if c.Records()[0].JobID != "build" {
		t.Errorf("Records() must return a copy; internal state was mutated")
	}
}

func TestSinkCollectorConcurrentAdd(t *testing.T) {
	c := NewSinkCollector()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Add(SinkRecord{JobID: "j"})
		}()
	}
	wg.Wait()
	if len(c.Records()) != 100 {
		t.Errorf("concurrent Add lost records: got %d, want 100", len(c.Records()))
	}
}
