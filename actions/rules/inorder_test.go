package rules

import (
	"flag"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// testParallel is the -parallel of go test: how many tests and inputs of a
// test run at once. It is GOMAXPROCS when the flag is not there.
func testParallel() int {
	if f := flag.Lookup("test.parallel"); f != nil {
		if n, err := strconv.Atoi(f.Value.String()); err == nil && n > 0 {
			return n
		}
	}
	return runtime.GOMAXPROCS(0)
}

// inOrder computes work(i) for each i below n on testParallel goroutines,
// and calls use(i, work(i)) on the calling goroutine in the order of i. At
// most twice testParallel results are computed or wait for use at once, so
// that a test does not hold the results of every input. work runs off the
// goroutine of the test: it does not call t.Fatal or t.FailNow. use may
// end the test (t.Fatal); the goroutines then stop after the works they
// have begun.
func inOrder[T any](n int, work func(i int) T, use func(i int, v T)) {
	p := testParallel()
	slots := make(chan struct{}, 2*p) // a result computed or waiting
	results := make([]chan T, n)
	for i := range results {
		results[i] = make(chan T, 1)
	}
	next := make(chan int)
	done := make(chan struct{})
	defer close(done)
	go func() {
		defer close(next)
		for i := range n {
			select {
			case slots <- struct{}{}:
			case <-done:
				return
			}
			select {
			case next <- i:
			case <-done:
				return
			}
		}
	}()
	for range p {
		go func() {
			for i := range next {
				results[i] <- work(i)
			}
		}()
	}
	for i := range n {
		use(i, <-results[i])
		<-slots
	}
}

// TestInOrder: inOrder gives each result once, in order, with no more
// than testParallel works at once and no more than twice testParallel
// results computed or waiting.
func TestInOrder(t *testing.T) {
	p := int64(testParallel())
	for _, n := range []int{0, 1, 50} {
		var running, most, held, mostHeld atomic.Int64
		raise := func(c, m *atomic.Int64) {
			v := c.Add(1)
			for {
				old := m.Load()
				if v <= old || m.CompareAndSwap(old, v) {
					return
				}
			}
		}
		var got []int
		inOrder(n, func(i int) int {
			raise(&held, &mostHeld)
			raise(&running, &most)
			time.Sleep(time.Duration(n-i) * 100 * time.Microsecond)
			running.Add(-1)
			return i * i
		}, func(i, v int) {
			held.Add(-1)
			if v != i*i {
				t.Errorf("n %d: result %d of %d", n, v, i)
			}
			got = append(got, i)
		})
		if len(got) != n {
			t.Errorf("n %d: %d results", n, len(got))
		}
		for i, x := range got {
			if x != i {
				t.Fatalf("n %d: order %v", n, got)
			}
		}
		if m := most.Load(); m > p {
			t.Errorf("n %d: %d works at once, more than %d", n, m, p)
		}
		if m := mostHeld.Load(); m > 2*p {
			t.Errorf("n %d: %d results computed or waiting at once, more than %d", n, m, 2*p)
		}
	}
}

// TestInOrderStopsOnGoexit: when use ends the goroutine that called
// inOrder (as t.Fatal does), the goroutines of inOrder stop.
func TestInOrderStopsOnGoexit(t *testing.T) {
	before := runtime.NumGoroutine()
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		inOrder(100, func(i int) int { return i }, func(i, _ int) {
			if i == 1 {
				runtime.Goexit()
			}
		})
	}()
	<-ended
	for range 100 {
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("%d goroutines after inOrder ended, %d before", runtime.NumGoroutine(), before)
}
