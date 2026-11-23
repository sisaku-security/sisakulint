package scalar

import (
	"math"
	"testing"
)

func TestBool(t *testing.T) {
	cases := []struct {
		s      string
		want   bool
		wantOK bool
	}{
		{"true", true, true}, {"True", true, true}, {"TRUE", true, true},
		{"false", false, true}, {"False", false, true}, {"FALSE", false, true},
		{"tRUE", false, false}, {"yes", false, false}, {"", false, false},
	}
	for _, c := range cases {
		if got, ok := Bool(c.s); got != c.want || ok != c.wantOK {
			t.Errorf("Bool(%q) = %v %v", c.s, got, ok)
		}
	}
}

func TestInt(t *testing.T) {
	cases := []struct {
		s      string
		want   int64
		wantOK bool
	}{
		{"0", 0, true}, {"-0", 0, true}, {"+12", 12, true}, {"007", 7, true},
		{"0o17", 15, true}, {"0x1F", 31, true}, {"0x1f", 31, true},
		{"9223372036854775807", math.MaxInt64, true},
		{"-9223372036854775808", math.MinInt64, true},
		{"9223372036854775808", 0, false},
		{"0x8000000000000000", 0, false},
		{"0o", 0, false}, {"0x", 0, false}, {"0o8", 0, false}, {"-0x1", 0, false},
		{"1_000", 0, false}, {"1.0", 0, false}, {"", 0, false}, {"+", 0, false},
	}
	for _, c := range cases {
		if got, ok := Int(c.s); got != c.want || ok != c.wantOK {
			t.Errorf("Int(%q) = %v %v", c.s, got, ok)
		}
	}
}

func TestFloat(t *testing.T) {
	cases := []struct {
		s      string
		want   float64
		wantOK bool
	}{
		{"1e3", 1000, true}, {".5", 0.5, true}, {"0.", 0, true}, {"-0.0", 0, true},
		{"+12e03", 12000, true}, {"-2E+05", -200000, true}, {"1", 1, true},
		{".inf", math.Inf(1), true}, {"-.Inf", math.Inf(-1), true}, {"+.INF", math.Inf(1), true},
		{"1e400", math.Inf(1), true},
		{"1e", 0, false}, {".", 0, false}, {"e3", 0, false}, {"inf", 0, false},
		{"-.nan", 0, false}, {".NaN.", 0, false}, {"0x1p3", 0, false}, {"", 0, false},
	}
	for _, c := range cases {
		if got, ok := Float(c.s); got != c.want || ok != c.wantOK {
			t.Errorf("Float(%q) = %v %v", c.s, got, ok)
		}
	}
	for _, s := range []string{".nan", ".NaN", ".NAN"} {
		if got, ok := Float(s); !math.IsNaN(got) || !ok {
			t.Errorf("Float(%q) = %v %v", s, got, ok)
		}
	}
}
