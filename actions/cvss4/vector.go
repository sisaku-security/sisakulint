package cvss4

import (
	"fmt"
	"strings"
)

// metrics are the Base metrics a vector has, in the order of the
// specification (Table 23), and the values each takes.
var metrics = [...]struct{ name, values string }{
	{"AV", "NALP"}, {"AC", "LH"}, {"AT", "NP"}, {"PR", "NLH"}, {"UI", "NPA"},
	{"VC", "HLN"}, {"VI", "HLN"}, {"VA", "HLN"}, {"SC", "HLN"}, {"SI", "HLN"}, {"SA", "HLN"},
}

// index is the index in metrics of each metric.
var index = func() map[string]int {
	m := map[string]int{}
	for i, x := range metrics {
		m[x.name] = i
	}
	return m
}()

// Vector is a CVSS v4.0 vector of the eleven Base metrics and, when it has
// one, Exploit Maturity (E).
type Vector struct {
	base [len(metrics)]byte // the value of each of metrics
	e    byte               // A, P or U; 0 when the vector has no E
}

// ParseVector reads "CVSS:4.0/", the eleven Base metrics in the order of
// the specification, and optionally E (A, P or U). It refuses anything
// else: E:X, the Environmental and the Supplemental metrics, since the
// registry of rules has none of them.
func ParseVector(s string) (Vector, error) {
	rest, ok := strings.CutPrefix(s, "CVSS:4.0/")
	if !ok {
		return Vector{}, fmt.Errorf("cvss4: %q does not start with CVSS:4.0/", s)
	}
	parts := strings.Split(rest, "/")
	if len(parts) != len(metrics) && len(parts) != len(metrics)+1 {
		return Vector{}, fmt.Errorf("cvss4: %q has %d metrics; it takes the eleven Base metrics and E", s, len(parts))
	}
	var v Vector
	for i, p := range parts {
		name, value, _ := strings.Cut(p, ":")
		want, values := "E", "APU"
		if i < len(metrics) {
			want, values = metrics[i].name, metrics[i].values
		}
		if name != want {
			return Vector{}, fmt.Errorf("cvss4: %q has %q where %s is", s, p, want)
		}
		if len(value) != 1 || !strings.Contains(values, value) {
			return Vector{}, fmt.Errorf("cvss4: %q: %s takes one of %s, not %q", s, name, values, value)
		}
		if i < len(metrics) {
			v.base[i] = value[0]
		} else {
			v.e = value[0]
		}
	}
	return v, nil
}

// value is the value of the metric name as the calculator reads it (its
// function m): E is A when the vector has none (E:X), and CR, IR and AR
// are H (X), since v has no Environmental metrics; the modified metrics
// are those of the Base. It is X for the modified metrics MSI and MSA,
// which only eq4 asks about.
func (v Vector) value(name string) string {
	switch name {
	case "E":
		if v.e == 0 {
			return "A"
		}
		return string(v.e)
	case "CR", "IR", "AR":
		return "H"
	case "MSI", "MSA":
		return "X"
	}
	i, ok := index[name]
	if !ok {
		panic("cvss4: no metric " + name)
	}
	return string(v.base[i])
}
