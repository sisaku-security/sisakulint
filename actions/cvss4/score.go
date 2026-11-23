// Copied from the CVSS v4.0 calculator of FIRST
// (https://github.com/FIRSTdotorg/cvss-v4-calculator at
// c5b0d409ae9f57c44264c6ce5f27d89298e1d32a), under its license:
//
// Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package cvss4

import (
	"fmt"
	"math"
	"strings"
)

// Score is a CVSS score, 0.0 to 10.0 in steps of 0.1.
type Score struct{ tenths uint8 }

// Tenths is s in tenths: 99 for 9.9.
func (s Score) Tenths() int { return int(s.tenths) }

// String is s with one decimal, as CVSS writes a score: 9.0, 10.0.
func (s Score) String() string { return fmt.Sprintf("%d.%d", s.tenths/10, s.tenths%10) }

// levels are the level of each value of each metric (cvss_score.js): the
// severity distance of a metric is the difference of two levels.
var levels = map[string]map[string]float64{
	"AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
	"PR": {"N": 0.0, "L": 0.1, "H": 0.2},
	"UI": {"N": 0.0, "P": 0.1, "A": 0.2},
	"AC": {"L": 0.0, "H": 0.1},
	"AT": {"N": 0.0, "P": 0.1},
	"VC": {"H": 0.0, "L": 0.1, "N": 0.2},
	"VI": {"H": 0.0, "L": 0.1, "N": 0.2},
	"VA": {"H": 0.0, "L": 0.1, "N": 0.2},
	"SC": {"H": 0.1, "L": 0.2, "N": 0.3},
	"SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
	"SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
	"CR": {"H": 0.0, "M": 0.1, "L": 0.2},
	"IR": {"H": 0.0, "M": 0.1, "L": 0.2},
	"AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}

// distanced are the metrics whose severity distances are found, in the
// order of the calculator.
var distanced = [...]string{"AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR"}

// step is the step of the levels. It is a variable, so that each product
// with it is one of float64 at run time, as in the calculator, and not a
// constant of arbitrary precision (7 * 0.1 is 0.7000000000000001 in
// float64, 0.7 as a constant).
var step = 0.1

// distancedAt is the index in distanced of each metric.
var distancedAt = func() map[string]int {
	m := map[string]int{}
	for i, name := range distanced {
		m[name] = i
	}
	return m
}()

// part is a highest severity vector of one EQ (a vector of maxComposed):
// the level of each metric of distanced it has, by the index in distanced.
type part [len(distanced)]struct {
	level float64
	has   bool
}

// composed are the vectors of maxComposed, each read into its part.
var composed = struct {
	eq1, eq2, eq4, eq5 map[int][]part
	eq3                map[int]map[int][]part
}{
	eq1: split(maxComposed.eq1), eq2: split(maxComposed.eq2), eq4: split(maxComposed.eq4), eq5: split(maxComposed.eq5),
	eq3: func() map[int]map[int][]part {
		out := map[int]map[int][]part{}
		for eq3, by6 := range maxComposed.eq3 {
			out[eq3] = split(by6)
		}
		return out
	}(),
}

// split is each vector of m read into its part.
func split(m map[int][]string) map[int][]part {
	out := map[int][]part{}
	for level, vs := range m {
		for _, s := range vs {
			var p part
			for x := range strings.SplitSeq(strings.TrimSuffix(s, "/"), "/") {
				name, value, _ := strings.Cut(x, ":")
				if i, ok := distancedAt[name]; ok {
					p[i].level, p[i].has = levels[name][value], true
				}
			}
			out[level] = append(out[level], p)
		}
	}
	return out
}

// Score is the score of v by the calculator (cvss_score.js): the score of
// its MacroVector, less the mean of the proportional distances to the
// MacroVectors below it, rounded to one decimal. It panics on a Vector
// ParseVector did not make, whose metrics have none of their values.
func (v Vector) Score() Score {
	if v.base[0] == 0 {
		panic("cvss4: Score of a Vector that ParseVector did not make")
	}
	if v.value("VC") == "N" && v.value("VI") == "N" && v.value("VA") == "N" && v.value("SC") == "N" && v.value("SI") == "N" && v.value("SA") == "N" {
		return Score{}
	}
	eq := v.macroVector()
	value, ok := lookup[key(eq)]
	if !ok {
		panic("cvss4: no score of the MacroVector " + key(eq)) // TestAll holds every vector to one
	}
	below := func(e [6]int) (float64, bool) {
		s, ok := lookup[key(e)]
		return s, ok
	}
	lower1, ok1 := below(with(eq, 0))
	lower2, ok2 := below(with(eq, 1))
	var lower36 float64
	var ok36 bool
	switch {
	case eq[2] == 1 && eq[5] == 1, eq[2] == 0 && eq[5] == 1:
		lower36, ok36 = below(with(eq, 2))
	case eq[2] == 1 && eq[5] == 0:
		lower36, ok36 = below(with(eq, 5))
	case eq[2] == 0 && eq[5] == 0:
		// the calculator takes left when left > right; a score not there
		// is undefined, and the comparison false
		left, okLeft := below(with(eq, 5))
		right, okRight := below(with(eq, 2))
		if okLeft && okRight && left > right {
			lower36, ok36 = left, true
		} else {
			lower36, ok36 = right, okRight
		}
	default: // 21 to 32, which is not there
		lower36, ok36 = below(with(with(eq, 2), 5))
	}
	lower4, ok4 := below(with(eq, 3))
	lower5, ok5 := below(with(eq, 4))

	d := v.distances(eq)
	sum := func(names ...string) float64 { // left to right, as the calculator adds them
		s := 0.0
		for _, name := range names {
			s += d[distancedAt[name]]
		}
		return s
	}
	distance1 := sum("AV", "PR", "UI")
	distance2 := sum("AC", "AT")
	distance36 := sum("VC", "VI", "VA", "CR", "IR", "AR")
	distance4 := sum("SC", "SI", "SA")

	maxSeverity1 := float64(float64(maxSeverity.eq1[eq[0]]) * step)
	maxSeverity2 := float64(float64(maxSeverity.eq2[eq[1]]) * step)
	maxSeverity36 := float64(float64(maxSeverity.eq3eq6[eq[2]][eq[5]]) * step)
	maxSeverity4 := float64(float64(maxSeverity.eq4[eq[3]]) * step)

	n := 0
	var normalized1, normalized2, normalized36, normalized4, normalized5 float64
	if ok1 {
		n++
		normalized1 = float64((value - lower1) * (distance1 / maxSeverity1))
	}
	if ok2 {
		n++
		normalized2 = float64((value - lower2) * (distance2 / maxSeverity2))
	}
	if ok36 {
		n++
		normalized36 = float64((value - lower36) * (distance36 / maxSeverity36))
	}
	if ok4 {
		n++
		normalized4 = float64((value - lower4) * (distance4 / maxSeverity4))
	}
	if ok5 {
		n++ // its proportion is always 0
		normalized5 = float64((value - lower5) * 0)
	}
	mean := 0.0
	if n > 0 {
		mean = (normalized1 + normalized2 + normalized36 + normalized4 + normalized5) / float64(n)
	}
	value -= mean
	value = min(max(value, 0), 10)
	return Score{uint8(jsRound(float64(value * 10)))}
}

// with is e with its EQ i one level lower (one more).
func with(e [6]int, i int) [6]int {
	e[i]++
	return e
}

// key is the key of lookup of the levels e: "001120".
func key(e [6]int) string {
	var b [6]byte
	for i, x := range e {
		b[i] = byte('0' + x)
	}
	return string(b[:])
}

// macroVector are the levels of EQ1 to EQ6 of v (macroVector of
// cvss_score.js).
func (v Vector) macroVector() [6]int {
	is := func(name, value string) bool { return v.value(name) == value }
	var eq [6]int
	switch {
	case is("AV", "N") && is("PR", "N") && is("UI", "N"):
		eq[0] = 0
	case (is("AV", "N") || is("PR", "N") || is("UI", "N")) && !is("AV", "P"):
		eq[0] = 1
	default:
		eq[0] = 2
	}
	if !(is("AC", "L") && is("AT", "N")) {
		eq[1] = 1
	}
	switch {
	case is("VC", "H") && is("VI", "H"):
		eq[2] = 0
	case is("VC", "H") || is("VI", "H") || is("VA", "H"):
		eq[2] = 1
	default:
		eq[2] = 2
	}
	switch {
	case is("MSI", "S") || is("MSA", "S"):
		eq[3] = 0
	case is("SC", "H") || is("SI", "H") || is("SA", "H"):
		eq[3] = 1
	default:
		eq[3] = 2
	}
	switch v.value("E") {
	case "P":
		eq[4] = 1
	case "U":
		eq[4] = 2
	}
	if !(is("CR", "H") && is("VC", "H") || is("IR", "H") && is("VI", "H") || is("AR", "H") && is("VA", "H")) {
		eq[5] = 1
	}
	return eq
}

// distances are the severity distances of v's metrics from the first of
// the highest severity vectors of its MacroVector that is not below v in
// any metric; from the last of them when none is, as the calculator
// leaves it.
func (v Vector) distances(eq [6]int) [len(distanced)]float64 {
	var mine [len(distanced)]float64
	for i, name := range distanced {
		mine[i] = levels[name][v.value(name)]
	}
	var d [len(distanced)]float64
search:
	for _, p1 := range composed.eq1[eq[0]] {
		for _, p2 := range composed.eq2[eq[1]] {
			for _, p3 := range composed.eq3[eq[2]][eq[5]] {
				for _, p4 := range composed.eq4[eq[3]] {
					for _, p5 := range composed.eq5[eq[4]] {
						below := false
						for i := range distanced {
							var highest float64
							for _, p := range [...]*part{&p1, &p2, &p3, &p4, &p5} {
								if p[i].has {
									highest = p[i].level
								}
							}
							d[i] = mine[i] - highest
							below = below || d[i] < 0
						}
						if !below {
							break search
						}
					}
				}
			}
		}
	}
	return d
}

// jsRound is Math.round of JavaScript: the nearest integer, a half up.
func jsRound(x float64) float64 {
	r := math.Floor(x)
	if x-r >= 0.5 {
		r++
	}
	return r
}
