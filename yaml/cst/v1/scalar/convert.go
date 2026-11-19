package scalar

import (
	"math"
	"strconv"
)

// The core schema's rules (10.3.2), written without regular expressions.

// null | Null | NULL | ~ | empty
func isNull(s string) bool {
	switch s {
	case "", "~", "null", "Null", "NULL":
		return true
	}
	return false
}

// true | True | TRUE | false | False | FALSE
func isBool(s string) bool {
	_, ok := Bool(s)
	return ok
}

// [-+]? [0-9]+ | 0o [0-7]+ | 0x [0-9a-fA-F]+
func isInt(s string) bool {
	switch {
	case len(s) > 2 && s[:2] == "0o":
		return all(s[2:], func(c byte) bool { return c >= '0' && c <= '7' })
	case len(s) > 2 && s[:2] == "0x":
		return all(s[2:], isHex)
	}
	return digits(sign(s)) == len(sign(s)) && len(sign(s)) > 0
}

// [-+]? ( \. [0-9]+ | [0-9]+ ( \. [0-9]* )? ) ( [eE] [-+]? [0-9]+ )?
// | [-+]? \. (inf | Inf | INF) | \. (nan | NaN | NAN)
func isFloat(s string) bool {
	switch s {
	case ".nan", ".NaN", ".NAN":
		return true
	}
	s = sign(s)
	switch s {
	case ".inf", ".Inf", ".INF":
		return true
	}
	i := digits(s)
	if i < len(s) && s[i] == '.' {
		f := digits(s[i+1:])
		if i == 0 && f == 0 {
			return false
		}
		i += 1 + f
	} else if i == 0 {
		return false
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		e := sign(s[i+1:])
		return digits(e) == len(e) && len(e) > 0
	}
	return i == len(s)
}

func sign(s string) string {
	if s != "" && (s[0] == '-' || s[0] == '+') {
		return s[1:]
	}
	return s
}

// digits is the length of the run of [0-9] at the start of s.
func digits(s string) int {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i
}

func all(s string, f func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !f(s[i]) {
			return false
		}
	}
	return true
}

// Bool converts s by the core schema's bool rule.
func Bool(s string) (bool, bool) {
	switch s {
	case "true", "True", "TRUE":
		return true, true
	case "false", "False", "FALSE":
		return false, true
	}
	return false, false
}

// Int converts s by the core schema's int rule; false when it does not fit
// in an int64.
func Int(s string) (int64, bool) {
	if !isInt(s) {
		return 0, false
	}
	base, text := 10, s
	switch {
	case len(s) > 2 && s[:2] == "0o":
		base, text = 8, s[2:]
	case len(s) > 2 && s[:2] == "0x":
		base, text = 16, s[2:]
	}
	v, err := strconv.ParseInt(text, base, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// Float converts s by the core schema's float rule. A value too large for
// a float64 is ±Inf.
func Float(s string) (float64, bool) {
	if !isFloat(s) {
		return 0, false
	}
	switch sign(s) {
	case ".inf", ".Inf", ".INF":
		if s[0] == '-' {
			return math.Inf(-1), true
		}
		return math.Inf(1), true
	case ".nan", ".NaN", ".NAN":
		return math.NaN(), true
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil && !isRange(err) {
		return 0, false
	}
	return v, true
}

func isRange(err error) bool {
	e, ok := err.(*strconv.NumError)
	return ok && e.Err == strconv.ErrRange
}
