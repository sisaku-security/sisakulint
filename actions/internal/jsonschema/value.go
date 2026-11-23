package jsonschema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

type kind uint8

const (
	kNull kind = iota
	kBool
	kNumber
	kString
	kArray
	kObject
)

var kindNames = [...]string{"null", "boolean", "number", "string", "array", "object"}

// value is a JSON value that keeps the order of an object's members.
type value struct {
	kind kind
	b    bool
	num  string // as written
	str  string
	arr  []*value
	obj  []member
}

type member struct {
	key string
	val *value
}

func (v *value) get(key string) (*value, bool) {
	for _, m := range v.obj {
		if m.key == key {
			return m.val, true
		}
	}
	return nil, false
}

// parse reads exactly one JSON value. It rejects what is not UTF-8 and
// objects with a key written twice.
func parse(data []byte) (*value, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("not UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec, "")
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("more than one JSON value")
	}
	return v, nil
}

func parseValue(dec *json.Decoder, at string) (*value, error) {
	tok, err := dec.Token()
	if err == io.EOF {
		return nil, errors.New("no JSON value")
	}
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case nil:
		return &value{kind: kNull}, nil
	case bool:
		return &value{kind: kBool, b: t}, nil
	case json.Number:
		return &value{kind: kNumber, num: string(t)}, nil
	case string:
		return &value{kind: kString, str: t}, nil
	case json.Delim:
		if t == '[' {
			v := &value{kind: kArray}
			for i := 0; dec.More(); i++ {
				e, err := parseValue(dec, at+"/"+strconv.Itoa(i))
				if err != nil {
					return nil, err
				}
				v.arr = append(v.arr, e)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return v, nil
		}
		v := &value{kind: kObject}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			k := kt.(string)
			if _, dup := v.get(k); dup {
				return nil, fmt.Errorf("%s: key %q is written twice", pointerOr(at), k)
			}
			e, err := parseValue(dec, at+"/"+escapePointer(k))
			if err != nil {
				return nil, err
			}
			v.obj = append(v.obj, member{k, e})
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return v, nil
	}
	return nil, fmt.Errorf("unexpected token %v", tok)
}

const maxSafeInteger = 1 << 53

// integer reads a number whose value is an integer of absolute value at
// most 2^53, the integers every JSON implementation reads exactly. The
// value counts, not how it is written: 1.0 and 1e0 are the integer 1, as
// in the data model of JSON Schema (draft 2020-12, 4.2.2) and in JCS. It
// reads the digits once, in time linear in the length of num.
func integer(num string) (int64, bool) {
	mant, exp, hasExp := strings.Cut(strings.ToLower(num), "e")
	neg := strings.HasPrefix(mant, "-")
	whole, frac, _ := strings.Cut(strings.TrimPrefix(mant, "-"), ".")
	// the value is digits times 10^e, digits without leading zeros
	digits := strings.TrimLeft(whole+frac, "0")
	if digits == "" {
		return 0, true
	}
	e := 0
	if hasExp {
		n, err := strconv.Atoi(exp)
		if err != nil || n > 1<<40 || n < -(1<<40) {
			// past this, a value with a digit other than 0 is below 1 or
			// far above 2^53, whatever its digits
			return 0, false
		}
		e = n
	}
	e -= len(frac)
	t := len(digits) - len(strings.TrimRight(digits, "0"))
	digits, e = digits[:len(digits)-t], e+t
	// 2^53 has 16 digits
	if e < 0 || len(digits)+e > 16 {
		return 0, false
	}
	n, err := strconv.ParseInt(digits+strings.Repeat("0", e), 10, 64)
	if err != nil || n > maxSafeInteger {
		return 0, false
	}
	if neg {
		n = -n
	}
	return n, true
}

func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

func unescapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~1", "/"), "~0", "~")
}

func pointerOr(at string) string {
	if at == "" {
		return "/"
	}
	return at
}
