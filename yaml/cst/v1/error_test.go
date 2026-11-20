package cst

import (
	"bytes"
	"testing"
)

func codes(tr *Tree) []ErrorCode {
	var cs []ErrorCode
	for _, e := range tr.Errors() {
		cs = append(cs, e.Code)
	}
	return cs
}

func TestConstraintViolations(t *testing.T) {
	cases := []struct {
		src  string
		want []ErrorCode // nil: no errors
		skel string      // "" : not checked
	}{
		{"!e!foo a", []ErrorCode{ErrUndefinedTagHandle}, doc1("=VAL <tag> :")},
		{"%TAG !e! tag:x,2000:\n---\n!e!foo a", nil, ""},
		{"%TAG !e! tag:x,2000:\n--- !e!a b\n...\n--- !e!c d\n", []ErrorCode{ErrUndefinedTagHandle}, ""},
		{"!!str a\n", nil, ""},
		{"!a b\n", nil, ""},
		{"%YAML 1.2\n%YAML 1.2\n---\n", []ErrorCode{ErrDuplicateDirective}, ""},
		{"%TAG !e! a:\n%TAG !e! b:\n---\n", []ErrorCode{ErrDuplicateDirective}, ""},
		{"&a &b x", []ErrorCode{ErrDuplicateProperty}, doc1("=VAL &a :")},
		{"!a !b x", []ErrorCode{ErrDuplicateProperty}, doc1("=VAL <tag> :")},
		{"k: a\xffb\n", []ErrorCode{ErrInvalidUTF8}, doc1("+MAP\n=VAL :\n=VAL :\n-MAP")},
		{"k: a\x01b\n", []ErrorCode{ErrInvalidChar}, doc1("+MAP\n=VAL :\n=VAL :\n-MAP")},
		{"k: \"a\x7fb\"\n", nil, ""}, // nb-json allows DEL in quoted scalars
		{"# \xe3\x81\x82 ok\nk: \xf0\x9f\x99\x82\n", nil, ""},
	}
	for _, c := range cases {
		tr := Parse([]byte(c.src))
		if err := validate(tr); err != nil {
			t.Errorf("%q: %v", c.src, err)
		}
		if !bytes.Equal(tr.Bytes(), []byte(c.src)) {
			t.Errorf("%q: Bytes differ", c.src)
		}
		got := codes(tr)
		if len(got) != len(c.want) {
			t.Errorf("%q: errors %v, want codes %v", c.src, tr.Errors(), c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%q: errors %v, want codes %v", c.src, tr.Errors(), c.want)
			}
		}
		if c.skel != "" && skeleton(c.src) != c.skel {
			t.Errorf("%q: skeleton\n%s\nwant\n%s", c.src, skeleton(c.src), c.skel)
		}
	}
}
