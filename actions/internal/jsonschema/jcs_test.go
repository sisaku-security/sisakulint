package jsonschema

import (
	"strings"
	"testing"
)

func TestCanonical(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`{"b":1,"a":2}`, `{"a":2,"b":1}`},
		{" { \"a\" : [ 1 , true , null ] } ", `{"a":[1,true,null]}`},
		{`"a/b"`, `"a/b"`},
		{`"\u00e9"`, "\"\xc3\xa9\""},
		{`"\u0001\b\t\n\f\r\"\\"`, `"\u0001\b\t\n\f\r\"\\"`},
		{`"\u001F"`, `"\u001f"`},
		{`-0`, `0`},
		{`9007199254740992`, `9007199254740992`},
		{`-9007199254740992`, `-9007199254740992`},
		// An integer written with a fraction or an exponent is the integer,
		// as ECMAScript writes it.
		{`1.0`, `1`},
		{`1e3`, `1000`},
		{`[2.50e1]`, `[25]`},
		// Keys sort by UTF-16 code units: U+10000 (a surrogate pair,
		// 0xD800...) comes before U+FFFF.
		{"{\"\xef\xbf\xbf\":1,\"\xf0\x90\x80\x80\":2}", "{\"\xf0\x90\x80\x80\":2,\"\xef\xbf\xbf\":1}"},
		{`{"a":{"d":1,"c":2}}`, `{"a":{"c":2,"d":1}}`},
	} {
		got, err := Canonical([]byte(c.in))
		if err != nil {
			t.Errorf("Canonical(%s): %v", c.in, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("Canonical(%s) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestCanonicalRejects(t *testing.T) {
	for _, in := range []string{
		`1.5`,
		`9007199254740993`,
		`{"a":1,"a":2}`,
		`[1,`,
		`1 2`,
		"\"\xff\"",
		``,
	} {
		if got, err := Canonical([]byte(in)); err == nil {
			t.Errorf("Canonical(%q) = %s, want an error", in, got)
		}
	}
}

func TestCanonicalErrorSaysWhy(t *testing.T) {
	_, err := Canonical([]byte(`{"a":1.5}`))
	if err == nil || !strings.Contains(err.Error(), "integer") {
		t.Errorf("error = %v, want one about integers", err)
	}
}
