package attackrun

import (
	"reflect"
	"testing"
)

func TestReadEnvFile(t *testing.T) {
	for _, c := range []struct {
		name, text string
		want       []EnvPair
		err        bool
	}{
		{"name=value", "a=1\n\nb=x=y\n", []EnvPair{{"a", "1"}, {"b", "x=y"}}, false},
		{"heredoc", "a<<E\nx\ny\nE\nb=2\n", []EnvPair{{"a", "x\ny"}, {"b", "2"}}, false},
		{"= before <<", "a=b<<c\n", []EnvPair{{"a", "b<<c"}}, false},
		{"an early delimiter closes it", "a<<E\nx\nE\nPWNED=1\nE\n", []EnvPair{{"a", "x"}, {"PWNED", "1"}}, true},
		{"CR stays in the line", "a=1\r\n", []EnvPair{{"a", "1\r"}}, false},
		{"no delimiter", "a<<E\nx\n", nil, true},
		{"the delimiter without a line break closes it", "a<<E\nx\nE", []EnvPair{{"a", "x"}}, false},
		{"a value line without a line break", "a<<E\nx", nil, true},
		{"empty name of a heredoc", "<<E\nE\n", nil, true},
	} {
		got, err := readEnvFile(c.text)
		if (err != nil) != c.err || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %q %v, want %q (error %v)", c.name, got, err, c.want, c.err)
		}
	}
}

func TestReadPathFile(t *testing.T) {
	got := readPathFile("/a\n\n/b\r\n/c\r/d")
	if want := []string{"/a", "/b", "/c", "/d"}; !reflect.DeepEqual(got, want) {
		t.Errorf("%q, want %q", got, want)
	}
}
