package core

import "testing"

func FuzzParse(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(""),
		[]byte("name: test\non: push\njobs: {}\n"),
		[]byte("jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"),
		[]byte("{{not yaml"),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, source []byte) {
		Parse(source)
	})
}
