// Package corpus finds the corpus and lists its files for the tests. The
// corpus is not part of the code: the tests that read it skip when it is
// not there (Dir), unless a run asks for the whole of it.
package corpus

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// File is one file of the corpus.
type File struct {
	Path string // absolute
	Rel  string // as in manifest.tsv, such as files/real-world/...
	Kind Kind   // guessed (yaml/corpus/README.md)
}

// Kind is what a file of the corpus is, as manifest.tsv writes it.
type Kind uint8

const (
	KindOther Kind = iota
	KindWorkflow
	KindAction
	KindDependabot
	KindLanguageservicesTest
)

var kindNames = [...]string{"other", "workflow", "action", "dependabot", "languageservices-test"}

func (k Kind) String() string { return kindNames[k] }

// Full is whether ACTIONS_CORPUS=full: the heavy tests run on every file.
func Full() bool { return os.Getenv("ACTIONS_CORPUS") == "full" }

// fullVariables are the variables that ask the tests for the whole corpus.
var fullVariables = []string{"ACTIONS_CORPUS", "CST_CORPUS", "EDIT_CORPUS"}

// Locate finds the corpus: the directory CORPUS_DIR names, or else the
// default one beside the code. It is an error when CORPUS_DIR names no
// directory, or when the default is not there and a variable of
// fullVariables asks for the whole corpus; present is false when the
// default is not there and none asks.
func Locate() (dir string, present bool, err error) {
	_, file, _, _ := runtime.Caller(0)
	return locate(filepath.Join(filepath.Dir(file), "..", "..", "yaml", "corpus"))
}

func locate(def string) (string, bool, error) {
	if dir := os.Getenv("CORPUS_DIR"); dir != "" {
		if !isDir(dir) {
			return "", false, fmt.Errorf("CORPUS_DIR %s is not a directory", dir)
		}
		return dir, true, nil
	}
	if isDir(def) {
		return def, true, nil
	}
	for _, v := range fullVariables {
		if os.Getenv(v) == "full" {
			return "", false, fmt.Errorf("%s=full asks for the whole corpus, but there is none at %s: set CORPUS_DIR", v, def)
		}
	}
	return "", false, nil
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// Dir is the directory of the corpus. It fails tb when Locate does, and
// skips it when there is no corpus.
func Dir(tb testing.TB) string {
	tb.Helper()
	dir, present, err := Locate()
	if err != nil {
		tb.Fatal(err)
	}
	if !present {
		tb.Skip("no corpus: set CORPUS_DIR")
	}
	return dir
}

// Files lists the files of manifest.tsv whose path starts with one of
// prefixes (all when there is none), in the corpus of Dir. Unless Full, it
// keeps every seventh file, so the default tests stay fast.
func Files(tb testing.TB, prefixes ...string) []File {
	tb.Helper()
	files, err := filesIn(Dir(tb), prefixes)
	if err != nil {
		tb.Fatal(err)
	}
	return files
}

func filesIn(root string, prefixes []string) ([]File, error) {
	f, err := os.Open(filepath.Join(root, "manifest.tsv"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var files []File
	sc := bufio.NewScanner(f)
	sc.Scan() // the header
	n := 0
	for sc.Scan() {
		cols := strings.Split(sc.Text(), "\t")
		if len(cols) < 3 || !hasPrefix(cols[0], prefixes) {
			continue
		}
		k := slices.Index(kindNames[:], cols[2])
		if k < 0 {
			return nil, fmt.Errorf("%s: the kind %q is not known", cols[0], cols[2])
		}
		n++
		if !Full() && n%7 != 1 {
			continue
		}
		files = append(files, File{Path: filepath.Join(root, cols[0]), Rel: cols[0], Kind: Kind(k)})
	}
	return files, sc.Err()
}

func hasPrefix(s string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// SeedFiles is Files when there is a corpus, and none when there is not:
// for the seeds of a fuzz test, which runs on its other seeds.
func SeedFiles(tb testing.TB, prefixes ...string) []File {
	tb.Helper()
	dir, present, err := Locate()
	if err != nil {
		tb.Fatal(err)
	}
	if !present {
		return nil
	}
	files, err := filesIn(dir, prefixes)
	if err != nil {
		tb.Fatal(err)
	}
	return files
}
