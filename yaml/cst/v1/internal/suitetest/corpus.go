package suitetest

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/internal/corpus"
)

// CorpusRoot is the directory of the files of the corpus: files under
// corpus.Dir, which skips tb when there is no corpus.
func CorpusRoot(tb testing.TB) string {
	tb.Helper()
	return filepath.Join(corpus.Dir(tb), "files")
}

// CorpusSeeds is every file of the corpus (CorpusFiles) under root, the
// directory of its files, when there is a corpus, and none when there is
// not: for inputs that the corpus only adds to, such as the seeds of a fuzz
// test. A name made of a file should be its path from root, which is the
// same in every checkout.
func CorpusSeeds(tb testing.TB) (root string, files []string) {
	tb.Helper()
	dir, present, err := corpus.Locate()
	if err != nil {
		tb.Fatal(err)
	}
	if !present {
		return "", nil
	}
	root = filepath.Join(dir, "files")
	files, err = CorpusFiles(root)
	if err != nil {
		tb.Fatal(err)
	}
	return root, files
}

// CorpusFiles lists every .yml and .yaml file under root, which is
// CorpusRoot.
func CorpusFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}
