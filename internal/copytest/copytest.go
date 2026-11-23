// Package copytest keeps the copies of the files of other projects that the
// tests read as they were copied. A copy is a directory with a README.md at
// its top, which gives where the files come from, their license, the number
// of the files and Sum of the directory.
package copytest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// Sum is the number of the regular files under dir, but the README.md at
// the top of dir, and the sha256 of the lines "<sha256>  ./<path>\n" of the
// files in byte order of their paths from dir: what
//
//	find . -type f -not -path ./README.md -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum
//
// writes in dir.
func Sum(dir string) (int, string, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() || p == filepath.Join(dir, "README.md") {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		paths = append(paths, "./"+filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return 0, "", err
	}
	slices.Sort(paths)
	list := sha256.New()
	for _, p := range paths {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(p)))
		if err != nil {
			return 0, "", err
		}
		fmt.Fprintf(list, "%x  %s\n", sha256.Sum256(b), p)
	}
	return len(paths), hex.EncodeToString(list.Sum(nil)), nil
}
