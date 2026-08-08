package core

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDefaultConfigFileIsParseable は -init が書き出す設定を parseConfig が読めることを確かめる。
//
// この検査が無かったため、生成テンプレートが Config の型から外れたまま 1 年以上残っていた。
// テンプレートは raw string なので、型を変えてもコンパイルは通る。書いたものを自分で読む検査を
// 1 つ置けば、その種のずれはここで落ちる。
func TestDefaultConfigFileIsParseable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sisakulint.yaml")

	if err := writeDefaultConfigFile(path); err != nil {
		t.Fatalf("writeDefaultConfigFile: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if _, err := parseConfig(b, path); err != nil {
		t.Fatalf("生成した設定を読み直せない: %v", err)
	}
}

// TestDefaultConfigFileHasNoTabs は生成物にタブ文字が無いことを確かめる。
//
// raw string の閉じインデントがそのまま出力へ入ると、YAML はタブを受け付けないので解釈に失敗する。
// 実際にそうなっていた。
func TestDefaultConfigFileHasNoTabs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sisakulint.yaml")
	if err := writeDefaultConfigFile(path); err != nil {
		t.Fatalf("writeDefaultConfigFile: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	for i, line := range splitLines(string(b)) {
		for _, r := range line {
			if r == '\t' {
				t.Fatalf("%d 行目にタブ文字がある: %q", i+1, line)
			}
		}
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i, r := range s {
		if r == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
