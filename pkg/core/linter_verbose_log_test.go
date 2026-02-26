package core

import (
	"bytes"
	"strings"
	"testing"
)

func TestVerboseLogFormat(t *testing.T) {
	t.Parallel()

	workflow := `name: Test
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - run: echo hello
`

	var logBuf bytes.Buffer
	opts := &LinterOptions{
		IsVerboseOutputEnabled: true,
		LogOutputDestination:   &logBuf,
	}
	linter, err := NewLinter(bytes.NewBuffer(nil), opts)
	if err != nil {
		t.Fatalf("NewLinter failed: %v", err)
	}

	_, err = linter.Lint("test.yaml", []byte(workflow), nil)
	if err != nil {
		t.Fatalf("Lint failed: %v", err)
	}

	logOutput := logBuf.String()
	lines := strings.Split(strings.TrimSpace(logOutput), "\n")

	for _, line := range lines {
		// "found in" が2回現れてはならない
		if count := strings.Count(line, "found in"); count > 1 {
			t.Errorf("verbose log contains duplicate 'found in': %q", line)
		}
		// 数値が連続してスペースで区切られてはならない (例: "0 0 ms")
		// "parsed workflow in" の行の検証
		if strings.Contains(line, "parsed workflow in") {
			if strings.Contains(line, "in 0 0") || strings.Contains(line, "in 1 ") {
				t.Errorf("verbose log 'parsed workflow in' has garbled format: %q", line)
			}
		}
		// "Found total" の行の検証
		if strings.Contains(line, "Found total") || strings.Contains(line, "found total") {
			if strings.Contains(line, "found in") && strings.Contains(line, "errors found") {
				t.Errorf("verbose log total errors line has garbled format: %q", line)
			}
		}
	}
}
