package core

import (
	"bytes"
	"regexp"
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
		// "parsed workflow in" の行の検証: "in \d+ \d+" のような旧形式の崩れたフォーマットを検出
		if strings.Contains(line, "parsed workflow in") {
			if matched, _ := regexp.MatchString(`in \d+ \d+`, line); matched {
				t.Errorf("verbose log 'parsed workflow in' has garbled format (expected 'in %%dms'): %q", line)
			}
		}
		// "found N errors in" の行の検証: 現在のフォーマット "found %d errors in %dms" に一致することを確認
		if strings.Contains(line, "found") && strings.Contains(line, "errors in") {
			if matched, _ := regexp.MatchString(`found \d+ errors in \d+ms`, line); !matched {
				t.Errorf("verbose log total errors line does not match 'found %%d errors in %%dms': %q", line)
			}
		}
	}
}
