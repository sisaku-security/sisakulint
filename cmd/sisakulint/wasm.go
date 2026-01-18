//go:build js && wasm

package main

import (
	"bytes"
	"encoding/json"
	"syscall/js"

	"github.com/sisaku-security/sisakulint/pkg/core"
)

// LintError represents a single linting error for JSON serialization.
type LintError struct {
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Message string `json:"message"`
	Rule    string `json:"rule"`
}

// LintResult represents the result of linting for JSON serialization.
type LintResult struct {
	Filename string      `json:"filename"`
	Errors   []LintError `json:"errors"`
	Success  bool        `json:"success"`
}

func analyzeYAML(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		return map[string]any{
			"success": false,
			"errors": []map[string]any{
				{
					"line":    0,
					"column":  0,
					"message": "analyzeYAML requires 2 arguments: yamlContent and filename",
					"rule":    "wasm-api",
				},
			},
		}
	}

	yamlContent := args[0].String()
	filename := args[1].String()

	var output bytes.Buffer
	linterOpts := &core.LinterOptions{}

	l, err := core.NewLinter(&output, linterOpts)
	if err != nil {
		return map[string]any{
			"success": false,
			"errors": []map[string]any{
				{
					"line":    0,
					"column":  0,
					"message": "Failed to initialize linter: " + err.Error(),
					"rule":    "wasm-api",
				},
			},
		}
	}

	// Use "<stdin>" to skip file system access
	result, err := l.Lint("<stdin>", []byte(yamlContent), nil)
	if err != nil {
		return map[string]any{
			"success": false,
			"errors": []map[string]any{
				{
					"line":    0,
					"column":  0,
					"message": "Linting failed: " + err.Error(),
					"rule":    "wasm-api",
				},
			},
		}
	}

	lintResult := LintResult{
		Filename: filename,
		Errors:   make([]LintError, 0, len(result.Errors)),
		Success:  len(result.Errors) == 0,
	}

	for _, e := range result.Errors {
		lintResult.Errors = append(lintResult.Errors, LintError{
			Line:    e.LineNumber,
			Column:  e.ColNumber,
			Message: e.Description,
			Rule:    e.Type,
		})
	}

	jsonBytes, err := json.Marshal(lintResult)
	if err != nil {
		return map[string]any{
			"success": false,
			"errors": []map[string]any{
				{
					"line":    0,
					"column":  0,
					"message": "Failed to marshal result: " + err.Error(),
					"rule":    "wasm-api",
				},
			},
		}
	}

	return string(jsonBytes)
}

func init() {
	js.Global().Set("sisakulintAnalyze", js.FuncOf(analyzeYAML))
}

func main() {
	// Block forever to keep the Go runtime alive for JavaScript callbacks
	<-make(chan struct{})
}
