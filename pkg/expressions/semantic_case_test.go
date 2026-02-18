package expressions

import "testing"

// TestCaseFunctionSignature tests that the case function is recognized
func TestCaseFunctionSignature(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		expression  string
		wantErrors  bool
		description string
	}{
		{
			name:        "case with two conditions",
			expression:  "case(true, 'yes', 'no')}}",
			wantErrors:  false,
			description: "case(condition, valueIfTrue, defaultValue)",
		},
		{
			name:        "case with multiple conditions",
			expression:  "case(false, 'a', true, 'b', 'default')}}",
			wantErrors:  false,
			description: "case(cond1, val1, cond2, val2, default)",
		},
		{
			name:        "case with comparison expressions",
			expression:  "case(github.event_name == 'push', 'pushed', github.event_name == 'pull_request', 'pr', 'other')}}",
			wantErrors:  false,
			description: "case with comparison expressions",
		},
		{
			name:        "case with single condition and default",
			expression:  "case(github.ref == 'main', 'pass', 'fail')}}",
			wantErrors:  false,
			description: "case with comparison condition",
		},
		{
			name:        "case returns number",
			expression:  "case(true, 1, 0)}}",
			wantErrors:  false,
			description: "case can return numbers",
		},
		{
			name:        "case in if condition",
			expression:  "case(github.ref == 'refs/heads/main', true, false)}}",
			wantErrors:  false,
			description: "case returning bool for if condition",
		},
		{
			name:        "nested case",
			expression:  "case(true, case(false, 'a', 'b'), 'c')}}",
			wantErrors:  false,
			description: "nested case expressions",
		},
		{
			name:        "case with no arguments",
			expression:  "case()}}",
			wantErrors:  true,
			description: "case requires at least 3 arguments",
		},
		{
			name:        "case with only condition",
			expression:  "case(true)}}",
			wantErrors:  true,
			description: "case requires at least 3 arguments",
		},
		{
			name:        "case with missing default",
			expression:  "case(true, 'value')}}",
			wantErrors:  true,
			description: "case requires condition, value, and default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Parse the expression (needs to end with }} as per tokenizer requirements)
			tokenizer := NewTokenizer(tt.expression)
			parser := NewMiniParser()
			tree, parseErr := parser.Parse(tokenizer)

			if parseErr != nil {
				t.Fatalf("Parse error: %v", parseErr)
			}

			if tree == nil {
				t.Fatal("Parsed tree is nil")
			}

			// Check semantics
			checker := NewExprSemanticsChecker(false, nil)
			_, errs := checker.Check(tree)

			hasErrors := len(errs) > 0

			if hasErrors != tt.wantErrors {
				if hasErrors {
					t.Errorf("Expected no errors for %q, got: %v", tt.description, errs)
				} else {
					t.Errorf("Expected errors for %q, but got none", tt.description)
				}
			}
		})
	}
}

// TestCaseFunctionInBuiltinSignatures tests that case is in BuiltinFuncSignatures
func TestCaseFunctionInBuiltinSignatures(t *testing.T) {
	t.Parallel()

	sig, exists := BuiltinFuncSignatures["case"]
	if !exists {
		t.Fatal("case function not found in BuiltinFuncSignatures")
	}

	if len(sig) == 0 {
		t.Fatal("case function signature is empty")
	}

	// Check the signature properties
	caseSig := sig[0]
	if caseSig.Name != "case" {
		t.Errorf("Expected name 'case', got %q", caseSig.Name)
	}

	if !caseSig.VariableLengthParams {
		t.Error("case function should have variable length params")
	}

	// case needs at least 3 arguments: condition, valueIfTrue, defaultValue
	if len(caseSig.Params) < 3 {
		t.Errorf("case function should have at least 3 base params, got %d", len(caseSig.Params))
	}
}
