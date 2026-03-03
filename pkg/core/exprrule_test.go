package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

// TestExpressionRule tests the creation of ExpressionRule
func TestExpressionRule(t *testing.T) {
	actionsCache := NewLocalActionsMetadataCache(nil, nil)
	workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)

	rule := ExpressionRule(actionsCache, workflowsCache)

	if rule == nil {
		t.Fatal("ExpressionRule() returned nil")
	}
	if rule.RuleName != "expression" {
		t.Errorf("Expected rule name 'expression', got '%s'", rule.RuleName)
	}
	if rule.RuleDesc != "Checks for syntax errors in expressions ${{ }} syntax" {
		t.Errorf("Expected specific description, got '%s'", rule.RuleDesc)
	}
	if rule.LocalActionsCache != actionsCache {
		t.Error("LocalActionsCache not set correctly")
	}
	if rule.LocalWorkflowsCache != workflowsCache {
		t.Error("LocalWorkflowsCache not set correctly")
	}
}

// TestExprRule_checkString tests basic string expression checking
func TestExprRule_checkString(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		quoted      bool
		wantErrStr  string
		wantNoError bool
	}{
		{
			name:        "valid expression",
			value:       "${{ github.ref }}",
			quoted:      true,
			wantNoError: true,
		},
		{
			name:        "invalid syntax - unclosed",
			value:       "${{ github.ref",
			quoted:      true,
			wantErrStr:  "",
			wantNoError: false,
		},
		{
			name:        "valid string without expression",
			value:       "hello world",
			quoted:      true,
			wantNoError: true,
		},
		{
			name:        "valid expression with function",
			value:       "${{ contains(github.ref, 'main') }}",
			quoted:      true,
			wantNoError: true,
		},
		{
			name:        "multiple expressions",
			value:       "${{ github.ref }} and ${{ github.sha }}",
			quoted:      true,
			wantNoError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actionsCache := NewLocalActionsMetadataCache(nil, nil)
			workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)
			rule := ExpressionRule(actionsCache, workflowsCache)

			pos := &ast.Position{Line: 1, Col: 1}
			str := &ast.String{
				Value:  tt.value,
				Quoted: tt.quoted,
				Pos:    pos,
			}

			result := rule.checkString(str, "")

			if tt.wantNoError {
				if len(rule.Errors()) > 0 {
					t.Errorf("Expected no errors, but got %d errors: %v", len(rule.Errors()), rule.Errors())
				}
			} else {
				if len(rule.Errors()) == 0 && tt.wantErrStr != "" {
					t.Error("Expected an error but got none")
				}
			}

			if tt.wantNoError && result == nil && strings.Contains(tt.value, "${{") {
				t.Error("Expected typed expressions but got nil")
			}
		})
	}
}

// TestExprRule_checkOneExpression tests single expression checking
func TestExprRule_checkOneExpression(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		wantType     string
		wantNoErrors bool
	}{
		{
			name:         "string context access",
			value:        "${{ github.ref }}",
			wantType:     "string",
			wantNoErrors: true,
		},
		{
			name:         "boolean expression",
			value:        "${{ true }}",
			wantType:     "bool",
			wantNoErrors: true,
		},
		{
			name:         "number expression",
			value:        "${{ 42 }}",
			wantType:     "number",
			wantNoErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actionsCache := NewLocalActionsMetadataCache(nil, nil)
			workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)
			rule := ExpressionRule(actionsCache, workflowsCache)

			pos := &ast.Position{Line: 1, Col: 1}
			str := &ast.String{
				Value:  tt.value,
				Quoted: true,
				Pos:    pos,
			}

			exprType := rule.checkOneExpression(str, "test value", "")

			if tt.wantNoErrors && len(rule.Errors()) > 0 {
				t.Errorf("Expected no errors, but got %d: %v", len(rule.Errors()), rule.Errors())
			}

			if exprType != nil && exprType.String() != tt.wantType {
				t.Errorf("Expected type %s, got %s", tt.wantType, exprType.String())
			}
		})
	}
}

// TestExprRule_checkBool tests boolean expression validation
func TestExprRule_checkBool(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		wantError   bool
		errorSubstr string
	}{
		{
			name:      "valid boolean expression",
			value:     "${{ true }}",
			wantError: false,
		},
		{
			name:      "valid comparison",
			value:     "${{ github.ref == 'main' }}",
			wantError: false,
		},
		{
			name:        "invalid type - string",
			value:       "${{ 'not a bool' }}",
			wantError:   true,
			errorSubstr: "must be bool",
		},
		{
			name:        "invalid type - number",
			value:       "${{ 42 }}",
			wantError:   true,
			errorSubstr: "must be bool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actionsCache := NewLocalActionsMetadataCache(nil, nil)
			workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)
			rule := ExpressionRule(actionsCache, workflowsCache)

			pos := &ast.Position{Line: 1, Col: 1}
			boolVal := &ast.Bool{
				Expression: &ast.String{
					Value:  tt.value,
					Quoted: true,
					Pos:    pos,
				},
			}

			rule.checkBool(boolVal, "")

			hasError := len(rule.Errors()) > 0
			if hasError != tt.wantError {
				t.Errorf("Expected error=%v, got error=%v (errors: %v)", tt.wantError, hasError, rule.Errors())
			}

			if tt.wantError && tt.errorSubstr != "" && hasError {
				found := false
				for _, err := range rule.Errors() {
					if strings.Contains(err.Description, tt.errorSubstr) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected error containing '%s', but got: %v", tt.errorSubstr, rule.Errors())
				}
			}
		})
	}
}

// TestExprRule_checkIfCondition tests if condition validation
func TestExprRule_checkIfCondition(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		wantError   bool
		errorSubstr string
	}{
		{
			name:      "valid boolean expression",
			value:     "${{ success() }}",
			wantError: false,
		},
		{
			name:      "valid comparison",
			value:     "${{ github.event_name == 'push' }}",
			wantError: false,
		},
		{
			name:      "valid without wrapper",
			value:     "success()",
			wantError: false,
		},
		{
			name:      "valid logical expression",
			value:     "!canceled()",
			wantError: false,
		},
		{
			name:      "valid and/or",
			value:     "true && false",
			wantError: false,
		},
		{
			name:      "valid - string is truthy in if condition",
			value:     "${{ 'string value' }}",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actionsCache := NewLocalActionsMetadataCache(nil, nil)
			workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)
			rule := ExpressionRule(actionsCache, workflowsCache)

			pos := &ast.Position{Line: 1, Col: 1}
			str := &ast.String{
				Value:  tt.value,
				Quoted: true,
				Pos:    pos,
			}

			rule.checkIfCondition(str, KeyPathJobStepsIf)

			hasError := len(rule.Errors()) > 0
			if hasError != tt.wantError {
				t.Errorf("Expected error=%v, got error=%v (errors: %v)", tt.wantError, hasError, rule.Errors())
			}

			if tt.wantError && tt.errorSubstr != "" && hasError {
				found := false
				for _, err := range rule.Errors() {
					if strings.Contains(err.Description, tt.errorSubstr) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected error containing '%s', but got: %v", tt.errorSubstr, rule.Errors())
				}
			}
		})
	}
}

// TestExprRule_checkObjectTy tests object type validation
func TestExprRule_checkObjectTy(t *testing.T) {
	tests := []struct {
		name      string
		inputType expressions.ExprType
		wantError bool
	}{
		{
			name:      "valid object type",
			inputType: expressions.NewEmptyObjectType(),
			wantError: false,
		},
		{
			name:      "valid unknown type",
			inputType: expressions.UnknownType{},
			wantError: false,
		},
		{
			name:      "invalid - string type",
			inputType: expressions.StringType{},
			wantError: true,
		},
		{
			name:      "invalid - array type",
			inputType: &expressions.ArrayType{Elem: expressions.StringType{}},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actionsCache := NewLocalActionsMetadataCache(nil, nil)
			workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)
			rule := ExpressionRule(actionsCache, workflowsCache)

			pos := &ast.Position{Line: 1, Col: 1}
			result := rule.checkObjectTy(tt.inputType, pos, "test object")

			hasError := len(rule.Errors()) > 0
			if hasError != tt.wantError {
				t.Errorf("Expected error=%v, got error=%v (errors: %v)", tt.wantError, hasError, rule.Errors())
			}

			if !tt.wantError && result == nil {
				t.Error("Expected non-nil result for valid type")
			}
		})
	}
}

// TestExprRule_checkArrayTy tests array type validation
func TestExprRule_checkArrayTy(t *testing.T) {
	tests := []struct {
		name      string
		inputType expressions.ExprType
		wantError bool
	}{
		{
			name:      "valid array type",
			inputType: &expressions.ArrayType{Elem: expressions.StringType{}},
			wantError: false,
		},
		{
			name:      "valid unknown type",
			inputType: expressions.UnknownType{},
			wantError: false,
		},
		{
			name:      "invalid - string type",
			inputType: expressions.StringType{},
			wantError: true,
		},
		{
			name:      "invalid - object type",
			inputType: expressions.NewEmptyObjectType(),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actionsCache := NewLocalActionsMetadataCache(nil, nil)
			workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)
			rule := ExpressionRule(actionsCache, workflowsCache)

			pos := &ast.Position{Line: 1, Col: 1}
			result := rule.checkArrayTy(tt.inputType, pos, "test array")

			hasError := len(rule.Errors()) > 0
			if hasError != tt.wantError {
				t.Errorf("Expected error=%v, got error=%v (errors: %v)", tt.wantError, hasError, rule.Errors())
			}

			if !tt.wantError && result == nil {
				t.Error("Expected non-nil result for valid type")
			}
		})
	}
}

// TestExprRule_checkNumberTy tests number type validation
func TestExprRule_checkNumberTy(t *testing.T) {
	tests := []struct {
		name      string
		inputType expressions.ExprType
		wantError bool
	}{
		{
			name:      "valid number type",
			inputType: expressions.NumberType{},
			wantError: false,
		},
		{
			name:      "valid unknown type",
			inputType: expressions.UnknownType{},
			wantError: false,
		},
		{
			name:      "invalid - string type",
			inputType: expressions.StringType{},
			wantError: true,
		},
		{
			name:      "invalid - bool type",
			inputType: expressions.BoolType{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actionsCache := NewLocalActionsMetadataCache(nil, nil)
			workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)
			rule := ExpressionRule(actionsCache, workflowsCache)

			pos := &ast.Position{Line: 1, Col: 1}
			result := rule.checkNumberTy(tt.inputType, pos, "test number")

			hasError := len(rule.Errors()) > 0
			if hasError != tt.wantError {
				t.Errorf("Expected error=%v, got error=%v (errors: %v)", tt.wantError, hasError, rule.Errors())
			}

			if !tt.wantError && result == nil {
				t.Error("Expected non-nil result for valid type")
			}
		})
	}
}

// TestExprRule_checkTemplateEvaluatedType tests invalid template types
func TestExprRule_checkTemplateEvaluatedType(t *testing.T) {
	tests := []struct {
		name      string
		exprType  expressions.ExprType
		wantError bool
	}{
		{
			name:      "valid - string type",
			exprType:  expressions.StringType{},
			wantError: false,
		},
		{
			name:      "valid - number type",
			exprType:  expressions.NumberType{},
			wantError: false,
		},
		{
			name:      "valid - bool type",
			exprType:  expressions.BoolType{},
			wantError: false,
		},
		{
			name:      "invalid - object type",
			exprType:  expressions.NewEmptyObjectType(),
			wantError: true,
		},
		{
			name:      "invalid - array type",
			exprType:  &expressions.ArrayType{Elem: expressions.StringType{}},
			wantError: true,
		},
		{
			name:      "invalid - null type",
			exprType:  expressions.NullType{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actionsCache := NewLocalActionsMetadataCache(nil, nil)
			workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)
			rule := ExpressionRule(actionsCache, workflowsCache)

			pos := ast.Position{Line: 1, Col: 1}
			typedExprs := []typedExpression{
				{typ: tt.exprType, pos: pos},
			}

			rule.checkTemplateEvaluatedType(typedExprs)

			hasError := len(rule.Errors()) > 0
			if hasError != tt.wantError {
				t.Errorf("Expected error=%v, got error=%v (errors: %v)", tt.wantError, hasError, rule.Errors())
			}
		})
	}
}

// TestExprRule_checkEnv tests environment variable checking
func TestExprRule_checkEnv(t *testing.T) {
	tests := []struct {
		name      string
		setupEnv  func() *ast.Env
		wantError bool
	}{
		{
			name: "nil env",
			setupEnv: func() *ast.Env {
				return nil
			},
			wantError: false,
		},
		{
			name: "valid env with vars",
			setupEnv: func() *ast.Env {
				return &ast.Env{
					Vars: map[string]*ast.EnvVar{
						"MY_VAR": {
							Name:  &ast.String{Value: "MY_VAR", Pos: &ast.Position{Line: 1, Col: 1}},
							Value: &ast.String{Value: "value", Pos: &ast.Position{Line: 1, Col: 10}},
						},
					},
				}
			},
			wantError: false,
		},
		{
			name: "valid env with expression",
			setupEnv: func() *ast.Env {
				return &ast.Env{
					Expression: &ast.String{
						Value:  "${{ matrix.env }}",
						Quoted: true,
						Pos:    &ast.Position{Line: 1, Col: 1},
					},
				}
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actionsCache := NewLocalActionsMetadataCache(nil, nil)
			workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)
			rule := ExpressionRule(actionsCache, workflowsCache)

			// Setup matrix type for env expression test
			if tt.name == "valid env with expression" {
				rule.MatrixType = expressions.NewStrictObjectType(map[string]expressions.ExprType{
					"env": expressions.NewEmptyObjectType(),
				})
			}

			env := tt.setupEnv()
			rule.checkEnv(env, KeyPathJobStepsEnv)

			hasError := len(rule.Errors()) > 0
			if hasError != tt.wantError {
				t.Errorf("Expected error=%v, got error=%v (errors: %v)", tt.wantError, hasError, rule.Errors())
			}
		})
	}
}

// TestExprRule_checkRawYAMLValue tests raw YAML value checking
func TestExprRule_checkRawYAMLValue(t *testing.T) {
	tests := []struct {
		name         string
		setupValue   func() ast.RawYAMLValue
		expectedType string
	}{
		{
			name: "string value",
			setupValue: func() ast.RawYAMLValue {
				return &ast.RawYAMLString{Value: "test", Posi: &ast.Position{Line: 1, Col: 1}}
			},
			expectedType: "string",
		},
		{
			name: "boolean value - true",
			setupValue: func() ast.RawYAMLValue {
				return &ast.RawYAMLString{Value: "true", Posi: &ast.Position{Line: 1, Col: 1}}
			},
			expectedType: "bool",
		},
		{
			name: "boolean value - false",
			setupValue: func() ast.RawYAMLValue {
				return &ast.RawYAMLString{Value: "false", Posi: &ast.Position{Line: 1, Col: 1}}
			},
			expectedType: "bool",
		},
		{
			name: "null value",
			setupValue: func() ast.RawYAMLValue {
				return &ast.RawYAMLString{Value: "null", Posi: &ast.Position{Line: 1, Col: 1}}
			},
			expectedType: "null",
		},
		{
			name: "number value",
			setupValue: func() ast.RawYAMLValue {
				return &ast.RawYAMLString{Value: "42", Posi: &ast.Position{Line: 1, Col: 1}}
			},
			expectedType: "number",
		},
		{
			name: "object value",
			setupValue: func() ast.RawYAMLValue {
				return &ast.RawYAMLObject{
					Props: map[string]ast.RawYAMLValue{
						"key": &ast.RawYAMLString{Value: "value", Posi: &ast.Position{Line: 1, Col: 6}},
					},
					Posi: &ast.Position{Line: 1, Col: 1},
				}
			},
			expectedType: "{key: string}",
		},
		{
			name: "array value",
			setupValue: func() ast.RawYAMLValue {
				return &ast.RawYAMLArray{
					Elems: []ast.RawYAMLValue{
						&ast.RawYAMLString{Value: "item1", Posi: &ast.Position{Line: 1, Col: 3}},
						&ast.RawYAMLString{Value: "item2", Posi: &ast.Position{Line: 2, Col: 3}},
					},
					Posi: &ast.Position{Line: 1, Col: 1},
				}
			},
			expectedType: "array<string>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actionsCache := NewLocalActionsMetadataCache(nil, nil)
			workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)
			rule := ExpressionRule(actionsCache, workflowsCache)

			value := tt.setupValue()
			exprType := rule.checkRawYAMLValue(value)

			if exprType == nil {
				t.Fatal("Expected non-nil type")
			}

			if exprType.String() != tt.expectedType {
				t.Errorf("Expected type %s, got %s", tt.expectedType, exprType.String())
			}
		})
	}
}

// TestConvertExprLineColToPos tests position conversion
func TestConvertExprLineColToPos(t *testing.T) {
	tests := []struct {
		name     string
		line     int
		col      int
		lineBase int
		colBase  int
		wantLine int
		wantCol  int
	}{
		{
			name:     "basic conversion",
			line:     1,
			col:      1,
			lineBase: 10,
			colBase:  5,
			wantLine: 10,
			wantCol:  5,
		},
		{
			name:     "offset conversion",
			line:     5,
			col:      10,
			lineBase: 100,
			colBase:  20,
			wantLine: 104,
			wantCol:  29,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pos := convertExprLineColToPos(tt.line, tt.col, tt.lineBase, tt.colBase)

			if pos.Line != tt.wantLine {
				t.Errorf("Expected line %d, got %d", tt.wantLine, pos.Line)
			}
			if pos.Col != tt.wantCol {
				t.Errorf("Expected col %d, got %d", tt.wantCol, pos.Col)
			}
		})
	}
}

// TestExprRule_checkInt tests integer checking
func TestExprRule_checkInt(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantError bool
	}{
		{
			name:      "valid number expression",
			value:     "${{ 42 }}",
			wantError: false,
		},
		{
			name:      "invalid - string expression",
			value:     "${{ 'not a number' }}",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actionsCache := NewLocalActionsMetadataCache(nil, nil)
			workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)
			rule := ExpressionRule(actionsCache, workflowsCache)

			intVal := &ast.Int{
				Expression: &ast.String{
					Value:  tt.value,
					Quoted: true,
					Pos:    &ast.Position{Line: 1, Col: 1},
				},
			}

			rule.checkInt(intVal, "")

			hasError := len(rule.Errors()) > 0
			if hasError != tt.wantError {
				t.Errorf("Expected error=%v, got error=%v (errors: %v)", tt.wantError, hasError, rule.Errors())
			}
		})
	}
}

// TestExprRule_checkFloat tests float checking
func TestExprRule_checkFloat(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantError bool
	}{
		{
			name:      "valid number expression",
			value:     "${{ 3.14 }}",
			wantError: false,
		},
		{
			name:      "invalid - string expression",
			value:     "${{ 'not a number' }}",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actionsCache := NewLocalActionsMetadataCache(nil, nil)
			workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)
			rule := ExpressionRule(actionsCache, workflowsCache)

			floatVal := &ast.Float{
				Expression: &ast.String{
					Value:  tt.value,
					Quoted: true,
					Pos:    &ast.Position{Line: 1, Col: 1},
				},
			}

			rule.checkFloat(floatVal, "")

			hasError := len(rule.Errors()) > 0
			if hasError != tt.wantError {
				t.Errorf("Expected error=%v, got error=%v (errors: %v)", tt.wantError, hasError, rule.Errors())
			}
		})
	}
}

// TestExprRule_checkStrings tests multiple string checking
func TestExprRule_checkStrings(t *testing.T) {
	actionsCache := NewLocalActionsMetadataCache(nil, nil)
	workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)
	rule := ExpressionRule(actionsCache, workflowsCache)

	strings := []*ast.String{
		{Value: "${{ github.ref }}", Quoted: true, Pos: &ast.Position{Line: 1, Col: 1}},
		{Value: "literal", Quoted: true, Pos: &ast.Position{Line: 2, Col: 1}},
		{Value: "${{ github.sha }}", Quoted: true, Pos: &ast.Position{Line: 3, Col: 1}},
	}

	rule.checkStrings(strings, "")

	// Should not error on valid expressions
	if len(rule.Errors()) > 0 {
		t.Errorf("Expected no errors, got %d: %v", len(rule.Errors()), rule.Errors())
	}
}

// TestExprRule_VisitWorkflowPre tests workflow pre-visit
func TestExprRule_VisitWorkflowPre(t *testing.T) {
	actionsCache := NewLocalActionsMetadataCache(nil, nil)
	workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)
	rule := ExpressionRule(actionsCache, workflowsCache)

	workflow := &ast.Workflow{
		Name: &ast.String{Value: "Test Workflow", Pos: &ast.Position{Line: 1, Col: 1}},
		On:   []ast.Event{},
		Jobs: map[string]*ast.Job{},
	}

	err := rule.VisitWorkflowPre(workflow)
	if err != nil {
		t.Errorf("VisitWorkflowPre returned error: %v", err)
	}

	if rule.WorkflowDefinition != workflow {
		t.Error("WorkflowDefinition not set correctly")
	}
}

// TestExprRule_VisitWorkflowPost tests workflow post-visit
func TestExprRule_VisitWorkflowPost(t *testing.T) {
	actionsCache := NewLocalActionsMetadataCache(nil, nil)
	workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)
	rule := ExpressionRule(actionsCache, workflowsCache)

	workflow := &ast.Workflow{
		Name: &ast.String{Value: "Test Workflow", Pos: &ast.Position{Line: 1, Col: 1}},
		On:   []ast.Event{},
		Jobs: map[string]*ast.Job{},
	}

	rule.WorkflowDefinition = workflow

	err := rule.VisitWorkflowPost(workflow)
	if err != nil {
		t.Errorf("VisitWorkflowPost returned error: %v", err)
	}

	if rule.WorkflowDefinition != nil {
		t.Error("WorkflowDefinition should be nil after post-visit")
	}
}

// TestExprRule_VisitJobPre tests job pre-visit
func TestExprRule_VisitJobPre(t *testing.T) {
	actionsCache := NewLocalActionsMetadataCache(nil, nil)
	workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)
	rule := ExpressionRule(actionsCache, workflowsCache)

	// Need to set WorkflowDefinition first
	rule.WorkflowDefinition = &ast.Workflow{
		Jobs: map[string]*ast.Job{},
	}

	job := &ast.Job{
		ID:   &ast.String{Value: "test-job", Pos: &ast.Position{Line: 1, Col: 1}},
		Name: &ast.String{Value: "Test Job", Pos: &ast.Position{Line: 1, Col: 1}},
		RunsOn: &ast.Runner{
			Labels: []*ast.String{
				{Value: "ubuntu-latest", Pos: &ast.Position{Line: 1, Col: 1}},
			},
		},
	}

	err := rule.VisitJobPre(job)
	if err != nil {
		t.Errorf("VisitJobPre returned error: %v", err)
	}

	if rule.StepsType == nil {
		t.Error("StepsType should be initialized")
	}
}

// TestExprRule_VisitJobPost tests job post-visit
func TestExprRule_VisitJobPost(t *testing.T) {
	actionsCache := NewLocalActionsMetadataCache(nil, nil)
	workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)
	rule := ExpressionRule(actionsCache, workflowsCache)

	rule.MatrixType = expressions.NewEmptyStrictObjectType()
	rule.StepsType = expressions.NewEmptyStrictObjectType()
	rule.NeedsType = expressions.NewEmptyStrictObjectType()

	job := &ast.Job{
		ID: &ast.String{Value: "test-job", Pos: &ast.Position{Line: 1, Col: 1}},
	}

	err := rule.VisitJobPost(job)
	if err != nil {
		t.Errorf("VisitJobPost returned error: %v", err)
	}

	if rule.MatrixType != nil {
		t.Error("MatrixType should be nil after post-visit")
	}
	if rule.StepsType != nil {
		t.Error("StepsType should be nil after post-visit")
	}
	if rule.NeedsType != nil {
		t.Error("NeedsType should be nil after post-visit")
	}
}

// TestExprRule_VisitStep tests step visit
func TestExprRule_VisitStep(t *testing.T) {
	actionsCache := NewLocalActionsMetadataCache(nil, nil)
	workflowsCache := NewLocalReusableWorkflowCache(nil, "", nil)
	rule := ExpressionRule(actionsCache, workflowsCache)

	rule.StepsType = expressions.NewEmptyStrictObjectType()

	step := &ast.Step{
		ID:   &ast.String{Value: "test-step", Pos: &ast.Position{Line: 1, Col: 1}},
		Name: &ast.String{Value: "Test Step", Pos: &ast.Position{Line: 1, Col: 1}},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: "echo 'hello'", Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}

	err := rule.VisitStep(step)
	if err != nil {
		t.Errorf("VisitStep returned error: %v", err)
	}

	// Check that step was added to StepsType
	stepID := strings.ToLower(step.ID.Value)
	if _, ok := rule.StepsType.Props[stepID]; !ok {
		t.Error("Step should be added to StepsType")
	}
}
