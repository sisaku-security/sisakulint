package analysis

import (
	"encoding/json"
	"testing"
)

// TestExpressionKeyJSON: each key and each error has the name of the
// schema of findings; the unset value has none.
func TestExpressionKeyJSON(t *testing.T) {
	for k, want := range map[ExpressionKey]string{ExpressionKeyJobTimeoutMinutes: `"job-timeout-minutes"`, ExpressionKeyStepContinueOnError: `"step-continue-on-error"`, ExpressionKeyRunsOn: `"runs-on"`} {
		if b, err := json.Marshal(k); err != nil || string(b) != want {
			t.Errorf("%v: %s %v, want %s", k, b, err, want)
		}
	}
	if len(ExpressionKeys()) != 32 {
		t.Errorf("%d keys", len(ExpressionKeys()))
	}
	if _, err := json.Marshal(ExpressionKeyUnset); err == nil {
		t.Error("ExpressionKeyUnset has a name")
	}
	for e, want := range map[EvaluationError]string{EvaluationErrorType: `"value-type"`, EvaluationErrorFormat: `"format-arguments"`, EvaluationErrorCase: `"case-predicate"`, EvaluationErrorFromJSON: `"fromjson-argument"`} {
		if b, err := json.Marshal(e); err != nil || string(b) != want {
			t.Errorf("%v: %s %v, want %s", e, b, err, want)
		}
	}
}
