package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestWorkflowSecretTaintMap_RegisterJobOutputs_StepsRef(t *testing.T) {
	t.Parallel()

	m := NewWorkflowSecretTaintMap()
	stepOutputs := map[string]map[string]string{
		"derive": {
			"token": "secrets.S",
		},
	}
	outputs := map[string]*ast.Output{
		"token": {
			Name:  &ast.String{Value: "token"},
			Value: &ast.String{Value: "${{ steps.derive.outputs.token }}"},
		},
	}
	m.RegisterJobOutputs("extract", stepOutputs, outputs)

	origin, registered := m.IsSecretNeedsOutput("extract", "token")
	if !registered {
		t.Fatal("job should be registered after RegisterJobOutputs")
	}
	if origin != "secrets.S" {
		t.Fatalf("origin = %q, want %q", origin, "secrets.S")
	}
}

func TestWorkflowSecretTaintMap_RegisterJobOutputs_CleanOutput(t *testing.T) {
	t.Parallel()

	m := NewWorkflowSecretTaintMap()
	outputs := map[string]*ast.Output{
		"sha": {
			Name:  &ast.String{Value: "sha"},
			Value: &ast.String{Value: "${{ steps.build.outputs.sha }}"},
		},
	}
	m.RegisterJobOutputs("safe-job", nil, outputs)

	origin, registered := m.IsSecretNeedsOutput("safe-job", "sha")
	if !registered {
		t.Fatal("job should be registered even for clean outputs")
	}
	if origin != "" {
		t.Fatalf("clean output should have no secret origin, got: %q", origin)
	}
}

func TestWorkflowSecretTaintMap_MultiHopChain(t *testing.T) {
	t.Parallel()

	m := NewWorkflowSecretTaintMap()
	outputsA := map[string]*ast.Output{
		"token": {
			Name:  &ast.String{Value: "token"},
			Value: &ast.String{Value: "${{ steps.derive.outputs.token }}"},
		},
	}
	m.RegisterJobOutputs("job-a", map[string]map[string]string{
		"derive": {
			"token": "secrets.S",
		},
	}, outputsA)

	outputsB := map[string]*ast.Output{
		"processed": {
			Name:  &ast.String{Value: "processed"},
			Value: &ast.String{Value: "${{ needs.job-a.outputs.token }}"},
		},
	}
	m.RegisterJobOutputs("job-b", nil, outputsB)

	path, origin, ok := m.ResolveFromExprStr("needs.job-b.outputs.processed")
	if !ok {
		t.Fatal("needs.job-b.outputs.processed should resolve")
	}
	if path != "needs.job-b.outputs.processed" {
		t.Fatalf("path = %q, want needs.job-b.outputs.processed", path)
	}
	if origin != "secrets.S" {
		t.Fatalf("origin = %q, want secrets.S", origin)
	}
}

func TestWorkflowSecretTaintMap_MultiHopChain_ReverseRegistrationOrder(t *testing.T) {
	t.Parallel()

	m := NewWorkflowSecretTaintMap()
	outputsB := map[string]*ast.Output{
		"processed": {
			Name:  &ast.String{Value: "processed"},
			Value: &ast.String{Value: "${{ needs.job-a.outputs.token }}"},
		},
	}
	m.RegisterJobOutputs("job-b", nil, outputsB)

	outputsA := map[string]*ast.Output{
		"token": {
			Name:  &ast.String{Value: "token"},
			Value: &ast.String{Value: "${{ steps.derive.outputs.token }}"},
		},
	}
	m.RegisterJobOutputs("job-a", map[string]map[string]string{
		"derive": {
			"token": "secrets.S",
		},
	}, outputsA)

	m.ResolvePendingJobOutputs()

	path, origin, ok := m.ResolveFromExprStr("needs.job-b.outputs.processed")
	if !ok {
		t.Fatal("needs.job-b.outputs.processed should resolve after pending output resolution")
	}
	if path != "needs.job-b.outputs.processed" {
		t.Fatalf("path = %q, want needs.job-b.outputs.processed", path)
	}
	if origin != "secrets.S" {
		t.Fatalf("origin = %q, want secrets.S", origin)
	}
}

func TestWorkflowSecretTaintMap_RegisterJobOutputs_MultipleOrigins(t *testing.T) {
	t.Parallel()

	m := NewWorkflowSecretTaintMap()
	outputs := map[string]*ast.Output{
		"combined": {
			Name:  &ast.String{Value: "combined"},
			Value: &ast.String{Value: "${{ steps.a.outputs.one }}-${{ steps.b.outputs.two }}-${{ steps.a.outputs.one }}"},
		},
	}
	m.RegisterJobOutputs("extract", map[string]map[string]string{
		"a": {
			"one": "secrets.ONE",
		},
		"b": {
			"two": "secrets.TWO",
		},
	}, outputs)

	origin, registered := m.IsSecretNeedsOutput("extract", "combined")
	if !registered {
		t.Fatal("job should be registered")
	}
	if !strings.Contains(origin, "secrets.ONE") || !strings.Contains(origin, "secrets.TWO") {
		t.Fatalf("origin should contain both secrets, got: %q", origin)
	}
	if strings.Count(origin, "secrets.ONE") != 1 {
		t.Fatalf("origin should deduplicate repeated secrets, got: %q", origin)
	}
}
