package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestParseDockerImageRef(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantRegistry   string
		wantNamespace  string
		wantRepository string
		wantTag        string
		wantDigest     string
		wantIsExpr     bool
	}{
		{
			name:           "simple image with tag",
			input:          "node:18",
			wantRepository: "node",
			wantTag:        "18",
		},
		{
			name:           "simple image with latest tag",
			input:          "node:latest",
			wantRepository: "node",
			wantTag:        "latest",
		},
		{
			name:           "simple image no tag",
			input:          "node",
			wantRepository: "node",
		},
		{
			name:           "image with sha256 digest",
			input:          "node:18@sha256:abc123def456",
			wantRepository: "node",
			wantTag:        "18",
			wantDigest:     "abc123def456",
		},
		{
			name:           "image with only sha256 digest",
			input:          "node@sha256:abc123def456",
			wantRepository: "node",
			wantDigest:     "abc123def456",
		},
		{
			name:           "namespace/repository",
			input:          "library/node:18",
			wantNamespace:  "library",
			wantRepository: "node",
			wantTag:        "18",
		},
		{
			name:           "registry/repository",
			input:          "ghcr.io/myimage:v1.0.0",
			wantRegistry:   "ghcr.io",
			wantRepository: "myimage",
			wantTag:        "v1.0.0",
		},
		{
			name:           "registry/namespace/repository",
			input:          "ghcr.io/myorg/myimage:v1.0.0",
			wantRegistry:   "ghcr.io",
			wantNamespace:  "myorg",
			wantRepository: "myimage",
			wantTag:        "v1.0.0",
		},
		{
			name:           "full reference with digest",
			input:          "ghcr.io/myorg/myimage:v1.0.0@sha256:abc123",
			wantRegistry:   "ghcr.io",
			wantNamespace:  "myorg",
			wantRepository: "myimage",
			wantTag:        "v1.0.0",
			wantDigest:     "abc123",
		},
		{
			name:           "expression",
			input:          "${{ matrix.image }}",
			wantIsExpr:     true,
		},
		{
			name:           "expression with text",
			input:          "node:${{ matrix.version }}",
			wantIsExpr:     true,
		},
		{
			name:           "docker.io registry explicit",
			input:          "docker.io/library/node:18",
			wantRegistry:   "docker.io",
			wantNamespace:  "library",
			wantRepository: "node",
			wantTag:        "18",
		},
		{
			name:           "localhost registry",
			input:          "localhost/myimage:latest",
			wantRegistry:   "localhost",
			wantRepository: "myimage",
			wantTag:        "latest",
		},
		{
			name:           "registry with port",
			input:          "localhost:5000/myimage:v1",
			wantRegistry:   "localhost:5000",
			wantRepository: "myimage",
			wantTag:        "v1",
		},
		{
			name:           "postgres official image",
			input:          "postgres:14",
			wantRepository: "postgres",
			wantTag:        "14",
		},
		{
			name:           "mysql official image with alpine",
			input:          "mysql:8.0-alpine",
			wantRepository: "mysql",
			wantTag:        "8.0-alpine",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseDockerImageRef(tt.input)

			if got.Registry != tt.wantRegistry {
				t.Errorf("Registry = %q, want %q", got.Registry, tt.wantRegistry)
			}
			if got.Namespace != tt.wantNamespace {
				t.Errorf("Namespace = %q, want %q", got.Namespace, tt.wantNamespace)
			}
			if got.Repository != tt.wantRepository {
				t.Errorf("Repository = %q, want %q", got.Repository, tt.wantRepository)
			}
			if got.Tag != tt.wantTag {
				t.Errorf("Tag = %q, want %q", got.Tag, tt.wantTag)
			}
			if got.Digest != tt.wantDigest {
				t.Errorf("Digest = %q, want %q", got.Digest, tt.wantDigest)
			}
			if got.IsExpression != tt.wantIsExpr {
				t.Errorf("IsExpression = %v, want %v", got.IsExpression, tt.wantIsExpr)
			}
		})
	}
}

func TestDockerImageRef_GetPinStatus(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantStatus ImagePinStatus
	}{
		{
			name:       "pinned by sha256",
			input:      "node:18@sha256:abc123",
			wantStatus: ImagePinStatusPinned,
		},
		{
			name:       "pinned by sha256 only",
			input:      "node@sha256:abc123",
			wantStatus: ImagePinStatusPinned,
		},
		{
			name:       "latest tag",
			input:      "node:latest",
			wantStatus: ImagePinStatusLatest,
		},
		{
			name:       "no tag (implicit latest)",
			input:      "node",
			wantStatus: ImagePinStatusLatest,
		},
		{
			name:       "specific tag only",
			input:      "node:18",
			wantStatus: ImagePinStatusTagOnly,
		},
		{
			name:       "semver tag only",
			input:      "node:18.0.0",
			wantStatus: ImagePinStatusTagOnly,
		},
		{
			name:       "expression",
			input:      "${{ matrix.image }}",
			wantStatus: ImagePinStatusExpression,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := ParseDockerImageRef(tt.input)
			got := ref.GetPinStatus()
			if got != tt.wantStatus {
				t.Errorf("GetPinStatus() = %v, want %v", got, tt.wantStatus)
			}
		})
	}
}

func TestUnpinnedImagesRule_VisitJobPre(t *testing.T) {
	tests := []struct {
		name       string
		job        *ast.Job
		wantErrors int
	}{
		{
			name: "no container",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
			},
			wantErrors: 0,
		},
		{
			name: "container with pinned image",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				Container: &ast.Container{
					Image: &ast.String{
						Value: "node:18@sha256:abc123def456789",
						Pos:   &ast.Position{Line: 5, Col: 10},
					},
				},
			},
			wantErrors: 0,
		},
		{
			name: "container with latest tag",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				Container: &ast.Container{
					Image: &ast.String{
						Value: "node:latest",
						Pos:   &ast.Position{Line: 5, Col: 10},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "container with no tag",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				Container: &ast.Container{
					Image: &ast.String{
						Value: "node",
						Pos:   &ast.Position{Line: 5, Col: 10},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "container with specific tag (no digest)",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				Container: &ast.Container{
					Image: &ast.String{
						Value: "node:18",
						Pos:   &ast.Position{Line: 5, Col: 10},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "container with expression",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				Container: &ast.Container{
					Image: &ast.String{
						Value: "${{ matrix.image }}",
						Pos:   &ast.Position{Line: 5, Col: 10},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "service with unpinned image",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				Services: map[string]*ast.Service{
					"postgres": {
						Name: &ast.String{Value: "postgres"},
						Container: &ast.Container{
							Image: &ast.String{
								Value: "postgres:latest",
								Pos:   &ast.Position{Line: 10, Col: 12},
							},
						},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "service with pinned image",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				Services: map[string]*ast.Service{
					"postgres": {
						Name: &ast.String{Value: "postgres"},
						Container: &ast.Container{
							Image: &ast.String{
								Value: "postgres:14@sha256:abc123",
								Pos:   &ast.Position{Line: 10, Col: 12},
							},
						},
					},
				},
			},
			wantErrors: 0,
		},
		{
			name: "container and service both unpinned",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				Container: &ast.Container{
					Image: &ast.String{
						Value: "node:18",
						Pos:   &ast.Position{Line: 5, Col: 10},
					},
				},
				Services: map[string]*ast.Service{
					"postgres": {
						Name: &ast.String{Value: "postgres"},
						Container: &ast.Container{
							Image: &ast.String{
								Value: "postgres:14",
								Pos:   &ast.Position{Line: 10, Col: 12},
							},
						},
					},
					"redis": {
						Name: &ast.String{Value: "redis"},
						Container: &ast.Container{
							Image: &ast.String{
								Value: "redis:latest",
								Pos:   &ast.Position{Line: 15, Col: 12},
							},
						},
					},
				},
			},
			wantErrors: 3,
		},
		{
			name: "multiple services mixed pinning",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				Services: map[string]*ast.Service{
					"postgres": {
						Name: &ast.String{Value: "postgres"},
						Container: &ast.Container{
							Image: &ast.String{
								Value: "postgres:14@sha256:pinned123",
								Pos:   &ast.Position{Line: 10, Col: 12},
							},
						},
					},
					"redis": {
						Name: &ast.String{Value: "redis"},
						Container: &ast.Container{
							Image: &ast.String{
								Value: "redis:7",
								Pos:   &ast.Position{Line: 15, Col: 12},
							},
						},
					},
				},
			},
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewUnpinnedImagesRule()
			err := rule.VisitJobPre(tt.job)
			if err != nil {
				t.Fatalf("VisitJobPre() error = %v", err)
			}

			gotErrors := len(rule.Errors())
			if gotErrors != tt.wantErrors {
				t.Errorf("got %d errors, want %d errors", gotErrors, tt.wantErrors)
				for i, e := range rule.Errors() {
					t.Logf("error[%d]: %s", i, e.Description)
				}
			}
		})
	}
}

func TestUnpinnedImagesRule_ErrorMessages(t *testing.T) {
	tests := []struct {
		name            string
		imageValue      string
		wantMsgContains string
	}{
		{
			name:            "latest tag message",
			imageValue:      "node:latest",
			wantMsgContains: "using 'latest' tag",
		},
		{
			name:            "no tag message",
			imageValue:      "node",
			wantMsgContains: "using 'latest' tag or no tag",
		},
		{
			name:            "tag without digest message",
			imageValue:      "node:18",
			wantMsgContains: "using a tag without SHA256 digest",
		},
		{
			name:            "matrix expression message",
			imageValue:      "${{ matrix.image }}",
			wantMsgContains: "matrix variable",
		},
		{
			name:            "general expression message",
			imageValue:      "${{ env.IMAGE }}",
			wantMsgContains: "expression",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewUnpinnedImagesRule()
			job := &ast.Job{
				ID: &ast.String{Value: "test-job"},
				Container: &ast.Container{
					Image: &ast.String{
						Value: tt.imageValue,
						Pos:   &ast.Position{Line: 5, Col: 10},
					},
				},
			}

			err := rule.VisitJobPre(job)
			if err != nil {
				t.Fatalf("VisitJobPre() error = %v", err)
			}

			errors := rule.Errors()
			if len(errors) != 1 {
				t.Fatalf("expected 1 error, got %d", len(errors))
			}

			if !strings.Contains(errors[0].Description, tt.wantMsgContains) {
				t.Errorf("error message %q does not contain %q", errors[0].Description, tt.wantMsgContains)
			}
		})
	}
}

