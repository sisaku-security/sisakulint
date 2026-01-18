package remote

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestExtractReusableActions(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []ReusableAction
	}{
		{
			name: "single reusable workflow",
			content: `
name: CI
on: push
jobs:
  call-workflow:
    uses: owner/repo/.github/workflows/reusable.yml@main
`,
			want: []ReusableAction{
				{
					Owner:    "owner",
					Repo:     "repo",
					Path:     ".github/workflows/reusable.yml",
					Ref:      "main",
					FullPath: "owner/repo/.github/workflows/reusable.yml@main",
				},
			},
		},
		{
			name: "multiple reusable workflows",
			content: `
name: CI
on: push
jobs:
  lint:
    uses: actions/reusable-workflows/.github/workflows/lint.yml@v1
  test:
    uses: org/shared/.github/workflows/test.yml@main
`,
			want: nil,
		},
		{
			name: "no reusable workflows",
			content: `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`,
			want: []ReusableAction{},
		},
		{
			name: "reusable workflow without ref",
			content: `
name: CI
on: push
jobs:
  call:
    uses: owner/repo/.github/workflows/workflow.yml
`,
			want: []ReusableAction{
				{
					Owner:    "owner",
					Repo:     "repo",
					Path:     ".github/workflows/workflow.yml",
					Ref:      "main",
					FullPath: "owner/repo/.github/workflows/workflow.yml",
				},
			},
		},
		{
			name:    "invalid yaml",
			content: "this is not valid yaml: [",
			want:    []ReusableAction{},
		},
		{
			name: "workflow without jobs",
			content: `
name: Empty
on: push
`,
			want: []ReusableAction{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractReusableActions([]byte(tt.content))

			if tt.name == "multiple reusable workflows" {
				if len(got) != 2 {
					t.Errorf("extractReusableActions() returned %d actions, want 2", len(got))
				}
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("extractReusableActions() returned %d actions, want %d", len(got), len(tt.want))
				return
			}
			for i, action := range got {
				if action.Owner != tt.want[i].Owner {
					t.Errorf("action[%d].Owner = %q, want %q", i, action.Owner, tt.want[i].Owner)
				}
				if action.Repo != tt.want[i].Repo {
					t.Errorf("action[%d].Repo = %q, want %q", i, action.Repo, tt.want[i].Repo)
				}
				if action.Path != tt.want[i].Path {
					t.Errorf("action[%d].Path = %q, want %q", i, action.Path, tt.want[i].Path)
				}
				if action.Ref != tt.want[i].Ref {
					t.Errorf("action[%d].Ref = %q, want %q", i, action.Ref, tt.want[i].Ref)
				}
			}
		})
	}
}

func TestParseReusableAction(t *testing.T) {
	tests := []struct {
		name  string
		uses  string
		want  *ReusableAction
		isNil bool
	}{
		{
			name: "valid with ref",
			uses: "owner/repo/.github/workflows/workflow.yml@v1",
			want: &ReusableAction{
				Owner:    "owner",
				Repo:     "repo",
				Path:     ".github/workflows/workflow.yml",
				Ref:      "v1",
				FullPath: "owner/repo/.github/workflows/workflow.yml@v1",
			},
		},
		{
			name: "valid with sha",
			uses: "owner/repo/.github/workflows/workflow.yml@abc123def456",
			want: &ReusableAction{
				Owner:    "owner",
				Repo:     "repo",
				Path:     ".github/workflows/workflow.yml",
				Ref:      "abc123def456",
				FullPath: "owner/repo/.github/workflows/workflow.yml@abc123def456",
			},
		},
		{
			name: "valid without ref",
			uses: "owner/repo/.github/workflows/workflow.yml",
			want: &ReusableAction{
				Owner:    "owner",
				Repo:     "repo",
				Path:     ".github/workflows/workflow.yml",
				Ref:      "main",
				FullPath: "owner/repo/.github/workflows/workflow.yml",
			},
		},
		{
			name:  "regular action (not reusable)",
			uses:  "actions/checkout@v4",
			isNil: true,
		},
		{
			name:  "local path",
			uses:  "./.github/workflows/local.yml",
			isNil: true,
		},
		{
			name:  "empty string",
			uses:  "",
			isNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseReusableAction(tt.uses)
			if tt.isNil {
				if got != nil {
					t.Errorf("parseReusableAction(%q) = %+v, want nil", tt.uses, got)
				}
				return
			}
			if got == nil {
				t.Errorf("parseReusableAction(%q) = nil, want %+v", tt.uses, tt.want)
				return
			}
			if got.Owner != tt.want.Owner {
				t.Errorf("Owner = %q, want %q", got.Owner, tt.want.Owner)
			}
			if got.Repo != tt.want.Repo {
				t.Errorf("Repo = %q, want %q", got.Repo, tt.want.Repo)
			}
			if got.Path != tt.want.Path {
				t.Errorf("Path = %q, want %q", got.Path, tt.want.Path)
			}
			if got.Ref != tt.want.Ref {
				t.Errorf("Ref = %q, want %q", got.Ref, tt.want.Ref)
			}
		})
	}
}

func TestNewScanner_Validation(t *testing.T) {
	tests := []struct {
		name    string
		opts    *ScannerOptions
		wantErr bool
	}{
		{
			name: "valid options",
			opts: &ScannerOptions{
				Parallelism: 3,
				Limit:       10,
				LintFunc:    func(string, []byte) (bool, error) { return false, nil },
			},
			wantErr: false,
		},
		{
			name: "missing LintFunc",
			opts: &ScannerOptions{
				Parallelism: 3,
				Limit:       10,
				LintFunc:    nil,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewScanner(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestScanWorkflowRecursive_ContextCancellation(t *testing.T) {
	scanner := &Scanner{
		verbose:  false,
		output:   io.Discard,
		lintFunc: func(string, []byte) (bool, error) { return false, nil },
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	wf := &WorkflowFile{
		Path:    ".github/workflows/test.yml",
		Content: []byte("name: test"),
		RepoInfo: &RepositoryInfo{
			Owner:    "owner",
			Name:     "repo",
			FullName: "owner/repo",
		},
	}

	var scanned sync.Map
	result := scanner.scanWorkflowRecursive(ctx, wf, 0, &scanned)

	if result {
		t.Errorf("scanWorkflowRecursive with canceled context should return false")
	}
}

func TestScanWorkflowRecursive_AlreadyScanned(t *testing.T) {
	callCount := 0
	scanner := &Scanner{
		verbose: false,
		output:  io.Discard,
		lintFunc: func(string, []byte) (bool, error) {
			callCount++
			return false, nil
		},
	}

	ctx := context.Background()
	wf := &WorkflowFile{
		Path:    ".github/workflows/test.yml",
		Content: []byte("name: test"),
		RepoInfo: &RepositoryInfo{
			Owner:    "owner",
			Name:     "repo",
			FullName: "owner/repo",
		},
	}

	var scanned sync.Map

	scanner.scanWorkflowRecursive(ctx, wf, 0, &scanned)
	if callCount != 1 {
		t.Errorf("First scan: lintFunc called %d times, want 1", callCount)
	}

	scanner.scanWorkflowRecursive(ctx, wf, 0, &scanned)
	if callCount != 1 {
		t.Errorf("Second scan: lintFunc called %d times, want 1 (should skip)", callCount)
	}
}

func TestScanRepository_ContextCancellation(t *testing.T) {
	scanner := &Scanner{
		verbose:  false,
		output:   io.Discard,
		lintFunc: func(string, []byte) (bool, error) { return false, nil },
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	repo := &RepositoryInfo{
		Owner:    "owner",
		Name:     "repo",
		FullName: "owner/repo",
	}

	result := scanner.scanRepository(ctx, repo)

	if result.Error == nil {
		t.Errorf("scanRepository with canceled context should return error")
	}
	if !errors.Is(result.Error, context.Canceled) {
		t.Errorf("scanRepository error = %v, want context.Canceled", result.Error)
	}
}

func TestSyncMapConcurrency(t *testing.T) {
	var scanned sync.Map
	var wg sync.WaitGroup
	paths := []string{"path1", "path2", "path3", "path4", "path5"}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			path := paths[id%len(paths)]
			scanned.LoadOrStore(path, true)
			time.Sleep(time.Microsecond)
			scanned.Load(path)
		}(i)
	}

	wg.Wait()

	for _, path := range paths {
		if _, ok := scanned.Load(path); !ok {
			t.Errorf("path %q not found in scanned map", path)
		}
	}
}
