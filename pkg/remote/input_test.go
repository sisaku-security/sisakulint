package remote

import (
	"testing"
)

func TestParseInput_OwnerRepo(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantType  InputType
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{
			name:      "valid owner/repo",
			input:     "ultra-supara/sisakulint",
			wantType:  InputTypeOwnerRepo,
			wantOwner: "ultra-supara",
			wantRepo:  "sisakulint",
			wantErr:   false,
		},
		{
			name:      "owner/repo with numbers",
			input:     "user123/repo456",
			wantType:  InputTypeOwnerRepo,
			wantOwner: "user123",
			wantRepo:  "repo456",
			wantErr:   false,
		},
		{
			name:      "owner/repo with dashes",
			input:     "my-org/my-repo",
			wantType:  InputTypeOwnerRepo,
			wantOwner: "my-org",
			wantRepo:  "my-repo",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseInput(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseInput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if got.Type != tt.wantType {
				t.Errorf("ParseInput() Type = %v, want %v", got.Type, tt.wantType)
			}
			if got.Owner != tt.wantOwner {
				t.Errorf("ParseInput() Owner = %v, want %v", got.Owner, tt.wantOwner)
			}
			if got.Repo != tt.wantRepo {
				t.Errorf("ParseInput() Repo = %v, want %v", got.Repo, tt.wantRepo)
			}
		})
	}
}

func TestParseInput_URL(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantType  InputType
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{
			name:      "valid https URL",
			input:     "https://github.com/sisaku-security/sisakulint",
			wantType:  InputTypeURL,
			wantOwner: "sisaku-security",
			wantRepo:  "sisakulint",
			wantErr:   false,
		},
		{
			name:      "URL with trailing path",
			input:     "https://github.com/owner/repo/tree/main",
			wantType:  InputTypeURL,
			wantOwner: "owner",
			wantRepo:  "repo",
			wantErr:   false,
		},
		{
			name:    "non-github URL",
			input:   "https://gitlab.com/owner/repo",
			wantErr: true,
		},
		{
			name:    "invalid URL path",
			input:   "https://github.com/onlyowner",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseInput(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseInput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if got.Type != tt.wantType {
				t.Errorf("ParseInput() Type = %v, want %v", got.Type, tt.wantType)
			}
			if got.Owner != tt.wantOwner {
				t.Errorf("ParseInput() Owner = %v, want %v", got.Owner, tt.wantOwner)
			}
			if got.Repo != tt.wantRepo {
				t.Errorf("ParseInput() Repo = %v, want %v", got.Repo, tt.wantRepo)
			}
		})
	}
}

func TestParseInput_SearchQuery(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantType  InputType
		wantQuery string
	}{
		{
			name:      "org search",
			input:     "org:kubernetes",
			wantType:  InputTypeSearchQuery,
			wantQuery: "org:kubernetes",
		},
		{
			name:      "language search",
			input:     "language:go stars:>1000",
			wantType:  InputTypeSearchQuery,
			wantQuery: "language:go stars:>1000",
		},
		{
			name:      "user search",
			input:     "user:octocat",
			wantType:  InputTypeSearchQuery,
			wantQuery: "user:octocat",
		},
		{
			name:      "topic search",
			input:     "topic:github-actions",
			wantType:  InputTypeSearchQuery,
			wantQuery: "topic:github-actions",
		},
		{
			name:      "complex query with spaces",
			input:     "org:microsoft language:typescript",
			wantType:  InputTypeSearchQuery,
			wantQuery: "org:microsoft language:typescript",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseInput(tt.input)
			if err != nil {
				t.Errorf("ParseInput() unexpected error = %v", err)
				return
			}
			if got.Type != tt.wantType {
				t.Errorf("ParseInput() Type = %v, want %v", got.Type, tt.wantType)
			}
			if got.Query != tt.wantQuery {
				t.Errorf("ParseInput() Query = %v, want %v", got.Query, tt.wantQuery)
			}
		})
	}
}

func TestIsOwnerRepoFormat(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"owner/repo", true},
		{"my-org/my-repo", true},
		{"user123/repo456", true},
		{"org:kubernetes", false},
		{"language:go", false},
		{"owner/repo/extra", false},
		{"noslash", false},
		{"has space/repo", false},
		{"owner/repo with space", false},
		{"stars:>100", false},
		{"user:octocat", false},
		{"in:readme", false},
		{"topic:ci", false},
		{"repo:owner/repo", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isOwnerRepoFormat(tt.input); got != tt.want {
				t.Errorf("isOwnerRepoFormat(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
