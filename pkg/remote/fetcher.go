package remote

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/google/go-github/v68/github"
)

// RepositoryInfo represents repository information
type RepositoryInfo struct {
	Owner    string
	Name     string
	FullName string // "owner/repo"
}

// WorkflowFile represents workflow file information
type WorkflowFile struct {
	Path     string // .github/workflows/ci.yml
	Content  []byte
	RepoInfo *RepositoryInfo
}

// Fetcher retrieves repositories and workflows from GitHub API
type Fetcher struct {
	client *github.Client
	limit  int
}

// NewFetcher creates a new Fetcher
func NewFetcher(limit int) (*Fetcher, error) {
	var httpClient *http.Client

	token := getToken()
	if token != "" {
		httpClient = &http.Client{
			Transport: &tokenTransport{token: token},
		}
	}

	client := github.NewClient(httpClient)

	return &Fetcher{
		client: client,
		limit:  limit,
	}, nil
}

// getToken retrieves authentication token using a fallback chain
// Priority: environment variable → gh CLI → git credential
func getToken() string {
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		return token
	}
	if token := os.Getenv("GH_TOKEN"); token != "" {
		return token
	}
	if token, err := getTokenFromGhCLI(); err == nil && token != "" {
		return token
	}
	if token, err := getTokenFromGitCredential(); err == nil && token != "" {
		return token
	}
	return ""
}

func getTokenFromGhCLI() (string, error) {
	cmd := exec.CommandContext(context.Background(), "gh", "auth", "token")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func getTokenFromGitCredential() (string, error) {
	cmd := exec.CommandContext(context.Background(), "git", "credential", "fill")
	cmd.Stdin = strings.NewReader("protocol=https\nhost=github.com\n")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "password=") {
			return strings.TrimPrefix(line, "password="), nil
		}
	}
	return "", fmt.Errorf("credential not found")
}

// tokenTransport is a Transport that adds token to GitHub API requests
type tokenTransport struct {
	token string
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clonedReq := req.Clone(req.Context())
	clonedReq.Header.Set("Authorization", "Bearer "+t.token)
	return http.DefaultTransport.RoundTrip(clonedReq)
}

// FetchRepositories retrieves repositories based on input
func (f *Fetcher) FetchRepositories(ctx context.Context, input *ParsedInput) ([]*RepositoryInfo, error) {
	switch input.Type {
	case InputTypeURL, InputTypeOwnerRepo:
		return f.fetchSingleRepo(ctx, input.Owner, input.Repo)
	case InputTypeSearchQuery:
		return f.searchRepositories(ctx, input.Query)
	default:
		return nil, fmt.Errorf("unknown input type: %d", input.Type)
	}
}

func (f *Fetcher) fetchSingleRepo(ctx context.Context, owner, repo string) ([]*RepositoryInfo, error) {
	r, _, err := f.client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch repository: %w", err)
	}

	return []*RepositoryInfo{
		{
			Owner:    r.GetOwner().GetLogin(),
			Name:     r.GetName(),
			FullName: r.GetFullName(),
		},
	}, nil
}

func (f *Fetcher) searchRepositories(ctx context.Context, query string) ([]*RepositoryInfo, error) {
	opts := &github.SearchOptions{
		ListOptions: github.ListOptions{
			PerPage: f.limit,
		},
	}

	result, _, err := f.client.Search.Repositories(ctx, query, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to search repositories: %w", err)
	}

	repos := make([]*RepositoryInfo, 0, len(result.Repositories))
	for _, r := range result.Repositories {
		repos = append(repos, &RepositoryInfo{
			Owner:    r.GetOwner().GetLogin(),
			Name:     r.GetName(),
			FullName: r.GetFullName(),
		})

		if len(repos) >= f.limit {
			break
		}
	}

	return repos, nil
}

// FetchWorkflows retrieves workflow files from repository
func (f *Fetcher) FetchWorkflows(ctx context.Context, repo *RepositoryInfo) ([]*WorkflowFile, error) {
	_, contents, _, err := f.client.Repositories.GetContents(
		ctx,
		repo.Owner,
		repo.Name,
		".github/workflows",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch workflow directory: %w", err)
	}

	workflows := make([]*WorkflowFile, 0)
	for _, content := range contents {
		if content.GetType() != "file" {
			continue
		}
		name := content.GetName()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}

		fileContent, _, _, err := f.client.Repositories.GetContents(
			ctx,
			repo.Owner,
			repo.Name,
			content.GetPath(),
			nil,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch workflow file %s: %w", content.GetPath(), err)
		}

		decodedContent, err := fileContent.GetContent()
		if err != nil {
			return nil, fmt.Errorf("failed to get content for file %s: %w", content.GetPath(), err)
		}

		workflows = append(workflows, &WorkflowFile{
			Path:     content.GetPath(),
			Content:  []byte(decodedContent),
			RepoInfo: repo,
		})
	}

	return workflows, nil
}

// FetchSingleWorkflow retrieves a single workflow file
func (f *Fetcher) FetchSingleWorkflow(ctx context.Context, repo *RepositoryInfo, workflowPath string) (*WorkflowFile, error) {
	fileContent, _, _, err := f.client.Repositories.GetContents(
		ctx,
		repo.Owner,
		repo.Name,
		workflowPath,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch workflow file %s: %w", workflowPath, err)
	}

	decodedContent, err := fileContent.GetContent()
	if err != nil {
		return nil, fmt.Errorf("failed to get content for file %s: %w", workflowPath, err)
	}

	return &WorkflowFile{
		Path:     workflowPath,
		Content:  []byte(decodedContent),
		RepoInfo: repo,
	}, nil
}
