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
	Ref      string // optional immutable or named ref for workflow retrieval
}

// WorkflowFile represents workflow file information
type WorkflowFile struct {
	Path     string // .github/workflows/ci.yml
	Content  []byte
	RepoInfo *RepositoryInfo
}

// Fetcher retrieves repositories and workflows from GitHub API
type Fetcher struct {
	client        *github.Client
	archiveClient *http.Client
	// allowInsecureArchive is test-only; production archive URLs must use TLS.
	allowInsecureArchive bool
	limit                int
}

// NewFetcher creates a new Fetcher
func NewFetcher(limit int) (*Fetcher, error) {
	return NewFetcherWithToken(limit, getToken())
}

// NewFetcherWithToken creates a Fetcher with an explicitly resolved token.
// CLI callers should use this constructor so -github-token and the standard
// environment fallback chain are shared by remote scans and lint rules.
func NewFetcherWithToken(limit int, token string) (*Fetcher, error) {
	apiClient := &http.Client{}
	if token != "" {
		apiClient.Transport = &tokenTransport{
			token: token,
			base:  http.DefaultTransport,
		}
	}

	client := github.NewClient(apiClient)

	return &Fetcher{
		client:        client,
		archiveClient: newArchiveHTTPClient(),
		limit:         limit,
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
	base  http.RoundTripper
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	clonedReq := req.Clone(req.Context())
	// Never forward a GitHub token to the signed archive host (or any other
	// redirect target). The archive downloader intentionally uses a separate
	// unauthenticated client as a second line of defence.
	if !isGitHubAPIHost(req.URL.Hostname()) {
		clonedReq.Header.Del("Authorization")
		return base.RoundTrip(clonedReq)
	}
	clonedReq.Header.Set("Authorization", "Bearer "+t.token)
	return base.RoundTrip(clonedReq)
}

func isGitHubAPIHost(host string) bool {
	return host == "api.github.com" || host == "uploads.github.com"
}

// FetchRepositories retrieves repositories based on input
func (f *Fetcher) FetchRepositories(ctx context.Context, input *ParsedInput) ([]*RepositoryInfo, error) {
	switch input.Type {
	case InputTypeURL, InputTypeOwnerRepo:
		repositories, err := f.fetchSingleRepo(ctx, input.Owner, input.Repo)
		if err == nil && input.Ref != "" {
			for _, repository := range repositories {
				repository.Ref = input.Ref
			}
		}
		return repositories, err
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
	return f.FetchWorkflowsAtRef(ctx, repo, "")
}

// FetchWorkflowsAtRef retrieves workflow files from a repository at ref.
// An empty ref preserves the GitHub API default-branch behaviour.
func (f *Fetcher) FetchWorkflowsAtRef(ctx context.Context, repo *RepositoryInfo, ref string) ([]*WorkflowFile, error) {
	var getOptions *github.RepositoryContentGetOptions
	if ref != "" {
		getOptions = &github.RepositoryContentGetOptions{Ref: ref}
	}
	_, contents, _, err := f.client.Repositories.GetContents(
		ctx,
		repo.Owner,
		repo.Name,
		".github/workflows",
		getOptions,
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
			getOptions,
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
func (f *Fetcher) FetchSingleWorkflow(ctx context.Context, repo *RepositoryInfo, workflowPath, ref string) (*WorkflowFile, error) {
	decodedContent, err := f.FetchFile(ctx, repo, workflowPath, ref)
	if err != nil {
		return nil, err
	}

	return &WorkflowFile{
		Path:     workflowPath,
		Content:  decodedContent,
		RepoInfo: repo,
	}, nil
}

// FetchFile retrieves a single file from a repository at the given ref.
func (f *Fetcher) FetchFile(ctx context.Context, repo *RepositoryInfo, filePath, ref string) ([]byte, error) {
	fileContent, _, _, err := f.client.Repositories.GetContents(
		ctx,
		repo.Owner,
		repo.Name,
		filePath,
		&github.RepositoryContentGetOptions{Ref: ref},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch file %s: %w", filePath, err)
	}

	decodedContent, err := fileContent.GetContent()
	if err != nil {
		return nil, fmt.Errorf("failed to get content for file %s: %w", filePath, err)
	}

	return []byte(decodedContent), nil
}
