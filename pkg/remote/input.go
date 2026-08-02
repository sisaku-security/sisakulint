package remote

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// InputType represents the type of input
type InputType int

const (
	InputTypeURL InputType = iota
	InputTypeOwnerRepo
	InputTypeSearchQuery
)

// ParsedInput represents parsed input
type ParsedInput struct {
	Type       InputType
	Owner      string // for URL/OwnerRepo
	Repo       string // for URL/OwnerRepo
	Query      string // for search
	Ref        string // for /tree/<ref> URLs
	PullNumber int    // for /pull/<number> URLs
}

// ParseInput automatically detects and parses the input string
func ParseInput(input string) (*ParsedInput, error) {
	// 1. Check URL format: https://github.com/owner/repo
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		return parseURL(input)
	}

	// 2. Check owner/repo format
	if isOwnerRepoFormat(input) {
		return parseOwnerRepo(input)
	}

	// 3. Treat everything else as a search query
	return parseSearchQuery(input), nil
}

func parseURL(input string) (*ParsedInput, error) {
	u, err := url.Parse(input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	if u.Host != "github.com" {
		return nil, fmt.Errorf("URLs other than github.com are not supported: %s", u.Host)
	}

	// Expecting /owner/repo with an optional /tree/<ref> or /pull/<number>
	// suffix. In particular, do not silently discard a pull request number:
	// doing so scans the default branch while presenting a PR URL to the user.
	parts := strings.Split(strings.Trim(strings.TrimPrefix(u.Path, "/"), "/"), "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid GitHub URL format: %s", input)
	}
	owner := parts[0]
	repo := strings.TrimSuffix(parts[1], ".git")
	if owner == "" || repo == "" {
		return nil, fmt.Errorf("invalid GitHub URL format: %s", input)
	}

	parsed := &ParsedInput{
		Type:  InputTypeURL,
		Owner: owner,
		Repo:  repo,
	}
	if len(parts) == 2 {
		return parsed, nil
	}

	switch parts[2] {
	case "tree":
		if len(parts) < 4 {
			return nil, fmt.Errorf("GitHub tree URL is missing a ref: %s", input)
		}
		parsed.Ref = strings.Join(parts[3:], "/")
	case "pull":
		if len(parts) < 4 {
			return nil, fmt.Errorf("GitHub pull request URL is missing a number: %s", input)
		}
		number, err := strconv.Atoi(parts[3])
		if err != nil || number <= 0 {
			return nil, fmt.Errorf("invalid GitHub pull request number %q", parts[3])
		}
		if len(parts) > 4 && parts[4] != "files" && parts[4] != "commits" && parts[4] != "checks" {
			return nil, fmt.Errorf("unsupported GitHub pull request URL path: %s", input)
		}
		parsed.PullNumber = number
	default:
		return nil, fmt.Errorf("unsupported GitHub URL path: %s", input)
	}

	return parsed, nil
}

func parseOwnerRepo(input string) (*ParsedInput, error) {
	parts := strings.Split(input, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid owner/repo format: %s", input)
	}

	return &ParsedInput{
		Type:  InputTypeOwnerRepo,
		Owner: parts[0],
		Repo:  parts[1],
	}, nil
}

func parseSearchQuery(input string) *ParsedInput {
	return &ParsedInput{
		Type:  InputTypeSearchQuery,
		Query: input,
	}
}

func isOwnerRepoFormat(input string) bool {
	// owner/repo format: single slash, no spaces, no GitHub search syntax keywords
	if strings.Count(input, "/") != 1 {
		return false
	}
	if strings.ContainsAny(input, " \t\n") {
		return false
	}

	// No GitHub search syntax keywords
	searchKeywords := []string{"language:", "stars:", "in:", "user:", "org:", "topic:", "repo:"}
	for _, kw := range searchKeywords {
		if strings.Contains(input, kw) {
			return false
		}
	}

	return true
}
