package remote

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/go-github/v68/github"
)

const (
	defaultMaxArchiveBytes   int64 = 100 << 20 // 100 MiB compressed
	defaultMaxExtractedBytes int64 = 400 << 20 // 400 MiB uncompressed (fits default Lambda /tmp)
	defaultMaxFileBytes      int64 = 50 << 20  // 50 MiB per file
	defaultMaxArchiveFiles         = 100_000
	maxArchiveRedirects            = 3
	maxPullRequestFiles            = 3_000
)

// PullRequestSnapshotOptions controls immutable PR snapshot materialization.
type PullRequestSnapshotOptions struct {
	// ExpectedHeadSHA, when non-empty, must exactly match the current PR head.
	// Services should always set this to the SHA from the verified webhook so a
	// delayed request cannot accidentally scan a newer revision.
	ExpectedHeadSHA string
	// Destination must not already exist. When empty, a temporary directory is
	// created and removed by Snapshot.Close.
	Destination string
}

// RepositorySnapshot is a local, immutable view of a pull request head.
type RepositorySnapshot struct {
	Root                string
	HeadSHA             string
	WorkflowPaths       []string
	TargetWorkflowPaths []string
	removeOnClose       bool
}

// Close removes snapshots backed by an internally-created temporary
// directory. Explicit destinations remain available to the caller.
func (s *RepositorySnapshot) Close() error {
	if s == nil || !s.removeOnClose || s.Root == "" {
		return nil
	}
	return os.RemoveAll(s.Root)
}

func newArchiveHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxArchiveRedirects {
				return errors.New("too many archive redirects")
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("repository archive redirect must use HTTPS, got %q", req.URL.Scheme)
			}
			// GitHub archive links are pre-signed. Never copy Authorization or
			// other caller headers across hosts.
			req.Header.Del("Authorization")
			return nil
		},
	}
}

// MaterializePullRequest resolves a PR, verifies its expected head SHA,
// downloads the repository archive at that immutable SHA, and safely extracts
// it. The full repository is materialized so project-wide lint rules can read
// configuration, lockfiles, local actions, and reusable workflows.
func (f *Fetcher) MaterializePullRequest(
	ctx context.Context,
	owner string,
	repo string,
	pullNumber int,
	opts *PullRequestSnapshotOptions,
) (*RepositorySnapshot, error) {
	if pullNumber <= 0 {
		return nil, fmt.Errorf("pull request number must be greater than zero")
	}
	if opts == nil {
		opts = &PullRequestSnapshotOptions{}
	}

	pr, _, err := f.client.PullRequests.Get(ctx, owner, repo, pullNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pull request #%d: %w", pullNumber, err)
	}
	headSHA := strings.ToLower(pr.GetHead().GetSHA())
	if headSHA == "" {
		return nil, fmt.Errorf("pull request #%d has no head SHA", pullNumber)
	}
	baseSHA := strings.ToLower(pr.GetBase().GetSHA())
	if baseSHA == "" {
		return nil, fmt.Errorf("pull request #%d has no base SHA", pullNumber)
	}
	if opts.ExpectedHeadSHA != "" && !strings.EqualFold(opts.ExpectedHeadSHA, headSHA) {
		return nil, fmt.Errorf(
			"pull request head changed: expected %s, got %s",
			opts.ExpectedHeadSHA,
			headSHA,
		)
	}
	if pr.GetChangedFiles() > maxPullRequestFiles {
		return nil, fmt.Errorf(
			"pull request changes %d files, exceeding GitHub's %d-file listing limit; refusing an incomplete scan",
			pr.GetChangedFiles(),
			maxPullRequestFiles,
		)
	}

	targets, err := f.fetchPullRequestWorkflowPaths(ctx, owner, repo, pullNumber)
	if err != nil {
		return nil, err
	}

	// ListFiles is a mutable PR endpoint. Re-read both sides of the comparison
	// after pagination so a synchronize event or base-branch update cannot pair
	// one revision's target list with another revision's archive. The archive
	// itself is fetched by the immutable head SHA captured above.
	currentPR, _, err := f.client.PullRequests.Get(ctx, owner, repo, pullNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to revalidate pull request #%d: %w", pullNumber, err)
	}
	currentHeadSHA := strings.ToLower(currentPR.GetHead().GetSHA())
	currentBaseSHA := strings.ToLower(currentPR.GetBase().GetSHA())
	if currentHeadSHA != headSHA || currentBaseSHA != baseSHA {
		return nil, fmt.Errorf(
			"pull request revision changed while listing files: expected head %s and base %s, got head %s and base %s",
			headSHA,
			baseSHA,
			currentHeadSHA,
			currentBaseSHA,
		)
	}
	if currentPR.GetChangedFiles() > maxPullRequestFiles {
		return nil, fmt.Errorf(
			"pull request changes %d files, exceeding GitHub's %d-file listing limit; refusing an incomplete scan",
			currentPR.GetChangedFiles(),
			maxPullRequestFiles,
		)
	}

	root, removeOnClose, err := createSnapshotDestination(opts.Destination)
	if err != nil {
		return nil, err
	}
	cleanupOnError := func() {
		if removeOnClose || opts.Destination != "" {
			_ = os.RemoveAll(root)
		}
	}

	archiveURL, _, err := f.client.Repositories.GetArchiveLink(
		ctx,
		owner,
		repo,
		github.Tarball,
		&github.RepositoryContentGetOptions{Ref: headSHA},
		0,
	)
	if err != nil {
		cleanupOnError()
		return nil, fmt.Errorf("failed to resolve repository archive: %w", err)
	}
	if archiveURL == nil {
		cleanupOnError()
		return nil, errors.New("GitHub returned an empty repository archive URL")
	}
	if err := f.downloadAndExtractArchive(ctx, archiveURL, root); err != nil {
		cleanupOnError()
		return nil, err
	}

	// Project discovery intentionally requires a .git marker. An archive has no
	// Git metadata, so create an empty marker directory after extraction.
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		cleanupOnError()
		return nil, fmt.Errorf("failed to create snapshot project marker: %w", err)
	}

	workflows, err := collectWorkflowPaths(root)
	if err != nil {
		cleanupOnError()
		return nil, err
	}
	if err := ensureTargetsExist(targets, workflows); err != nil {
		cleanupOnError()
		return nil, err
	}

	return &RepositorySnapshot{
		Root:                root,
		HeadSHA:             headSHA,
		WorkflowPaths:       workflows,
		TargetWorkflowPaths: targets,
		removeOnClose:       removeOnClose,
	}, nil
}

func createSnapshotDestination(destination string) (root string, removeOnClose bool, err error) {
	if destination == "" {
		root, err = os.MkdirTemp("", "sisakulint-remote-")
		if err != nil {
			return "", false, fmt.Errorf("failed to create snapshot directory: %w", err)
		}
		return root, true, nil
	}

	root, err = filepath.Abs(destination)
	if err != nil {
		return "", false, fmt.Errorf("failed to resolve snapshot destination: %w", err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", false, fmt.Errorf("snapshot destination already exists: %s", root)
		}
		return "", false, fmt.Errorf("failed to create snapshot destination: %w", err)
	}
	return root, false, nil
}

func (f *Fetcher) fetchPullRequestWorkflowPaths(
	ctx context.Context,
	owner string,
	repo string,
	pullNumber int,
) ([]string, error) {
	options := &github.ListOptions{PerPage: 100}
	seen := make(map[string]struct{})
	var targets []string
	for {
		files, response, err := f.client.PullRequests.ListFiles(ctx, owner, repo, pullNumber, options)
		if err != nil {
			return nil, fmt.Errorf("failed to list pull request files: %w", err)
		}
		for _, file := range files {
			filename := path.Clean(file.GetFilename())
			if file.GetStatus() == "removed" || !isWorkflowPath(filename) {
				continue
			}
			if _, ok := seen[filename]; ok {
				continue
			}
			seen[filename] = struct{}{}
			targets = append(targets, filename)
		}
		if response == nil || response.NextPage == 0 {
			break
		}
		options.Page = response.NextPage
	}
	sort.Strings(targets)
	return targets, nil
}

func isWorkflowPath(name string) bool {
	if name == "." || path.IsAbs(name) || strings.HasPrefix(name, "../") {
		return false
	}
	if !strings.HasPrefix(name, ".github/workflows/") {
		return false
	}
	return strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")
}

func (f *Fetcher) downloadAndExtractArchive(ctx context.Context, archiveURL *url.URL, root string) error {
	if archiveURL.Scheme != "https" && !(f.allowInsecureArchive && archiveURL.Scheme == "http") {
		return fmt.Errorf("repository archive URL must use HTTPS, got %q", archiveURL.Scheme)
	}
	client := f.archiveClient
	if client == nil {
		client = newArchiveHTTPClient()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, archiveURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create repository archive request: %w", err)
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("User-Agent", "sisakulint")
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download repository archive: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("repository archive download returned %s", response.Status)
	}

	compressed := &countingReader{
		reader: io.LimitReader(response.Body, defaultMaxArchiveBytes+1),
	}
	gzipReader, err := gzip.NewReader(compressed)
	if err != nil {
		return fmt.Errorf("failed to open repository archive: %w", err)
	}
	defer gzipReader.Close()
	if err := extractTar(gzipReader, root); err != nil {
		return err
	}
	if compressed.count > defaultMaxArchiveBytes {
		return fmt.Errorf("repository archive exceeds compressed size limit of %d bytes", defaultMaxArchiveBytes)
	}
	return nil
}

type countingReader struct {
	reader io.Reader
	count  int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.count += int64(n)
	return n, err
}

func extractTar(reader io.Reader, root string) error {
	tarReader := tar.NewReader(reader)
	var prefix string
	var extractedBytes int64
	fileCount := 0
	seen := make(map[string]struct{})

	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read repository archive: %w", err)
		}
		fileCount++
		if fileCount > defaultMaxArchiveFiles {
			return fmt.Errorf("repository archive exceeds file limit of %d", defaultMaxArchiveFiles)
		}
		// GitHub tarballs may begin with a POSIX PAX global header. archive/tar
		// already applies its metadata to following entries; it is not a
		// repository path and must not participate in top-level prefix checks.
		if header.Typeflag == tar.TypeXGlobalHeader || header.Typeflag == tar.TypeXHeader {
			continue
		}

		rawName := strings.TrimPrefix(header.Name, "./")
		for _, component := range strings.Split(rawName, "/") {
			if component == ".." {
				return fmt.Errorf("unsafe repository archive path %q", header.Name)
			}
		}
		cleanName := path.Clean(rawName)
		if cleanName == "." || path.IsAbs(cleanName) || strings.HasPrefix(cleanName, "../") {
			return fmt.Errorf("unsafe repository archive path %q", header.Name)
		}
		parts := strings.Split(cleanName, "/")
		if prefix == "" {
			prefix = parts[0]
		}
		if parts[0] != prefix {
			return fmt.Errorf("repository archive has multiple top-level directories")
		}
		if len(parts) == 1 {
			if header.Typeflag != tar.TypeDir {
				return fmt.Errorf("invalid repository archive root entry %q", header.Name)
			}
			continue
		}

		rel := path.Clean(strings.Join(parts[1:], "/"))
		if rel == "." || path.IsAbs(rel) || strings.HasPrefix(rel, "../") {
			return fmt.Errorf("unsafe repository archive path %q", header.Name)
		}
		if _, ok := seen[rel]; ok {
			return fmt.Errorf("duplicate repository archive path %q", rel)
		}
		seen[rel] = struct{}{}

		destination := filepath.Join(root, filepath.FromSlash(rel))
		if !pathInsideRoot(root, destination) {
			return fmt.Errorf("repository archive path %q escapes destination", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destination, 0o755); err != nil {
				return fmt.Errorf("failed to create archive directory %q: %w", rel, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > defaultMaxFileBytes {
				return fmt.Errorf("repository archive file %q exceeds size limit", rel)
			}
			extractedBytes += header.Size
			if extractedBytes > defaultMaxExtractedBytes {
				return fmt.Errorf("repository archive exceeds extracted size limit of %d bytes", defaultMaxExtractedBytes)
			}
			if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
				return fmt.Errorf("failed to create archive parent for %q: %w", rel, err)
			}
			file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
			if err != nil {
				return fmt.Errorf("failed to create archive file %q: %w", rel, err)
			}
			written, copyErr := io.CopyN(file, tarReader, header.Size)
			closeErr := file.Close()
			if copyErr != nil {
				return fmt.Errorf("failed to extract archive file %q: %w", rel, copyErr)
			}
			if written != header.Size {
				return fmt.Errorf("repository archive file %q was truncated", rel)
			}
			if closeErr != nil {
				return fmt.Errorf("failed to close archive file %q: %w", rel, closeErr)
			}
		default:
			// Symlinks, hardlinks, devices, and FIFOs can make a repository
			// snapshot escape its destination or change subsequent reads.
			return fmt.Errorf("unsupported repository archive entry type for %q", rel)
		}
	}
	if prefix == "" {
		return errors.New("repository archive is empty")
	}
	return nil
}

func pathInsideRoot(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	return err == nil && rel != ".." && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func collectWorkflowPaths(root string) ([]string, error) {
	workflowRoot := filepath.Join(root, ".github", "workflows")
	if _, err := os.Stat(workflowRoot); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to inspect workflow directory: %w", err)
	}
	var workflows []string
	err := filepath.WalkDir(workflowRoot, func(filename string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if isWorkflowPath(rel) {
			workflows = append(workflows, rel)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to collect workflow files: %w", err)
	}
	sort.Strings(workflows)
	return workflows, nil
}

func ensureTargetsExist(targets, workflows []string) error {
	available := make(map[string]struct{}, len(workflows))
	for _, workflow := range workflows {
		available[workflow] = struct{}{}
	}
	for _, target := range targets {
		if _, ok := available[target]; !ok {
			return fmt.Errorf("changed workflow %q is missing from pull request head snapshot", target)
		}
	}
	return nil
}
