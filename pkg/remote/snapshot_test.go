package remote

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-github/v68/github"
)

const snapshotTestSHA = "0123456789abcdef0123456789abcdef01234567"
const snapshotTestBaseSHA = "89abcdef0123456789abcdef0123456789abcdef"

func TestMaterializePullRequestUsesVerifiedImmutableHead(t *testing.T) {
	archive := makeTarGzip(t, map[string]string{
		"repository-root/.github/workflows/changed.yml":  "name: Changed\non: push\njobs: {}\n",
		"repository-root/.github/workflows/context.yaml": "name: Context\non: workflow_call\njobs: {}\n",
		"repository-root/.github/dependabot.yaml":        "version: 2\nupdates: []\n",
		"repository-root/package-lock.json":              "{}\n",
	})

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/pulls/7":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"number":7,"head":{"sha":%q},"base":{"sha":%q}}`, snapshotTestSHA, snapshotTestBaseSHA)
		case "/repos/owner/repo/pulls/7/files":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[
                    {"filename":".github/workflows/changed.yml","status":"modified"},
                    {"filename":".github/workflows/deleted.yml","status":"removed"},
                    {"filename":"README.md","status":"modified"}
                ]`)
		case "/repos/owner/repo/tarball/" + snapshotTestSHA:
			http.Redirect(w, r, server.URL+"/signed/archive.tar.gz", http.StatusFound)
		case "/signed/archive.tar.gz":
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(archive)
		default:
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	fetcher := newSnapshotTestFetcher(t, server)
	destination := filepath.Join(t.TempDir(), "checkout")
	snapshot, err := fetcher.MaterializePullRequest(
		context.Background(),
		"owner",
		"repo",
		7,
		&PullRequestSnapshotOptions{
			ExpectedHeadSHA: strings.ToUpper(snapshotTestSHA),
			Destination:     destination,
		},
	)
	if err != nil {
		t.Fatalf("MaterializePullRequest returned error: %v", err)
	}
	defer snapshot.Close()

	if snapshot.HeadSHA != snapshotTestSHA {
		t.Fatalf("HeadSHA = %q, want %q", snapshot.HeadSHA, snapshotTestSHA)
	}
	if !slices.Equal(snapshot.TargetWorkflowPaths, []string{".github/workflows/changed.yml"}) {
		t.Fatalf("TargetWorkflowPaths = %#v", snapshot.TargetWorkflowPaths)
	}
	wantWorkflows := []string{
		".github/workflows/changed.yml",
		".github/workflows/context.yaml",
	}
	if !slices.Equal(snapshot.WorkflowPaths, wantWorkflows) {
		t.Fatalf("WorkflowPaths = %#v, want %#v", snapshot.WorkflowPaths, wantWorkflows)
	}
	for _, name := range []string{
		".git",
		".github/dependabot.yaml",
		".github/workflows/changed.yml",
		"package-lock.json",
	} {
		if _, err := os.Stat(filepath.Join(destination, filepath.FromSlash(name))); err != nil {
			t.Errorf("snapshot is missing %s: %v", name, err)
		}
	}
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(destination); err != nil {
		t.Fatalf("explicit snapshot destination was removed: %v", err)
	}
}

func TestMaterializePullRequestRejectsChangedHeadBeforeDownloading(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path != "/repos/owner/repo/pulls/9" {
			t.Fatalf("unexpected request after head mismatch: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"number":9,"head":{"sha":%q},"base":{"sha":%q}}`, snapshotTestSHA, snapshotTestBaseSHA)
	}))
	defer server.Close()

	fetcher := newSnapshotTestFetcher(t, server)
	_, err := fetcher.MaterializePullRequest(
		context.Background(),
		"owner",
		"repo",
		9,
		&PullRequestSnapshotOptions{ExpectedHeadSHA: strings.Repeat("f", 40)},
	)
	if err == nil || !strings.Contains(err.Error(), "pull request head changed") {
		t.Fatalf("error = %v, want head changed error", err)
	}
	if requestCount != 1 {
		t.Fatalf("request count = %d, want 1", requestCount)
	}
}

func TestMaterializePullRequestRejectsGitHubFileListTruncation(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path != "/repos/owner/repo/pulls/10" {
			t.Fatalf("unexpected request after file-limit rejection: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"number":10,"changed_files":3001,"head":{"sha":%q},"base":{"sha":%q}}`, snapshotTestSHA, snapshotTestBaseSHA)
	}))
	defer server.Close()

	fetcher := newSnapshotTestFetcher(t, server)
	_, err := fetcher.MaterializePullRequest(
		context.Background(),
		"owner",
		"repo",
		10,
		&PullRequestSnapshotOptions{ExpectedHeadSHA: snapshotTestSHA},
	)
	if err == nil || !strings.Contains(err.Error(), "file listing limit") {
		t.Fatalf("error = %v, want file-list limit error", err)
	}
	if requestCount != 1 {
		t.Fatalf("request count = %d, want 1", requestCount)
	}
}

func TestMaterializePullRequestRejectsRevisionChangeDuringFileListing(t *testing.T) {
	const changedHeadSHA = "fedcba9876543210fedcba9876543210fedcba98"
	pullRequestReads := 0
	archiveRequested := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/pulls/11":
			pullRequestReads++
			headSHA := snapshotTestSHA
			if pullRequestReads > 1 {
				headSHA = changedHeadSHA
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"number":11,"head":{"sha":%q},"base":{"sha":%q}}`, headSHA, snapshotTestBaseSHA)
		case "/repos/owner/repo/pulls/11/files":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[{"filename":".github/workflows/ci.yml","status":"modified"}]`)
		default:
			archiveRequested = true
			t.Fatalf("unexpected request after revision change: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	fetcher := newSnapshotTestFetcher(t, server)
	_, err := fetcher.MaterializePullRequest(
		context.Background(),
		"owner",
		"repo",
		11,
		&PullRequestSnapshotOptions{ExpectedHeadSHA: snapshotTestSHA},
	)
	if err == nil || !strings.Contains(err.Error(), "pull request revision changed") {
		t.Fatalf("error = %v, want revision changed error", err)
	}
	if pullRequestReads != 2 {
		t.Fatalf("pull request read count = %d, want 2", pullRequestReads)
	}
	if archiveRequested {
		t.Fatal("archive was requested after the pull request revision changed")
	}
}

func TestFetchPullRequestWorkflowPathsPaginates(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/repo/pulls/3/files" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("page") {
		case "", "1":
			w.Header().Set("Link", fmt.Sprintf(`<%s/repos/owner/repo/pulls/3/files?page=2>; rel="next", <%s/repos/owner/repo/pulls/3/files?page=2>; rel="last"`, server.URL, server.URL))
			fmt.Fprint(w, `[{"filename":".github/workflows/a.yml","status":"modified"}]`)
		case "2":
			fmt.Fprint(w, `[{"filename":".github/workflows/b.yaml","status":"added"}]`)
		default:
			t.Fatalf("unexpected page %q", r.URL.Query().Get("page"))
		}
	}))
	defer server.Close()

	fetcher := newSnapshotTestFetcher(t, server)
	paths, err := fetcher.fetchPullRequestWorkflowPaths(context.Background(), "owner", "repo", 3)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".github/workflows/a.yml", ".github/workflows/b.yaml"}
	if !slices.Equal(paths, want) {
		t.Fatalf("paths = %#v, want %#v", paths, want)
	}
}

func TestExtractTarRejectsUnsafeEntries(t *testing.T) {
	tests := []struct {
		name     string
		header   tar.Header
		contents string
	}{
		{
			name: "parent traversal",
			header: tar.Header{
				Name:     "root/../outside.yml",
				Mode:     0o644,
				Size:     1,
				Typeflag: tar.TypeReg,
			},
			contents: "x",
		},
		{
			name: "symlink",
			header: tar.Header{
				Name:     "root/link",
				Linkname: "../../outside",
				Mode:     0o777,
				Typeflag: tar.TypeSymlink,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var archive bytes.Buffer
			writer := tar.NewWriter(&archive)
			if err := writer.WriteHeader(&tt.header); err != nil {
				t.Fatal(err)
			}
			if tt.contents != "" {
				if _, err := writer.Write([]byte(tt.contents)); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}

			err := extractTar(bytes.NewReader(archive.Bytes()), t.TempDir())
			if err == nil {
				t.Fatal("extractTar unexpectedly accepted unsafe entry")
			}
		})
	}
}

func TestExtractTarIgnoresPAXGlobalHeader(t *testing.T) {
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writer.WriteHeader(&tar.Header{
		Name:       "pax_global_header",
		Typeflag:   tar.TypeXGlobalHeader,
		PAXRecords: map[string]string{"comment": "github archive metadata"},
	}); err != nil {
		t.Fatal(err)
	}
	contents := "name: CI\non: push\njobs: {}\n"
	if err := writer.WriteHeader(&tar.Header{
		Name:     "root/.github/workflows/ci.yml",
		Mode:     0o644,
		Size:     int64(len(contents)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(contents)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	if err := extractTar(bytes.NewReader(archive.Bytes()), root); err != nil {
		t.Fatalf("extractTar rejected PAX global header: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".github", "workflows", "ci.yml")); err != nil {
		t.Fatalf("workflow was not extracted: %v", err)
	}
}

func newSnapshotTestFetcher(t *testing.T, server *httptest.Server) *Fetcher {
	t.Helper()
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	client := github.NewClient(server.Client())
	client.BaseURL = baseURL
	client.UploadURL = baseURL
	return &Fetcher{
		client:               client,
		archiveClient:        server.Client(),
		allowInsecureArchive: true,
		limit:                1,
	}
}

func makeTarGzip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{
		Name:     "repository-root/",
		Mode:     0o755,
		Typeflag: tar.TypeDir,
	}); err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(files))
	for filename := range files {
		paths = append(paths, filename)
	}
	slices.Sort(paths)
	for _, filename := range paths {
		contents := files[filename]
		if err := tarWriter.WriteHeader(&tar.Header{
			Name:     filename,
			Mode:     0o644,
			Size:     int64(len(contents)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
