package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v68/github"
	"github.com/sisaku-security/sisakulint/pkg/remote"
	"golang.org/x/sync/singleflight"
	"gopkg.in/yaml.v3"
)

// GitHub Actionsの入力メタデータ構造体 : inputs
// *https://docs.github.com/en/actions/creating-actions/metadata-syntax-for-github-actions#inputs
type ActionInputMetadata struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
}

// actionの入力メタデータのマップ
type ActionInputsMetadata map[string]*ActionInputMetadata

// YAMLからアクションの入力メタデータを読み込む関数
func (inputs *ActionInputsMetadata) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return expectedMapping("inputs", n)
	}

	type TempInputMetadata struct {
		Required bool    `yaml:"required"`
		Default  *string `yaml:"default"`
	}

	md := make(ActionInputsMetadata, len(n.Content)/2)
	for i := 0; i < len(n.Content); i += 2 {
		name := n.Content[i].Value
		value := n.Content[i+1]

		var m TempInputMetadata
		if err := value.Decode(&m); err != nil {
			return err
		}
		id := strings.ToLower(name)
		if _, ok := md[id]; ok {
			return fmt.Errorf("duplicate input %q", name)
		}
		md[id] = &ActionInputMetadata{name, m.Required || m.Default != nil}
	}
	*inputs = md
	return nil
}

// GitHub Actionsの出力メタデータ構造体
// *https://docs.github.com/en/actions/creating-actions/metadata-syntax-for-github-actions#outputs-for-composite-actions
type ActionOutputMetadata struct {
	Name string `json:"name"`
}

// アクションの出力メタデータのマップ
type ActionOutputsMetadata map[string]*ActionOutputMetadata

// YAMLからアクションの出力メタデータを読み込む関数
func (outputs *ActionOutputsMetadata) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return expectedMapping("outputs", n)
	}

	md := make(ActionOutputsMetadata, len(n.Content)/2)
	for i := 0; i < len(n.Content); i += 2 {
		name := n.Content[i].Value
		id := strings.ToLower(name)
		if _, ok := md[id]; ok {
			return fmt.Errorf("duplicate output %q", name)
		}
		md[id] = &ActionOutputMetadata{name}
	}
	*outputs = md
	return nil
}

// ActionRunsMetadata represents the "runs" section in GitHub Action metadata.
// For this linter, only composite-action steps are needed so rules can inspect
// transitive uses such as actions/cache.
type ActionRunsMetadata struct {
	Using string                `yaml:"using" json:"using"`
	Steps []*ActionStepMetadata `yaml:"steps" json:"steps"`
}

// ActionStepMetadata is the subset of composite action step metadata needed by
// rules that reason about transitive action calls.
type ActionStepMetadata struct {
	Uses string                 `yaml:"uses" json:"uses"`
	If   string                 `yaml:"if" json:"if"`
	With ActionStepWithMetadata `yaml:"with" json:"with"`
}

type ActionStepWithMetadata map[string]string

func (with *ActionStepWithMetadata) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return expectedMapping("with", n)
	}

	md := make(ActionStepWithMetadata, len(n.Content)/2)
	for i := 0; i < len(n.Content); i += 2 {
		name := n.Content[i].Value
		value := n.Content[i+1]
		if value.Kind == yaml.ScalarNode {
			md[strings.ToLower(name)] = value.Value
			continue
		}
		// Cache detection only needs key presence and simple scalar values; complex
		// structures are intentionally normalized without expression parsing.
		md[strings.ToLower(name)] = ""
	}
	*with = md
	return nil
}

// GitHub Actionsの全体的なメタデータ構造体
// *https://docs.github.com/en/actions/creating-actions/metadata-syntax-for-github-actions
type ActionMetadata struct {
	Name        string                `yaml:"name" json:"name"`
	Inputs      ActionInputsMetadata  `yaml:"inputs" json:"inputs"`
	Outputs     ActionOutputsMetadata `yaml:"outputs" json:"outputs"`
	Runs        *ActionRunsMetadata   `yaml:"runs" json:"runs"`
	SkipInputs  bool                  `json:"skip_inputs"`
	SkipOutputs bool                  `json:"skip_outputs"`
}

// String renders ActionMetadata as JSON so debug logs show dereferenced field
// values instead of raw pointer addresses. Without this, fmt's default %v
// stops dereferencing pointers nested inside maps/slices (Inputs, Outputs,
// Runs.Steps), printing them as 0xc000... addresses.
func (m *ActionMetadata) String() string {
	if m == nil {
		return "<nil>"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Sprintf("ActionMetadata(json marshal err: %v)", err)
	}
	return string(b)
}

type ActionMetadataResolver interface {
	FindMetadata(spec string) (*ActionMetadata, error)
}

type MultiActionMetadataResolver struct {
	resolvers []ActionMetadataResolver
}

func NewMultiActionMetadataResolver(resolvers ...ActionMetadataResolver) *MultiActionMetadataResolver {
	filtered := make([]ActionMetadataResolver, 0, len(resolvers))
	for _, resolver := range resolvers {
		if resolver != nil {
			filtered = append(filtered, resolver)
		}
	}
	return &MultiActionMetadataResolver{resolvers: filtered}
}

func (r *MultiActionMetadataResolver) FindMetadata(spec string) (*ActionMetadata, error) {
	var lastErr error
	for _, resolver := range r.resolvers {
		meta, err := resolver.FindMetadata(spec)
		if err != nil {
			lastErr = err
			continue
		}
		if meta != nil {
			return meta, nil
		}
	}
	return nil, lastErr
}

// ローカルアクションのメタデータキャッシュ構造体
type LocalActionsMetadataCache struct {
	mu    sync.RWMutex
	proj  *Project
	cache map[string]*ActionMetadata
	dbg   io.Writer
}

// ローカルアクションのメタデータキャッシュを新規作成する関数
func NewLocalActionsMetadataCache(proj *Project, dbg io.Writer) *LocalActionsMetadataCache {
	return &LocalActionsMetadataCache{proj: proj, cache: make(map[string]*ActionMetadata), dbg: dbg}
}

// デバッグ用のローカルアクションメタデータキャッシュを作成する関数
func nullLocalActionsMetadataCache(dbg io.Writer) *LocalActionsMetadataCache {
	return &LocalActionsMetadataCache{dbg: dbg}
}

// デバッグメッセージを出力する関数
func (c *LocalActionsMetadataCache) debug(format string, args ...interface{}) {
	if c.dbg == nil {
		return
	}
	format = "[LocalActionsMetadataCache] " + format + "\n"
	fmt.Fprintf(c.dbg, format, args...)
}

// キャッシュからメタデータを読み込む関数
func (c *LocalActionsMetadataCache) readCache(key string) (*ActionMetadata, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	m, ok := c.cache[key]
	return m, ok
}

// キャッシュにメタデータを書き込む関数
func (c *LocalActionsMetadataCache) writeCache(key string, val *ActionMetadata) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = val
}

// FindMetadataは指定されたspecのメタデータを検索します。specはローカルアクションを示すべきであるため、
// "./"で始まる必要があります。エラーが発生していなくても、最初の戻り値はnilになることがあります。
// LocalActionCacheは、アクションが見つからなかったことをキャッシュします。最初の検索時には、
// アクションが見つからなかったというエラーを返します。しかし、2回目の検索では、結果がnilであってもエラーは返されません。
// この振る舞いは、同じエラーを複数の場所から繰り返し報告するのを防ぐためです。
func (c *LocalActionsMetadataCache) FindMetadata(spec string) (*ActionMetadata, error) {
	if c.proj == nil || !strings.HasPrefix(spec, "./") {
		return nil, nil
	}

	if m, ok := c.readCache(spec); ok {
		c.debug("cache hit @ %s: %v", spec, m)
		return m, nil
	}

	dir := filepath.Join(c.proj.RootDirectory(), filepath.FromSlash(spec))
	dir = filepath.Clean(dir)

	if err := validatePathInsideRoot(c.proj.RootDirectory(), dir); err != nil {
		c.writeCache(spec, nil)
		return nil, fmt.Errorf("path traversal detected in action spec %q: %w", spec, err)
	}

	b, ok := c.readLocalActionMetadataFile(dir)
	if !ok {
		c.writeCache(spec, nil)
		return nil, nil
	}

	var meta ActionMetadata
	if err := yaml.Unmarshal(b, &meta); err != nil {
		c.writeCache(spec, nil)
		msg := strings.ReplaceAll(err.Error(), "\n", " ")
		return nil, fmt.Errorf("failed to parse action metadata file %q: %s", dir, msg)
	}

	c.debug("detected action metadata @ %s: %v", dir, &meta)
	c.writeCache(spec, &meta)
	return &meta, nil
}

// ローカルアクションのメタデータファイルを読み込む関数
func (c *LocalActionsMetadataCache) readLocalActionMetadataFile(dir string) ([]byte, bool) {
	paths := []string{
		filepath.Join(dir, "action.yaml"),
		filepath.Join(dir, "action.yml"),
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			return b, true
		}
	}
	return nil, false
}

type RemoteActionsMetadataCache struct {
	mu          sync.RWMutex
	fetcherOnce sync.Once
	fetcher     *remote.Fetcher
	fetcherErr  error
	cache       map[string]*ActionMetadata
	// failed records specs whose fetch exhausted the retry budget on
	// transient errors. Unlike cache (which stores definitive results such as
	// parsed metadata or a confirmed 404), a failed entry keeps returning the
	// original error so callers can tell "the action has no metadata" apart
	// from "resolution was degraded this run" — a transient failure must
	// never be converted into a silent nil, which would nondeterministically
	// suppress every resolver-backed rule for the rest of the run.
	failed map[string]error
	// consecutiveTransientFailures drives a run-wide circuit breaker: when
	// this many spec resolutions in a row exhaust their retry budget without
	// any success in between, the network is considered unavailable and
	// further fetches fail fast instead of burning attempts*paths*timeout per
	// remaining spec (e.g. a token set but no connectivity).
	consecutiveTransientFailures int
	breakerOpen                  bool
	flight                       singleflight.Group
	dbg                          io.Writer
	// fetchFile is a test seam; when nil, the lazily-constructed
	// remote.Fetcher is used.
	fetchFile func(ctx context.Context, repo *remote.RepositoryInfo, filePath, ref string) ([]byte, error)
	// sleep is a test seam for the retry backoff.
	sleep func(time.Duration)
}

type remoteActionSpec struct {
	owner string
	repo  string
	dir   string
	ref   string
}

const (
	// remoteMetadataFetchAttempts bounds retries per spec for transient
	// errors (timeouts, 5xx). 404 is definitive and never retried.
	remoteMetadataFetchAttempts = 3
	// remoteMetadataBreakerThreshold is the number of consecutive specs that
	// must exhaust their retry budget before the circuit breaker opens.
	remoteMetadataBreakerThreshold = 5
)

var errRemoteMetadataCircuitOpen = errors.New("remote action metadata resolution disabled for this run: too many consecutive network failures")

func NewRemoteActionsMetadataCache(dbg io.Writer) *RemoteActionsMetadataCache {
	return &RemoteActionsMetadataCache{
		cache:  make(map[string]*ActionMetadata),
		failed: make(map[string]error),
		dbg:    dbg,
		sleep:  time.Sleep,
	}
}

// ensureFetcher constructs the underlying remote.Fetcher on first use. The
// constructor of remote.Fetcher resolves a GitHub token, which in the absence
// of GITHUB_TOKEN/GH_TOKEN spawns external `gh auth token` and
// `git credential fill` processes. Deferring construction until a spec that
// actually requires network resolution is observed avoids that cost for files
// that never reach a remote composite-action lookup.
func (c *RemoteActionsMetadataCache) ensureFetcher() *remote.Fetcher {
	c.fetcherOnce.Do(func() {
		fetcher, err := remote.NewFetcher(1)
		if err != nil {
			c.fetcherErr = err
			if c.dbg != nil {
				fmt.Fprintf(c.dbg, "[RemoteActionsMetadataCache] failed to create remote fetcher: %v; FindMetadata remote resolution will be disabled\n", err)
			}
			return
		}
		c.fetcher = fetcher
	})
	return c.fetcher
}

func (c *RemoteActionsMetadataCache) debug(format string, args ...interface{}) {
	if c.dbg == nil {
		return
	}
	format = "[RemoteActionsMetadataCache] " + format + "\n"
	fmt.Fprintf(c.dbg, format, args...)
}

func (c *RemoteActionsMetadataCache) readCache(key string) (*ActionMetadata, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	m, ok := c.cache[key]
	return m, ok
}

func (c *RemoteActionsMetadataCache) writeCache(key string, val *ActionMetadata) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = val
}

func (c *RemoteActionsMetadataCache) FindMetadata(spec string) (*ActionMetadata, error) {
	if m, ok := c.readCache(spec); ok {
		c.debug("cache hit @ %s: %v", spec, m)
		return m, nil
	}
	if err := c.readFailed(spec); err != nil {
		return nil, err
	}

	actionSpec, ok := parseRemoteActionSpec(spec)
	if !ok {
		return nil, nil
	}

	// singleflight collapses concurrent lookups of the same spec (parallel
	// files of a run share this cache), so each action.yml is in flight at
	// most once regardless of how many workflows reference it.
	v, err, _ := c.flight.Do(spec, func() (interface{}, error) {
		if m, ok := c.readCache(spec); ok {
			return m, nil
		}
		if err := c.readFailed(spec); err != nil {
			return nil, err
		}
		return c.resolveRemote(spec, actionSpec)
	})
	meta, _ := v.(*ActionMetadata)
	return meta, err
}

func (c *RemoteActionsMetadataCache) readFailed(spec string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.failed[spec]
}

// noteTransientOutcome updates the circuit-breaker state. success resets the
// consecutive-failure counter; a spec that exhausted its retry budget
// increments it and may open the breaker for the rest of the run.
func (c *RemoteActionsMetadataCache) noteTransientOutcome(success bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if success {
		c.consecutiveTransientFailures = 0
		return
	}
	c.consecutiveTransientFailures++
	if !c.breakerOpen && c.consecutiveTransientFailures >= remoteMetadataBreakerThreshold {
		c.breakerOpen = true
		if c.dbg != nil {
			fmt.Fprintf(c.dbg, "[RemoteActionsMetadataCache] circuit breaker opened after %d consecutive fetch failures; remote metadata resolution disabled for this run\n", c.consecutiveTransientFailures)
		}
	}
}

func (c *RemoteActionsMetadataCache) isBreakerOpen() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.breakerOpen
}

func (c *RemoteActionsMetadataCache) doFetch(ctx context.Context, repo *remote.RepositoryInfo, filePath, ref string) ([]byte, error) {
	if c.fetchFile != nil {
		return c.fetchFile(ctx, repo, filePath, ref)
	}
	fetcher := c.ensureFetcher()
	if fetcher == nil {
		return nil, c.fetcherErr
	}
	return fetcher.FetchFile(ctx, repo, filePath, ref)
}

// isRemoteNotFoundError reports whether err is a definitive HTTP 404 — the
// file does not exist at that ref. Everything else (timeouts, 5xx, decode
// failures) is treated as transient and eligible for retry.
func isRemoteNotFoundError(err error) bool {
	var ghErr *github.ErrorResponse
	return errors.As(err, &ghErr) && ghErr.Response != nil && ghErr.Response.StatusCode == http.StatusNotFound
}

// resolveRemote fetches and parses the action metadata with bounded retries.
// Caching policy:
//   - parsed metadata          -> cached (definitive)
//   - 404 on every candidate   -> cached as nil (definitive: no metadata)
//   - unparseable content      -> cached as nil (definitive: not an action)
//   - transient failure        -> NOT cached; recorded in failed so repeat
//     lookups this run return the error immediately instead of re-burning
//     the retry budget, and a fresh run can succeed again
func (c *RemoteActionsMetadataCache) resolveRemote(spec string, actionSpec *remoteActionSpec) (*ActionMetadata, error) {
	if c.isBreakerOpen() {
		return nil, errRemoteMetadataCircuitOpen
	}

	repo := &remote.RepositoryInfo{
		Owner:    actionSpec.owner,
		Name:     actionSpec.repo,
		FullName: actionSpec.owner + "/" + actionSpec.repo,
	}

	var lastErr error
	for attempt := 0; attempt < remoteMetadataFetchAttempts; attempt++ {
		if attempt > 0 {
			c.debug("retrying metadata fetch for %s (attempt %d/%d) after transient error: %v", spec, attempt+1, remoteMetadataFetchAttempts, lastErr)
			c.sleep(time.Duration(attempt) * 500 * time.Millisecond)
		}

		var transientErr error
		notFound := 0
		paths := remoteActionMetadataPaths(actionSpec.dir)
		for _, metadataPath := range paths {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			b, err := c.doFetch(ctx, repo, metadataPath, actionSpec.ref)
			cancel()
			if err != nil {
				if isRemoteNotFoundError(err) {
					notFound++
					continue
				}
				if IsGitHubRateLimitError(err) {
					// Retrying cannot succeed until the rate window resets.
					// Not cached: a later authenticated run must be able to
					// resolve this spec.
					return nil, fmt.Errorf("failed to fetch remote action metadata for %q: %w", spec, err)
				}
				transientErr = err
				continue
			}

			var meta ActionMetadata
			if err := yaml.Unmarshal(b, &meta); err != nil {
				c.writeCache(spec, nil)
				c.noteTransientOutcome(true)
				msg := strings.ReplaceAll(err.Error(), "\n", " ")
				return nil, fmt.Errorf("failed to parse remote action metadata file %q: %s", metadataPath, msg)
			}

			c.debug("detected remote action metadata @ %s: %v", spec, &meta)
			c.writeCache(spec, &meta)
			c.noteTransientOutcome(true)
			return &meta, nil
		}

		if transientErr == nil && notFound == len(paths) {
			// Every candidate path answered 404: the action metadata does
			// not exist at this ref. Definitive, not an error.
			c.writeCache(spec, nil)
			c.noteTransientOutcome(true)
			return nil, nil
		}
		lastErr = transientErr
	}

	err := fmt.Errorf("failed to fetch remote action metadata for %q after %d attempts: %w", spec, remoteMetadataFetchAttempts, lastErr)
	c.mu.Lock()
	c.failed[spec] = err
	c.mu.Unlock()
	c.noteTransientOutcome(false)
	return nil, err
}

func parseRemoteActionSpec(spec string) (*remoteActionSpec, bool) {
	if spec == "" || strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, ".\\") || strings.HasPrefix(spec, "docker://") {
		return nil, false
	}

	at := strings.LastIndex(spec, "@")
	if at <= 0 || at == len(spec)-1 {
		return nil, false
	}

	actionPath := spec[:at]
	ref := spec[at+1:]
	parts := strings.Split(actionPath, "/")
	if len(parts) < 2 {
		return nil, false
	}

	dir := "."
	if len(parts) > 2 {
		dir = pathpkg.Clean(strings.Join(parts[2:], "/"))
		if dir == "." || strings.HasPrefix(dir, "/") || strings.HasPrefix(dir, "../") || dir == ".." {
			return nil, false
		}
	}

	return &remoteActionSpec{
		owner: parts[0],
		repo:  parts[1],
		dir:   dir,
		ref:   ref,
	}, true
}

func remoteActionMetadataPaths(dir string) []string {
	cleanDir := pathpkg.Clean(dir)
	return []string{
		pathpkg.Join(cleanDir, "action.yml"),
		pathpkg.Join(cleanDir, "action.yaml"),
	}
}

// ローカルアクションのメタデータキャッシュファクトリ構造体
type LocalActionsMetadataCacheFactory struct {
	caches map[string]*LocalActionsMetadataCache
	dbg    io.Writer
}

func (f *LocalActionsMetadataCacheFactory) GetCache(p *Project) *LocalActionsMetadataCache {
	if p == nil {
		return nullLocalActionsMetadataCache(f.dbg)
	}
	r := p.RootDirectory()
	if c, ok := f.caches[r]; ok {
		return c
	}
	c := NewLocalActionsMetadataCache(p, f.dbg)
	f.caches[r] = c
	return c
}

// ローカルアクションのメタデータキャッシュファクトリを新規作成する関数
func NewLocalActionsMetadataCacheFactory(dbg io.Writer) *LocalActionsMetadataCacheFactory {
	return &LocalActionsMetadataCacheFactory{map[string]*LocalActionsMetadataCache{}, dbg}
}
