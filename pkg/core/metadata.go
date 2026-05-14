package core

import (
	"context"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sisaku-security/sisakulint/pkg/remote"
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

	c.debug("detected action metadata @ %s: %v", dir, meta)
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
	dbg         io.Writer
}

type remoteActionSpec struct {
	owner string
	repo  string
	dir   string
	ref   string
}

func NewRemoteActionsMetadataCache(dbg io.Writer) *RemoteActionsMetadataCache {
	return &RemoteActionsMetadataCache{cache: make(map[string]*ActionMetadata), dbg: dbg}
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

	actionSpec, ok := parseRemoteActionSpec(spec)
	if !ok {
		return nil, nil
	}

	fetcher := c.ensureFetcher()
	if fetcher == nil {
		return nil, nil
	}

	repo := &remote.RepositoryInfo{
		Owner:    actionSpec.owner,
		Name:     actionSpec.repo,
		FullName: actionSpec.owner + "/" + actionSpec.repo,
	}

	var lastErr error
	for _, metadataPath := range remoteActionMetadataPaths(actionSpec.dir) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		b, err := fetcher.FetchFile(ctx, repo, metadataPath, actionSpec.ref)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}

		var meta ActionMetadata
		if err := yaml.Unmarshal(b, &meta); err != nil {
			c.writeCache(spec, nil)
			msg := strings.ReplaceAll(err.Error(), "\n", " ")
			return nil, fmt.Errorf("failed to parse remote action metadata file %q: %s", metadataPath, msg)
		}

		c.debug("detected remote action metadata @ %s: %v", spec, meta)
		c.writeCache(spec, &meta)
		return &meta, nil
	}

	c.writeCache(spec, nil)
	if lastErr != nil {
		return nil, fmt.Errorf("failed to fetch remote action metadata for %q: %w", spec, lastErr)
	}
	return nil, nil
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
