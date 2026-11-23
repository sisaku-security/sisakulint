package analysis

// CacheWrite is whether a job's cache-mode, written for the job or else
// the workflow, lets it save caches: what the run may write when it is not written is the event's.
type CacheWrite uint8

const (
	CacheWriteYes       CacheWrite = iota // write or write-only, or a ${{ }} that reads a context, which GitHub refuses to run
	CacheWriteNo                          // read or none
	CacheWriteUnwritten                   // not written: the event decides
)

var cacheWriteNames = [...]string{"CacheWriteYes", "CacheWriteNo", "CacheWriteUnwritten"}

func (w CacheWrite) String() string { return cacheWriteNames[w] }

// CacheAction is an action that saves to the cache what a path has.
type CacheAction uint8

const (
	CacheActionNone  CacheAction = iota
	CacheActionCache             // actions/cache: restores, and saves at the end of the job (its post step)
	CacheActionSave              // actions/cache/save: saves at the step
)

var cacheActionNames = [...]string{"CacheActionNone", "CacheActionCache", "CacheActionSave"}

func (a CacheAction) String() string { return cacheActionNames[a] }

// CacheMode is a value of cache-mode: GitHub takes these four,
// written in lower case, and refuses the workflow for any other.
type CacheMode uint8

const (
	CacheModeUnset     CacheMode = iota
	CacheModeRead                // restores, saves nothing
	CacheModeWrite               // restores and saves
	CacheModeWriteOnly           // saves, restores nothing
	CacheModeNone                // neither
)

var cacheModeNames = [...]string{"", "read", "write", "write-only", "none"}

// String is the value as cache-mode writes it; empty for CacheModeUnset.
func (m CacheMode) String() string { return cacheModeNames[m] }

// Saves is whether m lets a job save to the cache.
func (m CacheMode) Saves() bool { return m == CacheModeWrite || m == CacheModeWriteOnly }

// ParseCacheMode is the value s writes; ok is false for one GitHub refuses.
func ParseCacheMode(s string) (m CacheMode, ok bool) {
	for i, n := range cacheModeNames {
		if i > 0 && n == s {
			return CacheMode(i), true
		}
	}
	return CacheModeUnset, false
}
