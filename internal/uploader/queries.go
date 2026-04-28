package uploader

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	savedqueries "github.com/SpecterOps/MSSQLHound/saved_queries"
)

// SavedQuery is the in-memory representation of a BloodHound CE saved Cypher
// query as accepted by POST/PUT /api/v2/saved-queries.
type SavedQuery struct {
	Name        string
	Query       string
	Description string
}

// savedQueryFile is the JSON shape for both the embedded saved_queries/*.json
// and any user-supplied --queries-dir/*.json files.
type savedQueryFile struct {
	Name        string `json:"name"`
	Query       string `json:"query"`
	Description string `json:"description,omitempty"`
}

// MarshalJSON renders a SavedQuery as the BloodHound CE request body.
func (q SavedQuery) MarshalJSON() ([]byte, error) {
	return json.Marshal(savedQueryFile{
		Name:        q.Name,
		Query:       q.Query,
		Description: q.Description,
	})
}

// LoadEmbeddedQueries returns every saved query embedded into the binary at
// build time. The returned slice is sorted by Name for deterministic ordering.
func LoadEmbeddedQueries() ([]SavedQuery, error) {
	entries, err := savedqueries.FS.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("read embedded saved_queries: %w", err)
	}

	queries := make([]SavedQuery, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		data, readErr := fs.ReadFile(savedqueries.FS, e.Name())
		if readErr != nil {
			return nil, fmt.Errorf("read embedded saved query %s: %w", e.Name(), readErr)
		}
		q, parseErr := parseQueryBytes(data)
		if parseErr != nil {
			return nil, fmt.Errorf("parse embedded saved query %s: %w", e.Name(), parseErr)
		}
		queries = append(queries, q)
	}

	sortByName(queries)
	return queries, nil
}

// LoadQueriesFromDir reads every *.json file in dir and returns those that
// parse as valid SavedQuery records. Invalid or unreadable files are logged
// at Warn level and skipped so a single malformed file does not block the
// whole upload. Non-.json entries are ignored.
func LoadQueriesFromDir(dir string, logger *slog.Logger) ([]SavedQuery, error) {
	if dir == "" {
		return nil, nil
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}

	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat queries dir %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("--queries-dir %s is not a directory", dir)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read queries dir %s: %w", dir, err)
	}

	queries := make([]SavedQuery, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			logger.Warn("Skipped saved query file (read failed)", "file", path, "error", readErr)
			continue
		}
		q, parseErr := parseQueryBytes(data)
		if parseErr != nil {
			logger.Warn("Skipped saved query file (invalid)", "file", path, "error", parseErr)
			continue
		}
		queries = append(queries, q)
	}

	sortByName(queries)
	return queries, nil
}

// MergeQueries combines bundled and custom-dir queries. On a name collision
// the custom-dir entry replaces the bundled one, so operators can override
// shipped queries without forking the binary. Output is sorted by Name.
func MergeQueries(bundled, custom []SavedQuery) []SavedQuery {
	merged := make(map[string]SavedQuery, len(bundled)+len(custom))
	for _, q := range bundled {
		merged[q.Name] = q
	}
	for _, q := range custom {
		merged[q.Name] = q
	}

	out := make([]SavedQuery, 0, len(merged))
	for _, q := range merged {
		out = append(out, q)
	}
	sortByName(out)
	return out
}

// parseQueryBytes decodes a single saved-query JSON document and validates
// that the required fields are populated.
func parseQueryBytes(data []byte) (SavedQuery, error) {
	var f savedQueryFile
	if err := json.Unmarshal(data, &f); err != nil {
		return SavedQuery{}, fmt.Errorf("unmarshal: %w", err)
	}
	f.Name = strings.TrimSpace(f.Name)
	f.Query = strings.TrimSpace(f.Query)
	if f.Name == "" {
		return SavedQuery{}, fmt.Errorf("missing required field: name")
	}
	if f.Query == "" {
		return SavedQuery{}, fmt.Errorf("missing required field: query")
	}
	return SavedQuery{
		Name:        f.Name,
		Query:       f.Query,
		Description: f.Description,
	}, nil
}

func sortByName(qs []SavedQuery) {
	sort.Slice(qs, func(i, j int) bool { return qs[i].Name < qs[j].Name })
}
