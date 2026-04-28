package uploader

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEmbeddedQueries(t *testing.T) {
	queries, err := LoadEmbeddedQueries()
	if err != nil {
		t.Fatalf("LoadEmbeddedQueries() error: %v", err)
	}
	if len(queries) < 11 {
		t.Fatalf("expected at least 11 embedded queries, got %d", len(queries))
	}
	for _, q := range queries {
		if q.Name == "" {
			t.Errorf("embedded query has empty Name: %+v", q)
		}
		if q.Query == "" {
			t.Errorf("embedded query %q has empty Query", q.Name)
		}
	}

	// Sorted by name.
	for i := 1; i < len(queries); i++ {
		if queries[i-1].Name > queries[i].Name {
			t.Errorf("embedded queries not sorted: %q before %q", queries[i-1].Name, queries[i].Name)
		}
	}
}

func TestLoadQueriesFromDir(t *testing.T) {
	tmp := t.TempDir()

	good := `{"name":"Test One","query":"MATCH (n) RETURN n LIMIT 1","description":"smoke"}`
	missingName := `{"query":"MATCH (n) RETURN n"}`
	missingQuery := `{"name":"NoQuery"}`
	bogus := `not json at all`

	mustWrite := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(tmp, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	mustWrite("good.json", good)
	mustWrite("missing_name.json", missingName)
	mustWrite("missing_query.json", missingQuery)
	mustWrite("bogus.json", bogus)
	mustWrite("readme.md", "# not a json file")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	queries, err := LoadQueriesFromDir(tmp, logger)
	if err != nil {
		t.Fatalf("LoadQueriesFromDir() error: %v", err)
	}
	if len(queries) != 1 {
		t.Fatalf("expected 1 valid query (3 invalid + 1 non-json skipped), got %d", len(queries))
	}
	if queries[0].Name != "Test One" {
		t.Errorf("Name = %q, want %q", queries[0].Name, "Test One")
	}
	if queries[0].Description != "smoke" {
		t.Errorf("Description = %q, want %q", queries[0].Description, "smoke")
	}
}

func TestLoadQueriesFromDir_EmptyPath(t *testing.T) {
	got, err := LoadQueriesFromDir("", nil)
	if err != nil {
		t.Fatalf("expected nil error for empty dir, got %v", err)
	}
	if got != nil {
		t.Errorf("expected nil slice for empty dir, got %v", got)
	}
}

func TestLoadQueriesFromDir_NotADirectory(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "regular.txt")
	if err := os.WriteFile(file, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadQueriesFromDir(file, nil); err == nil {
		t.Fatal("expected error when --queries-dir points at a file, got nil")
	}
}

func TestMergeQueries_CustomOverridesBundled(t *testing.T) {
	bundled := []SavedQuery{
		{Name: "A", Query: "bundled-a", Description: "bundled"},
		{Name: "B", Query: "bundled-b"},
	}
	custom := []SavedQuery{
		{Name: "B", Query: "custom-b", Description: "ops"},
		{Name: "C", Query: "custom-c"},
	}

	merged := MergeQueries(bundled, custom)
	if len(merged) != 3 {
		t.Fatalf("len = %d, want 3", len(merged))
	}

	// Sorted by Name; index by Name for assertions.
	got := map[string]SavedQuery{}
	for _, q := range merged {
		got[q.Name] = q
	}
	if got["A"].Query != "bundled-a" {
		t.Errorf("A.Query = %q, want %q", got["A"].Query, "bundled-a")
	}
	if got["B"].Query != "custom-b" {
		t.Errorf("B.Query = %q, want %q (custom should override)", got["B"].Query, "custom-b")
	}
	if got["B"].Description != "ops" {
		t.Errorf("B.Description = %q, want %q", got["B"].Description, "ops")
	}
	if got["C"].Query != "custom-c" {
		t.Errorf("C.Query = %q, want %q", got["C"].Query, "custom-c")
	}
}

func TestSavedQuery_MarshalJSON(t *testing.T) {
	q := SavedQuery{Name: "X", Query: "MATCH (n) RETURN n", Description: "doc"}
	body, err := q.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"name":"X","query":"MATCH (n) RETURN n","description":"doc"}`
	if string(body) != want {
		t.Errorf("MarshalJSON =\n  %s\nwant\n  %s", body, want)
	}
}

func TestSavedQuery_MarshalJSON_OmitsEmptyDescription(t *testing.T) {
	q := SavedQuery{Name: "X", Query: "MATCH (n) RETURN n"}
	body, err := q.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"name":"X","query":"MATCH (n) RETURN n"}`
	if string(body) != want {
		t.Errorf("MarshalJSON =\n  %s\nwant\n  %s", body, want)
	}
}
