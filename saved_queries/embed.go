// Package savedqueries embeds the prebuilt BloodHound CE Cypher queries that
// ship with MSSQLHound so they can be uploaded to a BloodHound CE instance via
// POST /api/v2/saved-queries without any external file dependencies.
//
// The directory name (saved_queries) keeps its underscore for documentation
// and back-compat; this package directive uses a valid Go identifier.
package savedqueries

import "embed"

// FS contains every *.json file colocated with this source file.
//
//go:embed *.json
var FS embed.FS
