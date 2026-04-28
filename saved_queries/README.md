Please note that you must ingest the `seed_data.json` file in order to successfully run the prebuilt Cypher queries in this directory if any of the edge classes are not already present in your BloodHound graph database.

## Automated upload

These queries are also embedded into the `mssqlhound` binary at build time and can be installed directly into a BloodHound CE instance via the API — no manual import required:

```bash
# Install just the bundled queries (PUT-updates existing names, POST-creates new ones)
./mssqlhound -B '<token-id>:<token-key>@https://bloodhound.example.com' --upload-queries-only

# Install bundled queries plus your own *.json files from a directory (additive)
./mssqlhound -B '<token-id>:<token-key>@https://bloodhound.example.com' \
  --upload-queries-only --queries-dir /path/to/extra/queries
```

When `-B` is set without an `--upload-*-only` flag, queries are uploaded alongside schema and results. Use `--no-upload-queries` to suppress this.

Custom-directory JSON files use the same shape as the files here: `{"name": "...", "query": "...", "description": "..."}`.
