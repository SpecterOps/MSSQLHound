# Plan: Publish Cross-Platform Release Binaries via workflow_dispatch

## Context

MSSQLHound currently has one GitHub Actions workflow ([.github/workflows/ci.yml](.github/workflows/ci.yml)) for unit and integration tests, but no release automation — producing binaries for end users is a manual `go build` today. The Go entrypoint [cmd/mssqlhound/main.go:20](cmd/mssqlhound/main.go#L20) hard-codes `version = "2.0.0"`, so published binaries currently can't report the release they came from.

Goal: a new workflow that, on manual dispatch, builds `mssqlhound` for 6 OS/arch targets, embeds the release version into each binary, and publishes all six plus a SHA256 checksum file to a brand-new GitHub Release. Decisions confirmed with user:

- **Targets:** linux/amd64, linux/arm64, windows/amd64, windows/arm64, darwin/amd64, darwin/arm64
- **Versioning:** `workflow_dispatch` takes a `tag` input (e.g. `v2.0.0`); the release job creates and pushes the tag automatically via `softprops/action-gh-release` (using `target_commitish`)
- **Checksums:** generate `checksums.txt` (SHA256) alongside the binaries
- **Release state:** publish immediately (not draft, not prerelease)

## New file

Create **[.github/workflows/release.yml](.github/workflows/release.yml)**:

```yaml
name: Release

on:
  workflow_dispatch:
    inputs:
      tag:
        description: "Release tag (e.g. v2.0.0). Must match v<major>.<minor>.<patch>[-suffix]."
        required: true
        type: string
      release_notes:
        description: "Release notes body (markdown). Optional."
        required: false
        type: string

permissions:
  contents: write   # needed to create tag + release

concurrency:
  group: release-${{ inputs.tag }}
  cancel-in-progress: false

jobs:
  validate:
    name: Validate inputs
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Check tag format
        run: |
          echo "${{ inputs.tag }}" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$' \
            || { echo "Invalid tag: ${{ inputs.tag }}"; exit 1; }
      - name: Ensure tag does not already exist
        run: |
          if git rev-parse "refs/tags/${{ inputs.tag }}" >/dev/null 2>&1; then
            echo "Tag ${{ inputs.tag }} already exists — pick a new one."; exit 1
          fi

  build:
    name: Build ${{ matrix.goos }}/${{ matrix.goarch }}
    needs: validate
    runs-on: ubuntu-latest
    strategy:
      fail-fast: true
      matrix:
        include:
          - { goos: linux,   goarch: amd64, ext: "" }
          - { goos: linux,   goarch: arm64, ext: "" }
          - { goos: windows, goarch: amd64, ext: ".exe" }
          - { goos: windows, goarch: arm64, ext: ".exe" }
          - { goos: darwin,  goarch: amd64, ext: "" }
          - { goos: darwin,  goarch: arm64, ext: "" }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: "go.mod"
          cache: true
      - name: Build
        env:
          GOOS: ${{ matrix.goos }}
          GOARCH: ${{ matrix.goarch }}
          CGO_ENABLED: "0"
        run: |
          set -euo pipefail
          VERSION="${{ inputs.tag }}"
          VERSION_NO_V="${VERSION#v}"
          OUT="mssqlhound-${VERSION}-${GOOS}-${GOARCH}${{ matrix.ext }}"
          mkdir -p dist
          go build -trimpath \
            -ldflags "-s -w -X main.version=${VERSION_NO_V}" \
            -o "dist/${OUT}" ./cmd/mssqlhound
          ls -lh dist/
      - uses: actions/upload-artifact@v4
        with:
          name: mssqlhound-${{ matrix.goos }}-${{ matrix.goarch }}
          path: dist/*
          if-no-files-found: error
          retention-days: 7

  release:
    name: Create GitHub Release
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
        with:
          path: dist
          merge-multiple: true
      - name: Generate SHA256 checksums
        working-directory: dist
        run: |
          sha256sum * > checksums.txt
          echo "--- checksums.txt ---"
          cat checksums.txt
      - name: Create release and upload assets
        uses: softprops/action-gh-release@v2
        with:
          tag_name: ${{ inputs.tag }}
          name: ${{ inputs.tag }}
          body: ${{ inputs.release_notes }}
          target_commitish: ${{ github.sha }}   # tag is created pointing at this commit
          draft: false
          prerelease: false
          files: dist/*
          fail_on_unmatched_files: true
```

## How it works

1. **`validate`** — fails fast if the tag isn't `vX.Y.Z[-suffix]` or already exists, so we don't burn 6 parallel builds on a typo.
2. **`build`** (matrix, 6 jobs in parallel) — sets `GOOS`/`GOARCH`, builds with `CGO_ENABLED=0` (the module graph in [go.mod](go.mod) is pure Go, so cross-compilation works cleanly), injects the tag via `-X main.version=...` into the `version` var in [cmd/mssqlhound/main.go:20](cmd/mssqlhound/main.go#L20), and uploads one artifact per target. `-trimpath -s -w` strips local paths and debug info for smaller, reproducible binaries.
3. **`release`** — downloads all six artifacts, computes `sha256sum` into `checksums.txt`, and `softprops/action-gh-release@v2` (a) creates the tag on the current commit via `target_commitish`, (b) publishes the release immediately, and (c) attaches all files from `dist/`.

## Why these choices

- **`workflow_dispatch` only** — matches your request; no tag-push trigger. You drive releases from the Actions tab.
- **softprops/action-gh-release creates the tag** — avoids a separate git-push step with its own auth plumbing. Keeps `contents: write` as the only elevated permission.
- **`CGO_ENABLED=0`** — lets one ubuntu-latest runner cross-compile all six targets. No per-OS runners needed, so the matrix is fast and cheap.
- **Immediate publish** — matches your answer. Easy to switch later by flipping `draft: true` or adding a boolean input.
- **Naming `mssqlhound-vX.Y.Z-<os>-<arch>[.exe]`** — standard Go-release convention; sorts predictably in the Releases UI.

## Verification

After the file is committed to `main`:

1. **Local sanity check** (before pushing the workflow): run `go build -ldflags "-X main.version=2.0.0-test" ./cmd/mssqlhound && ./mssqlhound --version` (or whatever flag surfaces `version`) to confirm ldflags injection targets the right symbol.
2. **Dry run on a test tag:** go to *Actions → Release → Run workflow*, enter `v0.0.1-test` (or similar). Confirm:
   - All 6 `build` matrix jobs succeed.
   - `release` job creates a new tag + Release with 7 assets (6 binaries + `checksums.txt`).
   - `sha256sum -c checksums.txt` passes locally after downloading.
   - Each binary reports the injected version when run (`mssqlhound --version`).
3. **Cleanup:** delete the test tag + release from GitHub if you don't want it sticking around.
4. **Real release:** re-run with the actual tag (e.g. `v2.0.1`).

## Follow-ups not in scope

- Per project rule #6, after approval this plan should also be copied to `.claude/plans/` in the repo (the plan-mode workflow restricted edits to this scratch file).
- Consider updating [README.md](README.md) with a "Releases" section pointing users at the GitHub Releases page once the first real release is out.
- If you later want code signing (Authenticode for Windows, notarization for macOS), that's a separate pass — the current workflow intentionally ships unsigned binaries to keep the first version simple.
