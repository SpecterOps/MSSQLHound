package uploader

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
)

// UploadSummary holds the aggregate result of uploading files.
type UploadSummary struct {
	// FilesUploaded is the total number of files successfully uploaded.
	FilesUploaded int
	// FilesFailed is the total number of files that failed to upload.
	FilesFailed int
	// Errors contains any errors encountered during upload.
	Errors []error
}

// SavedQueryUploadSummary holds the aggregate result of uploading saved queries.
type SavedQueryUploadSummary struct {
	// Created is the count of queries that were newly POSTed to BH CE.
	Created int
	// Updated is the count of queries whose existing record was PUT-updated.
	Updated int
	// Failed is the count of queries that errored on either path.
	Failed int
	// Errors contains the per-query errors encountered, in submission order.
	Errors []error
}

// Uploader manages uploading collector output files to BloodHound CE.
type Uploader struct {
	// Client is the BloodHound CE API client.
	Client *Client

	// Logger is the structured logger for all output.
	Logger *slog.Logger
}

// NewUploader creates an Uploader for the given BloodHound CE instance.
// Returns nil if url is empty.
func NewUploader(url, tokenID, tokenKey string, logger *slog.Logger) *Uploader {
	if url == "" {
		return nil
	}

	var auth Authenticator
	if tokenID != "" && tokenKey != "" {
		auth = &HMACAuth{
			TokenID:  tokenID,
			TokenKey: tokenKey,
		}
	} else if tokenID != "" {
		// If only tokenID is provided, treat it as a JWT Bearer token.
		auth = &BearerAuth{Token: tokenID}
	} else {
		return nil
	}

	if normalized := NormalizeBaseURL(url); normalized != url && logger != nil {
		logger.Info("Normalized BloodHound URL", "from", url, "to", normalized)
	}

	return &Uploader{
		Client: NewClient(url, auth),
		Logger: logger,
	}
}

// UploadFiles uploads the given files to BloodHound CE. It starts a single
// upload job, uploads all files, and signals job completion.
func (u *Uploader) UploadFiles(ctx context.Context, files []string) UploadSummary {
	var summary UploadSummary

	if len(files) == 0 {
		return summary
	}

	u.Logger.Info("Uploading to BloodHound", "files", len(files))

	// Phase 1: Start the upload job.
	jobID, err := u.Client.StartUpload(ctx)
	if err != nil {
		summary.FilesFailed = len(files)
		summary.Errors = append(summary.Errors, fmt.Errorf("failed to start upload: %w", err))
		u.Logger.Warn("Failed to start upload", "error", err)
		return summary
	}

	u.Logger.Debug("Upload job started", "jobID", jobID)

	// Phase 2: Upload each file.
	for _, f := range files {
		if ctx.Err() != nil {
			summary.FilesFailed += len(files) - summary.FilesUploaded - summary.FilesFailed
			summary.Errors = append(summary.Errors, ctx.Err())
			break
		}

		name := filepath.Base(f)
		u.Logger.Debug("Uploading file", "file", name)
		if err := u.Client.UploadFile(ctx, jobID, f); err != nil {
			summary.FilesFailed++
			summary.Errors = append(summary.Errors, fmt.Errorf("%s: %w", name, err))
			u.Logger.Warn("Failed to upload file", "file", name, "error", err)
			continue
		}
		summary.FilesUploaded++
		u.Logger.Info("Uploaded file", "file", name)
	}

	// Phase 3: End the upload job.
	if err := u.Client.EndUpload(ctx, jobID); err != nil {
		u.Logger.Warn("Failed to end upload job", "error", err)
		summary.Errors = append(summary.Errors, fmt.Errorf("end upload: %w", err))
	}

	return summary
}

// UploadSavedQueries pushes each query to BloodHound CE as a saved Cypher
// query. A single ListSavedQueries() call up front builds a name->id index,
// so existing entries are PUT-updated (preserving id, ownership, and any
// sharing) and new entries are POST-created. Per-query failures are captured
// in the summary; the loop never aborts early.
func (u *Uploader) UploadSavedQueries(ctx context.Context, queries []SavedQuery) SavedQueryUploadSummary {
	var summary SavedQueryUploadSummary

	if len(queries) == 0 {
		return summary
	}

	u.Logger.Info("Uploading saved queries to BloodHound", "queries", len(queries))

	existing, err := u.Client.ListSavedQueries(ctx)
	if err != nil {
		summary.Failed = len(queries)
		summary.Errors = append(summary.Errors, fmt.Errorf("list saved queries: %w", err))
		u.Logger.Warn("Failed to enumerate existing saved queries; aborting upload", "error", err)
		return summary
	}

	for _, q := range queries {
		if ctx.Err() != nil {
			summary.Failed += len(queries) - summary.Created - summary.Updated - summary.Failed
			summary.Errors = append(summary.Errors, ctx.Err())
			break
		}

		if id, ok := existing[q.Name]; ok {
			u.Logger.Debug("Updating saved query", "name", q.Name, "id", id)
			if err := u.Client.UpdateSavedQuery(ctx, id, q); err != nil {
				summary.Failed++
				summary.Errors = append(summary.Errors, fmt.Errorf("%s: %w", q.Name, err))
				u.Logger.Warn("Failed to update saved query", "name", q.Name, "error", err)
				continue
			}
			summary.Updated++
			u.Logger.Info("Updated saved query", "name", q.Name)
			continue
		}

		u.Logger.Debug("Creating saved query", "name", q.Name)
		if err := u.Client.CreateSavedQuery(ctx, q); err != nil {
			summary.Failed++
			summary.Errors = append(summary.Errors, fmt.Errorf("%s: %w", q.Name, err))
			u.Logger.Warn("Failed to create saved query", "name", q.Name, "error", err)
			continue
		}
		summary.Created++
		u.Logger.Info("Created saved query", "name", q.Name)
	}

	return summary
}
