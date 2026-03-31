// MSSQLHound - BloodHound collector for MSSQL attack paths
// Copyright (C) 2024  SpecterOps
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
