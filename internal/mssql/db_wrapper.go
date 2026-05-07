// Package mssql provides SQL Server connection and data collection functionality.
package mssql

import (
	"context"
	"database/sql"
)

// DBWrapper provides a small interface around database/sql query methods.
type DBWrapper struct {
	db *sql.DB
}

// NewDBWrapper creates a new database wrapper.
func NewDBWrapper(db *sql.DB) *DBWrapper {
	return &DBWrapper{db: db}
}

// RowScanner provides a unified interface for scanning rows.
type RowScanner interface {
	Scan(dest ...interface{}) error
}

// Rows provides a unified interface for iterating over query results.
type Rows interface {
	Next() bool
	Scan(dest ...interface{}) error
	Close() error
	Err() error
	Columns() ([]string, error)
}

// nativeRows wraps sql.Rows.
type nativeRows struct {
	rows *sql.Rows
}

func (r *nativeRows) Next() bool                     { return r.rows.Next() }
func (r *nativeRows) Scan(dest ...interface{}) error { return r.rows.Scan(dest...) }
func (r *nativeRows) Close() error                   { return r.rows.Close() }
func (r *nativeRows) Err() error                     { return r.rows.Err() }
func (r *nativeRows) Columns() ([]string, error)     { return r.rows.Columns() }

// QueryContext executes a query and returns rows.
func (w *DBWrapper) QueryContext(ctx context.Context, query string, args ...interface{}) (Rows, error) {
	rows, err := w.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return &nativeRows{rows: rows}, nil
}

// QueryRowContext executes a query and returns a single row.
func (w *DBWrapper) QueryRowContext(ctx context.Context, query string, args ...interface{}) RowScanner {
	return w.db.QueryRowContext(ctx, query, args...)
}

// ExecContext executes a query without returning rows.
func (w *DBWrapper) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return w.db.ExecContext(ctx, query, args...)
}
