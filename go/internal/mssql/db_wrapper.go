// Package mssql provides SQL Server connection and data collection functionality.
package mssql

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// DBWrapper provides a unified interface for database queries
// that works with both native go-mssqldb and PowerShell fallback modes.
type DBWrapper struct {
	db            *sql.DB           // Native database connection
	psClient      *PowerShellClient // PowerShell client for fallback
	usePowerShell bool
}

// NewDBWrapper creates a new database wrapper
func NewDBWrapper(db *sql.DB, psClient *PowerShellClient, usePowerShell bool) *DBWrapper {
	return &DBWrapper{
		db:            db,
		psClient:      psClient,
		usePowerShell: usePowerShell,
	}
}

// RowScanner provides a unified interface for scanning rows
type RowScanner interface {
	Scan(dest ...interface{}) error
}

// Rows provides a unified interface for iterating over query results
type Rows interface {
	Next() bool
	Scan(dest ...interface{}) error
	Close() error
	Err() error
	Columns() ([]string, error)
}

// nativeRows wraps sql.Rows
type nativeRows struct {
	rows *sql.Rows
}

func (r *nativeRows) Next() bool                     { return r.rows.Next() }
func (r *nativeRows) Scan(dest ...interface{}) error { return r.rows.Scan(dest...) }
func (r *nativeRows) Close() error                   { return r.rows.Close() }
func (r *nativeRows) Err() error                     { return r.rows.Err() }
func (r *nativeRows) Columns() ([]string, error)     { return r.rows.Columns() }

// psRows wraps PowerShell query results to implement the Rows interface
type psRows struct {
	results []QueryResult
	columns []string // Column names in query order (from QueryResponse)
	current int
	lastErr error
}

func newPSRows(response *QueryResponse) *psRows {
	r := &psRows{
		results: response.Rows,
		columns: response.Columns, // Use column order from PowerShell response
		current: -1,
	}
	return r
}

func (r *psRows) Next() bool {
	r.current++
	return r.current < len(r.results)
}

func (r *psRows) Scan(dest ...interface{}) error {
	if r.current >= len(r.results) || r.current < 0 {
		return sql.ErrNoRows
	}

	row := r.results[r.current]

	// Match columns to destinations in order
	for i, col := range r.columns {
		if i >= len(dest) {
			break
		}
		if err := scanValue(row[col], dest[i]); err != nil {
			r.lastErr = err
			return err
		}
	}
	return nil
}

func (r *psRows) Close() error               { return nil }
func (r *psRows) Err() error                 { return r.lastErr }
func (r *psRows) Columns() ([]string, error) { return r.columns, nil }

// scanValue converts a PowerShell query result value to the destination type
func scanValue(src interface{}, dest interface{}) error {
	if src == nil {
		switch d := dest.(type) {
		case *sql.NullString:
			d.Valid = false
			return nil
		case *sql.NullInt64:
			d.Valid = false
			return nil
		case *sql.NullBool:
			d.Valid = false
			return nil
		case *sql.NullInt32:
			d.Valid = false
			return nil
		case *sql.NullFloat64:
			d.Valid = false
			return nil
		case *sql.NullTime:
			d.Valid = false
			return nil
		case *string:
			*d = ""
			return nil
		case *int:
			*d = 0
			return nil
		case *int64:
			*d = 0
			return nil
		case *bool:
			*d = false
			return nil
		case *time.Time:
			*d = time.Time{}
			return nil
		case *interface{}:
			*d = nil
			return nil
		case *[]byte:
			*d = nil
			return nil
		default:
			return nil
		}
	}

	switch d := dest.(type) {
	case *sql.NullString:
		d.Valid = true
		switch v := src.(type) {
		case string:
			d.String = v
		case float64:
			d.String = fmt.Sprintf("%v", v)
		default:
			d.String = fmt.Sprintf("%v", v)
		}
		return nil

	case *sql.NullInt64:
		d.Valid = true
		switch v := src.(type) {
		case float64:
			d.Int64 = int64(v)
		case int:
			d.Int64 = int64(v)
		case int64:
			d.Int64 = v
		case bool:
			if v {
				d.Int64 = 1
			} else {
				d.Int64 = 0
			}
		default:
			d.Int64 = 0
		}
		return nil

	case *sql.NullInt32:
		d.Valid = true
		switch v := src.(type) {
		case float64:
			d.Int32 = int32(v)
		case int:
			d.Int32 = int32(v)
		case int64:
			d.Int32 = int32(v)
		case bool:
			if v {
				d.Int32 = 1
			} else {
				d.Int32 = 0
			}
		default:
			d.Int32 = 0
		}
		return nil

	case *sql.NullBool:
		d.Valid = true
		switch v := src.(type) {
		case bool:
			d.Bool = v
		case float64:
			d.Bool = v != 0
		case int:
			d.Bool = v != 0
		default:
			d.Bool = false
		}
		return nil

	case *sql.NullFloat64:
		d.Valid = true
		switch v := src.(type) {
		case float64:
			d.Float64 = v
		case int:
			d.Float64 = float64(v)
		case int64:
			d.Float64 = float64(v)
		default:
			d.Float64 = 0
		}
		return nil

	case *string:
		switch v := src.(type) {
		case string:
			*d = v
		default:
			*d = fmt.Sprintf("%v", v)
		}
		return nil

	case *int:
		switch v := src.(type) {
		case float64:
			*d = int(v)
		case int:
			*d = v
		case int64:
			*d = int(v)
		default:
			*d = 0
		}
		return nil

	case *int64:
		switch v := src.(type) {
		case float64:
			*d = int64(v)
		case int:
			*d = int64(v)
		case int64:
			*d = v
		default:
			*d = 0
		}
		return nil

	case *bool:
		switch v := src.(type) {
		case bool:
			*d = v
		case float64:
			*d = v != 0
		case int:
			*d = v != 0
		default:
			*d = false
		}
		return nil

	case *time.Time:
		switch v := src.(type) {
		case string:
			// Try common date formats from PowerShell/JSON
			formats := []string{
				time.RFC3339,
				"2006-01-02T15:04:05.999999999Z07:00",
				"2006-01-02T15:04:05Z",
				"2006-01-02T15:04:05",
				"2006-01-02 15:04:05",
				"1/2/2006 3:04:05 PM",
				"/Date(1136239445000)/", // .NET JSON date format
			}
			for _, format := range formats {
				if t, err := time.Parse(format, v); err == nil {
					*d = t
					return nil
				}
			}
			*d = time.Time{}
		case time.Time:
			*d = v
		default:
			*d = time.Time{}
		}
		return nil

	case *sql.NullTime:
		d.Valid = true
		switch v := src.(type) {
		case string:
			formats := []string{
				time.RFC3339,
				"2006-01-02T15:04:05.999999999Z07:00",
				"2006-01-02T15:04:05Z",
				"2006-01-02T15:04:05",
				"2006-01-02 15:04:05",
				"1/2/2006 3:04:05 PM",
			}
			for _, format := range formats {
				if t, err := time.Parse(format, v); err == nil {
					d.Time = t
					return nil
				}
			}
			d.Valid = false
			d.Time = time.Time{}
		case time.Time:
			d.Time = v
		default:
			d.Valid = false
			d.Time = time.Time{}
		}
		return nil

	case *interface{}:
		*d = src
		return nil

	case *[]byte: // []uint8 is same as []byte
		// Handle byte slices (used for binary data like SIDs)
		bytesDest := dest.(*[]byte)
		switch v := src.(type) {
		case string:
			// String from JSON - could be base64 or hex
			*bytesDest = []byte(v)
		case []byte:
			*bytesDest = v
		case []interface{}:
			// PowerShell sometimes returns byte arrays as array of numbers
			bytes := make([]byte, len(v))
			for i, b := range v {
				if num, ok := b.(float64); ok {
					bytes[i] = byte(num)
				}
			}
			*bytesDest = bytes
		default:
			// Set to empty slice
			*bytesDest = []byte{}
		}
		return nil

	default:
		return fmt.Errorf("unsupported scan destination type: %T", dest)
	}
}

// QueryContext executes a query and returns rows
func (w *DBWrapper) QueryContext(ctx context.Context, query string, args ...interface{}) (Rows, error) {
	if w.usePowerShell {
		// PowerShell doesn't support parameterized queries well, so we only support queries without args
		if len(args) > 0 {
			return nil, fmt.Errorf("PowerShell mode does not support parameterized queries")
		}
		response, err := w.psClient.ExecuteQuery(ctx, query)
		if err != nil {
			return nil, err
		}
		return newPSRows(response), nil
	}

	rows, err := w.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return &nativeRows{rows: rows}, nil
}

// QueryRowContext executes a query and returns a single row
func (w *DBWrapper) QueryRowContext(ctx context.Context, query string, args ...interface{}) RowScanner {
	if w.usePowerShell {
		if len(args) > 0 {
			return &errorRowScanner{err: fmt.Errorf("PowerShell mode does not support parameterized queries")}
		}
		response, err := w.psClient.ExecuteQuery(ctx, query)
		if err != nil {
			return &errorRowScanner{err: err}
		}
		if len(response.Rows) == 0 {
			return &errorRowScanner{err: sql.ErrNoRows}
		}
		rows := newPSRows(response)
		rows.Next() // Advance to first row
		return rows
	}

	return w.db.QueryRowContext(ctx, query, args...)
}

// ExecContext executes a query without returning rows
func (w *DBWrapper) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	if w.usePowerShell {
		if len(args) > 0 {
			return nil, fmt.Errorf("PowerShell mode does not support parameterized queries")
		}
		_, err := w.psClient.ExecuteQuery(ctx, query)
		if err != nil {
			return nil, err
		}
		return &psResult{}, nil
	}

	return w.db.ExecContext(ctx, query, args...)
}

// psResult implements sql.Result for PowerShell mode
type psResult struct{}

func (r *psResult) LastInsertId() (int64, error) { return 0, nil }
func (r *psResult) RowsAffected() (int64, error) { return 0, nil }

// errorRowScanner returns an error on Scan
type errorRowScanner struct {
	err error
}

func (r *errorRowScanner) Scan(dest ...interface{}) error {
	return r.err
}
