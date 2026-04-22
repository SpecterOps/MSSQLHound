// Package logging provides a custom slog handler with colored, human-readable output.
package logging

import (
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"sync"
	"time"
)

// LevelVerbose sits between INFO and DEBUG for detailed progress messages.
const LevelVerbose = slog.Level(-2)

// Handler implements slog.Handler with the format:
//
//	LEVEL   TIMESTAMP [target] message key=value ...
type Handler struct {
	level   slog.Leveler
	w       io.Writer
	mu      *sync.Mutex
	color   bool
	attrs   []slog.Attr
	groups  []string
	target  string // extracted from attrs for special rendering
	noColor bool
}

// Options configures the Handler.
type Options struct {
	// Level is the minimum log level to emit.
	Level slog.Leveler
	// NoColor forces color off regardless of TTY detection.
	NoColor bool
}

// NewHandler creates a Handler that writes to w.
// Color is auto-detected when w is os.Stderr (or any *os.File with a terminal fd).
func NewHandler(w io.Writer, opts *Options) *Handler {
	h := &Handler{
		w:  w,
		mu: &sync.Mutex{},
	}
	if opts != nil {
		h.level = opts.Level
		h.noColor = opts.NoColor
	}
	if h.level == nil {
		h.level = slog.LevelInfo
	}
	if !h.noColor {
		h.color = colorEnabled(w)
	}
	return h
}

// Enabled reports whether the handler handles records at the given level.
func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

// Handle formats and writes a log record.
func (h *Handler) Handle(_ context.Context, r slog.Record) error {
	buf := make([]byte, 0, 256)

	// Level
	lvl := levelName(r.Level)
	if h.color {
		buf = append(buf, levelColor(r.Level)...)
	}
	buf = append(buf, lvl...)
	// Pad to 7 chars (length of "WARNING" / "VERBOSE")
	for i := len(lvl); i < 7; i++ {
		buf = append(buf, ' ')
	}
	if h.color {
		buf = append(buf, resetCode...)
	}
	buf = append(buf, ' ')

	// Timestamp in UTC
	ts := r.Time.UTC().Format(time.RFC3339)
	buf = append(buf, ts...)
	buf = append(buf, ' ')

	// Target (from pre-attached attrs or record attrs)
	target := h.target
	if target == "" {
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "target" {
				target = a.Value.String()
				return false
			}
			return true
		})
	}
	if target != "" {
		if h.color {
			buf = append(buf, targetColor(target)...)
		}
		buf = append(buf, '[')
		buf = append(buf, target...)
		buf = append(buf, ']')
		if h.color {
			buf = append(buf, resetCode...)
		}
		buf = append(buf, ' ')
	}

	// Message
	buf = append(buf, r.Message...)

	// Attrs (skip "target" since we rendered it specially)
	// First, pre-attached attrs from WithAttrs
	for _, a := range h.attrs {
		if a.Key == "target" {
			continue
		}
		buf = appendAttr(buf, a, h.color)
	}
	// Then record-level attrs
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "target" {
			return true
		}
		buf = appendAttr(buf, a, h.color)
		return true
	})

	buf = append(buf, '\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write(buf)
	return err
}

// WithAttrs returns a new Handler with the given attrs pre-attached.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newH := h.clone()
	for _, a := range attrs {
		if a.Key == "target" {
			newH.target = a.Value.String()
		} else {
			newH.attrs = append(newH.attrs, a)
		}
	}
	return newH
}

// WithGroup returns a new Handler with the given group name.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	newH := h.clone()
	newH.groups = append(newH.groups, name)
	return newH
}

func (h *Handler) clone() *Handler {
	return &Handler{
		level:   h.level,
		w:       h.w,
		mu:      h.mu, // share the mutex
		color:   h.color,
		noColor: h.noColor,
		attrs:   append([]slog.Attr(nil), h.attrs...),
		groups:  append([]string(nil), h.groups...),
		target:  h.target,
	}
}

func appendAttr(buf []byte, a slog.Attr, color bool) []byte {
	buf = append(buf, ' ')
	if color {
		buf = append(buf, dimCode...)
	}
	buf = append(buf, a.Key...)
	buf = append(buf, '=')
	if color {
		buf = append(buf, resetCode...)
	}
	buf = append(buf, a.Value.String()...)
	return buf
}

func levelName(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "ERROR"
	case l >= slog.LevelWarn:
		return "WARNING"
	case l >= slog.LevelInfo:
		return "INFO"
	case l >= LevelVerbose:
		return "VERBOSE"
	default:
		return "DEBUG"
	}
}

// ANSI escape codes
var (
	resetCode = []byte("\033[0m")
	dimCode   = []byte("\033[2m")

	colorError   = []byte("\033[31m") // red
	colorWarning = []byte("\033[33m") // yellow
	colorVerbose = []byte("\033[90m") // dim/gray
	colorDebug   = []byte("\033[35m") // magenta
)

func levelColor(l slog.Level) []byte {
	switch {
	case l >= slog.LevelError:
		return colorError
	case l >= slog.LevelWarn:
		return colorWarning
	case l >= slog.LevelInfo:
		return nil // white/default
	case l >= LevelVerbose:
		return colorVerbose
	default:
		return colorDebug
	}
}

// Target color palette (256-color) — avoids exact level colors: 31 (red), 33 (yellow), 35 (magenta), 90 (gray).
var targetPalette = [][]byte{
	// Reds / oranges (not \033[31m)
	[]byte("\033[38;5;124m"), // dark red
	[]byte("\033[38;5;131m"), // indian red
	[]byte("\033[38;5;167m"), // salmon
	[]byte("\033[38;5;173m"), // dark salmon
	[]byte("\033[38;5;203m"), // light coral
	[]byte("\033[38;5;208m"), // dark orange
	[]byte("\033[38;5;209m"), // light salmon
	// Yellows / golds (not \033[33m)
	[]byte("\033[38;5;136m"), // dark goldenrod
	[]byte("\033[38;5;143m"), // dark khaki
	[]byte("\033[38;5;179m"), // goldenrod
	[]byte("\033[38;5;186m"), // khaki
	[]byte("\033[38;5;222m"), // light goldenrod
	// Greens
	[]byte("\033[38;5;37m"),  // teal
	[]byte("\033[38;5;49m"),  // spring green
	[]byte("\033[38;5;77m"),  // pale green
	[]byte("\033[38;5;84m"),  // sea green
	[]byte("\033[38;5;114m"), // dark sea green
	[]byte("\033[38;5;120m"), // light green
	[]byte("\033[38;5;150m"), // dark olive green
	// Blues / cyans
	[]byte("\033[38;5;27m"),  // blue
	[]byte("\033[38;5;33m"),  // dodger blue
	[]byte("\033[38;5;39m"),  // deep sky blue
	[]byte("\033[38;5;51m"),  // cyan
	[]byte("\033[38;5;69m"),  // cornflower blue
	[]byte("\033[38;5;75m"),  // steel blue
	[]byte("\033[38;5;80m"),  // medium turquoise
	[]byte("\033[38;5;111m"), // sky blue
	[]byte("\033[38;5;117m"), // light blue
	// Purples / pinks
	[]byte("\033[38;5;63m"),  // slate blue
	[]byte("\033[38;5;105m"), // medium purple
	[]byte("\033[38;5;135m"), // medium orchid
	[]byte("\033[38;5;141m"), // medium purple
	[]byte("\033[38;5;147m"), // light slate blue
	[]byte("\033[38;5;176m"), // plum
	[]byte("\033[38;5;183m"), // orchid
	[]byte("\033[38;5;189m"), // lavender
}

func targetColor(target string) []byte {
	h := fnv.New32a()
	fmt.Fprint(h, target)
	return targetPalette[h.Sum32()%uint32(len(targetPalette))]
}
