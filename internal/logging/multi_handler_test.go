package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestMultiHandler_Handle(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	h1 := NewHandler(&buf1, &Options{Level: slog.LevelInfo, NoColor: true})
	h2 := NewHandler(&buf2, &Options{Level: slog.LevelInfo, NoColor: true})
	multi := NewMultiHandler(h1, h2)
	log := slog.New(multi)

	log.Info("test message", "key", "value")

	if !strings.Contains(buf1.String(), "test message") {
		t.Errorf("handler 1 missing message, got: %s", buf1.String())
	}
	if !strings.Contains(buf2.String(), "test message") {
		t.Errorf("handler 2 missing message, got: %s", buf2.String())
	}
	if !strings.Contains(buf1.String(), "key=value") {
		t.Errorf("handler 1 missing attr, got: %s", buf1.String())
	}
	if !strings.Contains(buf2.String(), "key=value") {
		t.Errorf("handler 2 missing attr, got: %s", buf2.String())
	}
}

func TestMultiHandler_Enabled(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	h1 := NewHandler(&buf1, &Options{Level: slog.LevelError, NoColor: true})
	h2 := NewHandler(&buf2, &Options{Level: slog.LevelDebug, NoColor: true})
	multi := NewMultiHandler(h1, h2)

	// Should be enabled at Debug because h2 accepts it
	if !multi.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("expected Enabled=true at Debug level (h2 accepts it)")
	}

	// Debug message should only appear in buf2
	log := slog.New(multi)
	log.Debug("debug only")

	if strings.Contains(buf1.String(), "debug only") {
		t.Error("handler 1 should not have debug message")
	}
	if !strings.Contains(buf2.String(), "debug only") {
		t.Error("handler 2 should have debug message")
	}
}

func TestMultiHandler_WithAttrs(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	h1 := NewHandler(&buf1, &Options{Level: slog.LevelInfo, NoColor: true})
	h2 := NewHandler(&buf2, &Options{Level: slog.LevelInfo, NoColor: true})
	multi := NewMultiHandler(h1, h2)
	log := slog.New(multi).With("target", "server1:1433")

	log.Info("connected")

	// Target should be rendered in brackets by both handlers
	if !strings.Contains(buf1.String(), "[server1:1433]") {
		t.Errorf("handler 1 missing target, got: %s", buf1.String())
	}
	if !strings.Contains(buf2.String(), "[server1:1433]") {
		t.Errorf("handler 2 missing target, got: %s", buf2.String())
	}
}

func TestMultiHandler_WithGroup(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	h1 := NewHandler(&buf1, &Options{Level: slog.LevelInfo, NoColor: true})
	h2 := NewHandler(&buf2, &Options{Level: slog.LevelInfo, NoColor: true})
	multi := NewMultiHandler(h1, h2)

	grouped := multi.WithGroup("mygroup")
	if grouped == nil {
		t.Fatal("WithGroup returned nil")
	}

	// Empty group should return same handler
	same := multi.WithGroup("")
	if same != multi {
		t.Error("WithGroup(\"\") should return the same handler")
	}
}
