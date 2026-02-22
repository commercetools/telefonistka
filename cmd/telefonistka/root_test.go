package main

import (
	"log/slog"
	"testing"
)

func TestReplaceAttr(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		input   slog.Attr
		wantKey string
	}{
		"time key": {
			input:   slog.Attr{Key: slog.TimeKey, Value: slog.StringValue("now")},
			wantKey: "timestamp",
		},
		"level key": {
			input:   slog.Attr{Key: slog.LevelKey, Value: slog.StringValue("INFO")},
			wantKey: "severity",
		},
		"message key": {
			input:   slog.Attr{Key: slog.MessageKey, Value: slog.StringValue("hello")},
			wantKey: "message",
		},
		"unknown key": {
			input:   slog.Attr{Key: "custom", Value: slog.StringValue("val")},
			wantKey: "custom",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := replaceAttr(nil, tc.input)
			if got.Key != tc.wantKey {
				t.Errorf("replaceAttr() key = %q, want %q", got.Key, tc.wantKey)
			}
			if got.Value.String() != tc.input.Value.String() {
				t.Errorf("replaceAttr() value = %v, want %v", got.Value, tc.input.Value)
			}
		})
	}
}

func TestGetEnv(t *testing.T) {
	t.Run("env set", func(t *testing.T) {
		t.Setenv("TEST_GETENV_SET", "val")
		if got := getEnv("TEST_GETENV_SET", "fallback"); got != "val" {
			t.Errorf("getEnv() = %q, want %q", got, "val")
		}
	})
	t.Run("env unset", func(t *testing.T) {
		if got := getEnv("TEST_GETENV_UNSET", "fallback"); got != "fallback" {
			t.Errorf("getEnv() = %q, want %q", got, "fallback")
		}
	})
}
