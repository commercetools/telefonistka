package gh

import (
	"io"
	"log/slog"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Silence default slog output during tests.  Individual tests
	// that need logging can call slog.SetDefault with their own handler.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}
