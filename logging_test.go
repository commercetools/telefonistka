package main

import (
	"testing"

	"sigs.k8s.io/kind/pkg/log"
)

func helmLogFunc(t *testing.T) func(format string, values ...interface{}) {
	t.Helper()
	return func(format string, v ...interface{}) {
		t.Helper()
		t.Logf(format, v...)
	}
}

// testLogger implements a logger to use when running kind in a test.
type testLogger struct{ *testing.T }

// Write implements io.Writer and logs the data using the test instance.
func (t testLogger) Write(b []byte) (int, error) {
	t.Helper()
	t.Log(string(b))
	return len(b), nil
}

// Warn implements log.Logger and logs the message using the test instance.
func (t testLogger) Warn(message string) {
	t.Helper()
	t.Log(message)
}

// Warnf implements log.Logger and logs the message using the test instance.
func (t testLogger) Warnf(format string, args ...interface{}) {
	t.Helper()
	t.Logf(format, args...)
}

// Error implements log.Logger and logs the message using the test instance.
func (t testLogger) Error(message string) {
	t.Helper()
	t.Log(message)
}

// Errorf implements log.Logger and logs the message using the test instance.
func (t testLogger) Errorf(format string, args ...interface{}) {
	t.Helper()
	if t.T != nil {
		t.T.Errorf(format, args...)
	}
}

// V implements log.Logger and returns an InfoLogger for the specified verbosity level.
func (t testLogger) V(log.Level) log.InfoLogger { return &t }

// Info implements log.InfoLogger and logs the message using the test instance.
func (t testLogger) Info(message string) {
	t.Helper()
	t.Log(message)
}

// Infof implements log.InfoLogger and logs the message using the test instance.
func (t testLogger) Infof(format string, args ...interface{}) {
	t.Helper()
	t.Logf(format, args...)
}

// Enabled implements log.InfoLogger and always return true.
func (t testLogger) Enabled() bool { return true }

// ioLogger implements io.Writer and logs written bytes using t.Logf.
// Unlike testLogger, which is designed for structured logging in tests,
// ioLogger is focused on handling raw byte streams.
type ioLogger struct {
	*testing.T
}

// Implements io.Writer but logs written bytes to t.Logf.
func (t ioLogger) Write(b []byte) (int, error) {
	t.Helper()
	t.Log(string(b))
	return len(b), nil
}
