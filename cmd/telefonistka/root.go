package telefonistka

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "telefonistka",
	Version: "0.0.0",
	Short:   "telefonistka - Safe and Controlled GitOps Promotion Across Environments/Failure-Domains",
	Long: `Telefonistka is a Github webhook server/CLI tool that facilitates change promotion across environments/failure domains in Infrastructure as Code GitOps repos

see https://github.com/commercetools/telefonistka`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

const (
	logTimestamp = "timestamp"
	logSeverity  = "severity"
	logMessage   = "message"
)

var logLevels = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
	"fatal": slog.LevelError,
	"panic": slog.LevelError,
}

func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	switch a.Key {
	case slog.TimeKey:
		return slog.Attr{Key: logTimestamp, Value: a.Value}
	case slog.LevelKey:
		return slog.Attr{Key: logSeverity, Value: a.Value}
	case slog.MessageKey:
		return slog.Attr{Key: logMessage, Value: a.Value}
	default:
		return a
	}
}

func Execute() {
	level := logLevels[getEnv("LOG_LEVEL", "info")]
	handlerOpts := slog.HandlerOptions{}
	handlerOpts.Level = level
	handlerOpts.ReplaceAttr = replaceAttr
	logHandler := slog.NewJSONHandler(os.Stderr, &handlerOpts)
	logger := slog.New(logHandler)
	slog.SetDefault(logger)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your CLI '%s'", err)
		os.Exit(1)
	}
}
