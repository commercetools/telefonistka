package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/wayfair-incubator/telefonistka/internal/logging"
)

var version string

var rootCmd = &cobra.Command{
	Use:     "telefonistka",
	Version: version,
	Short:   "telefonistka - Safe and Controlled GitOps Promotion Across Environments/Failure-Domains",
	Long: `Telefonistka is a Github webhook server/CLI tool that facilitates change promotion across environments/failure domains in Infrastructure as Code GitOps repos

see https://github.com/wayfair-incubator/telefonistka`,
}

func main() {
	logging.ConfigureLogging()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your CLI '%s'", err)
		os.Exit(1)
	}
}
