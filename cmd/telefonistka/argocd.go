package telefonistka

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wayfair-incubator/telefonistka/internal/pkg/argocd"
)

// @Title
// @Description
// @Author
// @Update

// This is still(https://github.com/spf13/cobra/issues/1862) the documented way to use cobra

func init() { //nolint:gochecknoinits
	eventCmd := &cobra.Command{
		Use: "arogcd",
		// Short: "Handles a GitHub event based on event JSON file",
		// Long:  "Handles a GitHub event based on event JSON file.\nThis operation mode was was built with GitHub Actions in mind",
		Args: cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			playWithArgo()
		},
	}
	rootCmd.AddCommand(eventCmd)
}

func playWithArgo() {
	token := getCrucialEnv("ARGOCD_TOKEN")
	argocd.Play(token)

}

func getCrucialEnv(key string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	log.Fatalf("%s environment variable is required", key)
	os.Exit(3)
	return ""
}
