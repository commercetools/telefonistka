package telefonistka

import (
	"os"
	"strconv"

	"github.com/argoproj/argo-cd/v2/pkg/apiclient"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/spf13/cobra"
	"github.com/wayfair-incubator/telefonistka/internal/pkg/githubapi"
)

// This is still(https://github.com/spf13/cobra/issues/1862) the documented way to use cobra
func init() { //nolint:gochecknoinits
	var eventType string
	var eventFilePath string
	eventCmd := &cobra.Command{
		Use:   "event",
		Short: "Handles a GitHub event based on event JSON file",
		Long:  "Handles a GitHub event based on event JSON file.\nThis operation mode was was built with GitHub Actions in mind",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			event(eventType, eventFilePath)
		},
	}
	eventCmd.Flags().StringVarP(&eventType, "type", "t", getEnv("GITHUB_EVENT_NAME", ""), "Event type, defaults to GITHUB_EVENT_NAME env var")
	eventCmd.Flags().StringVarP(&eventFilePath, "file", "f", getEnv("GITHUB_EVENT_PATH", ""), "File path for event JSON, defaults to GITHUB_EVENT_PATH env var")
	rootCmd.AddCommand(eventCmd)
}

func event(eventType string, eventFilePath string) {
	mainGhClientCache, _ := lru.New[string, githubapi.GhClientPair](128)
	prApproverGhClientCache, _ := lru.New[string, githubapi.GhClientPair](128)
	plaintext, _ := strconv.ParseBool(getEnv("ARGOCD_PLAINTEXT", "false"))
	insecure, _ := strconv.ParseBool(getEnv("ARGOCD_INSECURE", "false"))
	serverAddr := getEnv("ARGOCD_SERVER_ADDR", "localhost:8080")
	token := getEnv("ARGOCD_TOKEN", "")
	argoOpts := apiclient.ClientOptions{
		ServerAddr: serverAddr,
		AuthToken:  token,
		PlainText:  plaintext,
		Insecure:   insecure,
	}
	githubapi.ReciveEventFile(eventFilePath, eventType, mainGhClientCache, prApproverGhClientCache, &argoOpts)
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
