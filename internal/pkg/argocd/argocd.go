package argocd

import (
	"github.com/argoproj/argo-cd/pkg/apiclient"
)

func createArgoCdClient(token string) (*apiclient.Client, error) {
	opts := apiclient.ClientOptions{
		ServerAddr: "localhost:8080",
		Insecure:   true,
		AuthToken:  token,
	}

	clientset, err := apiclient.NewClient(opts)
	if err != nil {
		return nil, err
	}
	return &clientset, nil
}

func Play(token string) {
	client, err := createArgoCdClient(token)
	if err != nil {
		panic(err)
	}
	client.ListRepositories()
}
