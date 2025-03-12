package mocks

// This package contains generated mocks

//go:generate go run go.uber.org/mock/mockgen@v0.5.0 -destination=argocd_application.go -package=mocks github.com/argoproj/argo-cd/v3/pkg/apiclient/application ApplicationServiceClient

//go:generate go run go.uber.org/mock/mockgen@v0.5.0 -destination=argocd_settings.go -package=mocks github.com/argoproj/argo-cd/v3/pkg/apiclient/settings SettingsServiceClient

//go:generate go run go.uber.org/mock/mockgen@v0.5.0 -destination=argocd_project.go -package=mocks github.com/argoproj/argo-cd/v3/pkg/apiclient/project ProjectServiceClient
