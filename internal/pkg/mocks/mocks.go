package mocks

// This package contains generated mocks

//  mockgen -package=mocks -destination authenticator.go k8s.io/apiserver/pkg/authentication/authenticator Token
//  mockgen -source=../../../vendor/github.com/argoproj/argo-cd/v2/pkg/apiclient/application/application.pb.go -destination=mock_argocd_application.go -package=mocks
//go:generate go run github.com/golang/mock/mockgen@v1.6.0 -destination=argocd_application.go -package=mocks github.com/argoproj/argo-cd/v2/pkg/apiclient/application ApplicationServiceClient
