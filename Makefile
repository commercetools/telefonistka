#
# Makefile
#
# Simple makefile to build binary.
#
# @author Kubernetes Team <k8s_team@wayfair.com>
# @copyright 2019 Wayfair, LLC. -- All rights reserved.

VENDOR_DIR = vendor

.PHONY: get-deps
get-deps: $(VENDOR_DIR)

$(VENDOR_DIR):
	go generate $$(go list ./internal/pkg/mocks/...)
	GO111MODULE=on go mod vendor

.PHONY: build
build: $(VENDOR_DIR)
	GOOS=linux CGO_ENABLED=0 go build -ldflags '-extldflags "-static"' -o telefonistka .

.PHONY: clean
clean:
	rm -f telefonistka

.PHONY: test
test: $(VENDOR_DIR)
	TEMPLATES_PATH=../../../templates/ go test -v -timeout 30s ./...

.PHONY: dev-local-cluster
dev-local-cluster:
	@kind get clusters | grep telefonistka-dev || kind create cluster --config dev-local/cluster-config-telefonistka-dev.yaml
	@kind get clusters | grep local-test-cluster || kind create cluster --config dev-local/cluster-config-local-test-cluster.yaml
	@kubectl config use-context kind-telefonistka-dev
	@kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml && \
	kubectl wait --timeout=2m --for=condition=Ready pod -l app.kubernetes.io/name=ingress-nginx \
		-l app.kubernetes.io/component=controller -n ingress-nginx

.PHONY: dev-local-argocd
dev-local-argocd:
	kubectl create namespace argocd || true
	kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
	kubectl apply -f dev-local/manifests/argocd-configmap.yaml
	kubectl apply -f dev-local/manifests/argocd-ingress.yaml
	kubectl apply -f dev-local/manifests/argocd-applicationSet.yaml
	kubectl -n argocd patch secret argocd-secret --patch-file dev-local/manifests/argocd-password-patch.yaml
	kubectl config set-context --current --namespace=argocd
	argocd cluster add kind-local-test-cluster --yes || true
	kubectl -n argocd patch secret argocd-secret --patch-file dev-local/manifests/argocd-cluster-url-patch.yaml

	

export GITHUB_TOKEN:=$(shell gh auth token)
.PHONY: dev-local-telefonistka
dev-local-telefonistka:
	kubectl config use-context kind-telefonistka-dev
	kubectl create namespace telefonistka-dev || true
	kubectl config set-context --current --namespace=argocd
	kubectl get secret argocd-token -n telefonistka-dev || kubectl create secret generic argocd-token \
		-n telefonistka-dev \
		--from-literal=ARGOCD_TOKEN=$$(argocd account generate-token --account telefonistka)
	@kubectl get secret github-token -n telefonistka-dev || kubectl create secret generic github-token \
		-n telefonistka-dev \
		--from-literal=GITHUB_OAUTH_TOKEN=$(GITHUB_TOKEN) \
		--from-literal=APPROVER_GITHUB_OAUTH_TOKEN=$(GITHUB_TOKEN)
	find dev-local/manifests -maxdepth 1 -iname "telefonistka*" -exec kubectl apply -f {} \;

		

GH_REPO=commercetools/telefonistka-dev-$(shell whoami)
.PHONY: dev-local-gh
dev-local-gh:
	cd dev-local/telefonistka-dev-repo && \
	[ -d .git ] || (git init && \
	git add -A && \
	git commit -m "Initial commit")
	(gh repo view $(GH_REPO) > /dev/null) || (cd dev-local/telefonistka-dev-repo && \
	gh repo create $(GH_REPO) --internal --source=. --push)
	kubectl config use-context kind-telefonistka-dev
	kubectl config set-context kind-telefonistka-dev --namespace=argocd 
	@argocd repo add https://github.com/$(GH_REPO) --username telefonistka-dev --password $(GITHUB_TOKEN)
	gh webhook forward --repo=$(GH_REPO) \
	--events='*' \
	--url=http://localhost:8080/telefonistka/webhook \
	--secret=""

dev-local: dev-local-cluster dev-local-argocd dev-local-telefonistka dev-local-deploy dev-local-gh
	@echo "🤖 You're good to go partner!"

.PHONY: dev-local-clean
dev-local-clean:
	kind delete cluster --name telefonistka-dev
	kind delete cluster --name local-test-cluster
	unset GH_TOKEN; unset GITHUB_TOKEN; gh repo delete $(GH_REPO) --yes
	cd dev-local/telefonistka-dev-repo && \
	rm -rf .git

.PHONY: dev-local-deploy
dev-local-deploy:
	docker build -t telefonistka-dev-local:latest .
	kind load docker-image telefonistka-dev-local:latest --name telefonistka-dev
	kubectl config use-context kind-telefonistka-dev
	kubectl delete -f dev-local/manifests/telefonistka-pod.yaml
	kubectl apply -f dev-local/manifests/telefonistka-pod.yaml

.PHONY: dev-local-undeploy
	