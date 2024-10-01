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
	GOOS=linux CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' -o telefonistka .

.PHONY: clean
clean:
	rm -f telefonistka

.PHONY: test
test: $(VENDOR_DIR)
	TEMPLATES_PATH=../../../templates/ go test -v -timeout 30s ./...

.PHONY: dev-local-cluster
dev-local-cluster:
	@kind get clusters | grep telefonistka-dev || kind create cluster --config dev-local/cluster-config.yaml
	@kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml && \
	kubectl wait --timeout=2m --for=condition=Ready pod -l app.kubernetes.io/name=ingress-nginx \
		-l app.kubernetes.io/component=controller -n ingress-nginx 

.PHONY: dev-local-argocd
dev-local-argocd:
	kubectl create namespace argocd || true
	kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
	kubectl apply -f dev-local/manifests/argocd-configmap.yaml
	kubectl apply -f dev-local/manifests/argocd-ingress.yaml
	kubectl -n argocd patch secret argocd-secret --patch-file dev-local/manifests/argocd-password-patch.yaml

export GITHUB_TOKEN:=$(shell gh auth token)
.PHONY: dev-local-telefonistka
dev-local-telefonistka:
	kubectl create namespace telefonistka-dev || true
	find dev-local/manifests -maxdepth 1 -iname "telefonistka*" -exec kubectl apply -f {} \;
	kubectl config set-context --current --namespace=argocd
	kubectl create secret generic argocd-token \
		-n telefonistka-dev \
		--from-literal=ARGOCD_TOKEN=$$(argocd account generate-token --account telefonistka)
	@kubectl create secret generic github-token \
		-n telefonistka-dev \
		--from-literal=GITHUB_OAUTH_TOKEN=$(GITHUB_TOKEN) \
		--from-literal=APPROVER_GITHUB_OAUTH_TOKEN=$(GITHUB_TOKEN) \
		

GH_REPO=commercetools/telefonistka-dev
.PHONY: dev-local-gh
dev-local-gh:
	cd dev-local/telefonistka-dev-repo && \
	git init && \
	git add -A && \
	git commit -m "Initial commit" && \
	gh repo create $(GH_REPO) --internal --source=. --push
	gh webhook forward --repo=commercetools/telefonistka-dev \
	--events='*' \
	--url=http://localhost/telefonistka/webhook \
	--secret=""

dev-local: dev-local-cluster dev-local-argocd dev-local-telefonistka dev-local-deploy dev-local-gh
	@echo "🤖 You're good to go partner!"

.PHONY: dev-local-clean
dev-local-clean:
	kind delete cluster --name telefonistka-dev
	unset GH_TOKEN; unset GITHUB_TOKEN; gh repo delete $(GH_REPO) --yes
	cd dev-local/telefonistka-dev-repo && \
	rm -rf .git

.PHONY: dev-local-deploy
dev-local-deploy:
	docker build -t telefonistka-dev-local:latest .
	kind load docker-image telefonistka-dev-local:latest --name telefonistka-dev
	kubectl apply -f dev-local/manifests/telefonistka-pod.yaml

.PHONY: dev-local-undeploy
	