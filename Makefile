IMG ?= ghcr.io/laldershaab/kube-token-exchanger:latest

.PHONY: generate
generate:
	go run sigs.k8s.io/controller-tools/cmd/controller-gen \
		object paths="./api/..." \
		crd:crdVersions=v1 output:crd:artifacts:config=config/crd/bases \
		rbac:roleName=kube-token-exchanger output:rbac:artifacts:config=config/rbac \
		paths="./..."

.PHONY: build
build:
	go build -o bin/operator ./cmd/operator

.PHONY: test
test:
	go test ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: manifests
manifests:
	kubectl kustomize config

.PHONY: run
run:
	go run ./cmd/operator --leader-elect

.PHONY: docker-build
docker-build:
	docker build -t $(IMG) .
