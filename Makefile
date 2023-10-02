SHELL := /bin/bash
.ONESHELL:

TAG = $$(git rev-parse --short HEAD)
IMG ?= ghcr.io/xenitab/acr-proxy:$(TAG)
TEST_ENV_FILE = .tmp/env

ifneq (,$(wildcard $(TEST_ENV_FILE)))
    include $(TEST_ENV_FILE)
    export
endif

.PHONY: all
all: fmt vet lint test

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: build
build:
	CGO_ENABLED=0  go build -installsuffix 'static' -o bin/acr-proxy ./src/main.go

.PHONY: docker-build
docker-build:
	docker build . -t $(IMG)

.PHONY: test
test: fmt vet
	go test --cover ./...

.PHONY: cover
cover:
	mkdir -p .tmp
	go test -timeout 5m -coverpkg=./src/... -coverprofile=.tmp/coverage.out ./src/...
	go tool cover -html=.tmp/coverage.out

.PHONY: terraform-up
terraform-up:
	cd terraform
	terraform init
	terraform apply -auto-approve -var-file="../.tmp/lab.tfvars"

.PHONY: terraform-up-customerapptest
terraform-up-customerapptest:
	cd test/client-app
	terraform init
	terraform apply -auto-approve -var-file="../../.tmp/customerapptest.tfvars"

.PHONY: terraform-down-customerapptest
terraform-down-customerapptest:
	cd test/client-app
	terraform init
	terraform destroy -auto-approve -var-file="../../.tmp/customerapptest.tfvars"

.PHONY: run
run:
	go run ./... \
		--allowed-tenant-ids $${ALLOWED_TENANTS} \
		--azure-container-registry-name $${REGISTRY_NAME} \
		--azure-container-registry-user $${REGISTRY_USER} \
		--azure-container-registry-password $${REGISTRY_PASSWORD}
