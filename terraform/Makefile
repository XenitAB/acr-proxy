.ONESHELL:
SHELL:=/bin/bash

ifndef ENV
$(error Need to set ENV)
endif
DIR=unbox
DEPLOYMENT_TF_VARS = $(DIR)/variables/$(ENV).tfvars

UNIQUE_SUFFIX := $(shell grep -i -w unique_suffix $(DEPLOYMENT_TF_VARS) | awk -F'=' '{print $$2}' | tr -d '"' | tr -d '[:blank:]')
ifndef UNIQUE_SUFFIX
$(error Need to set unique_suffix terraform variable inside of $(DIR)/variables/$(ENV).tfvars)
endif

COMMON_NAME := $(shell grep -i -w name $(DEPLOYMENT_TF_VARS) | awk -F'=' '{print $$2}' | tr -d '"' | tr -d '[:blank:]')
ifndef COMMON_NAME
$(error Need to set common_name terraform variable inside of $(DIR)/variables/$(ENV).tfvars)
endif

CURRENT_SUBSCRIPTION_ID := $(shell az account show --query id --output tsv)
REQUIRED_SUBSCRIPTION_ID := $(shell grep -i -w subscription_id $(DEPLOYMENT_TF_VARS) | awk -F'=' '{print $$2}' | tr -d '"' | tr -d '[:blank:]')
ifndef REQUIRED_SUBSCRIPTION_ID
$(error Need to set subscription_id terraform variable inside of $(DIR)/variables/$(ENV).tfvars)
endif
ifneq ($(CURRENT_SUBSCRIPTION_ID),$(REQUIRED_SUBSCRIPTION_ID))
$(error Need to set Azure CLI to use the subscription id $(REQUIRED_SUBSCRIPTION_ID) defined by $(DIR)/variables/$(ENV).tfvars. The current is: $(CURRENT_SUBSCRIPTION_ID))
endif

SUFFIX="tfstate$(UNIQUE_SUFFIX)"
IMAGE="ghcr.io/xenitab/github-actions/tools:2023.12.1"

# User mapping compat when using podman as alias for docker (with Debian update-alternatives or Red Hat alternatives)
export PODMAN_USERNS=keep-id

OPA_BLAST_RADIUS := $(if $(OPA_BLAST_RADIUS),$(OPA_BLAST_RADIUS),50)
RG_LOCATION_SHORT:=we
RG_LOCATION_LONG:=swedencentral
AZURE_CONFIG_DIR := $(if $(AZURE_CONFIG_DIR),$(AZURE_CONFIG_DIR),"$${HOME}/.azure")
TTY_OPTIONS=$(shell [ -t 0 ] && echo '-it')
TEMP_ENV_FILE:=$(shell mktemp)
TEMP_SHELL_RC_FILE:=$(shell mktemp)

AZURE_DIR_MOUNT:=-v $(AZURE_CONFIG_DIR):/work/.azure
DOCKER_ENTRYPOINT:=/opt/terraform.sh
DOCKER_OPTS:=--user $(shell id -u) $(TTY_OPTIONS) --rm --env-file $(TEMP_ENV_FILE)
DOCKER_MOUNTS:=-v "$${PWD}/$(DIR)":"/tmp/$(DIR)" -v "$${PWD}/global.tfvars":"/tmp/global.tfvars"
DOCKER_RUN:=docker run $(DOCKER_OPTS) --entrypoint $(DOCKER_ENTRYPOINT) $(AZURE_DIR_MOUNT) $(DOCKER_MOUNTS) $(IMAGE)
DOCKER_SHELL:=docker run $(DOCKER_OPTS) --entrypoint /bin/bash $(AZURE_DIR_MOUNT) $(DOCKER_MOUNTS) -v "$(TEMP_SHELL_RC_FILE)":"/work/.bashrc" $(IMAGE)
CLEANUP_COMMAND:=$(MAKE) --no-print-directory teardown TEMP_ENV_FILE=$(TEMP_ENV_FILE) TEMP_SHELL_RC_FILE=$(TEMP_SHELL_RC_FILE)

.PHONY: setup
.SILENT: setup
setup:
	set -e

	mkdir -p $(AZURE_CONFIG_DIR)
	export AZURE_CONFIG_DIR="$(AZURE_CONFIG_DIR)"

	echo BACKEND_KEY=$(DIR)$(ENV).terraform.tfstate >> $(TEMP_ENV_FILE)
	echo BACKEND_RG=rg-$(ENV)-$(RG_LOCATION_SHORT)-$(COMMON_NAME) >> $(TEMP_ENV_FILE)
	echo BACKEND_KV=kv-$(ENV)-$(RG_LOCATION_SHORT)-$(COMMON_NAME)-$(UNIQUE_SUFFIX) >> $(TEMP_ENV_FILE)
	echo BACKEND_KV_KEY=sops >> $(TEMP_ENV_FILE)
	echo BACKEND_NAME=tf$(ENV)$(RG_LOCATION_SHORT)$(COMMON_NAME)$(UNIQUE_SUFFIX) >> $(TEMP_ENV_FILE)
	echo CONTAINER_NAME=tfstate-$(DIR) >> $(TEMP_ENV_FILE)
	echo AZURE_RESOURCE_LOCKS=false >> $(TEMP_ENV_FILE)

	if [ -n "$${servicePrincipalId}" ]; then
		echo ARM_CLIENT_ID=$${servicePrincipalId} >> $(TEMP_ENV_FILE)
		echo ARM_CLIENT_SECRET=$${servicePrincipalKey} >> $(TEMP_ENV_FILE)
		echo ARM_TENANT_ID=$${tenantId} >> $(TEMP_ENV_FILE)
	fi

	echo ARM_SUBSCRIPTION_ID=$$(az account show -o tsv --query 'id') >> $(TEMP_ENV_FILE)

	echo RG_LOCATION_SHORT=$(RG_LOCATION_SHORT) >> $(TEMP_ENV_FILE)
	echo RG_LOCATION_LONG=$(RG_LOCATION_LONG) >> $(TEMP_ENV_FILE)

.PHONY: teardown
.SILENT: teardown
teardown:
	-rm -f $(TEMP_ENV_FILE)

.PHONY: prepare
prepare: setup
	trap '$(CLEANUP_COMMAND)' EXIT
	$(DOCKER_RUN) prepare $(DIR) $(ENV) $(SUFFIX)

.PHONY: plan
plan: setup
	trap '$(CLEANUP_COMMAND)' EXIT
	$(DOCKER_RUN) plan $(DIR) $(ENV) $(SUFFIX) $(OPA_BLAST_RADIUS)

.PHONY: apply
apply: setup
	trap '$(CLEANUP_COMMAND)' EXIT
	$(DOCKER_RUN) apply $(DIR) $(ENV) $(SUFFIX)

.PHONY: destroy
destroy: setup
	trap '$(CLEANUP_COMMAND)' EXIT
	$(DOCKER_RUN) destroy $(DIR) $(ENV) $(SUFFIX)

.PHONY: state-remove
state-remove: setup
	trap '$(CLEANUP_COMMAND)' EXIT
	$(DOCKER_RUN) state-remove $(DIR) $(ENV) $(SUFFIX)

.PHONY: validate
validate: setup
	trap '$(CLEANUP_COMMAND)' EXIT
	$(DOCKER_RUN) validate $(DIR) $(ENV) $(SUFFIX)

.PHONY: shell
shell: setup
	trap '$(CLEANUP_COMMAND)' EXIT
	cat << EOF > $(TEMP_SHELL_RC_FILE)
	cd /tmp/$(DIR)
	/opt/terraform.sh init $(DIR) $(ENV) $(SUFFIX)
	EOF
	$(DOCKER_SHELL)
