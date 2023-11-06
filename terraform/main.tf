terraform {
  required_providers {
    azurerm = {
      version = "3.75.0"
      source  = "hashicorp/azurerm"
    }
  }
}

provider "azurerm" {
  features {}
}

locals {
  eln = join("-", [var.environment, var.location_short, var.name])
}

resource "azurerm_resource_group" "this" {
  name     = "rg-${local.eln}"
  location = var.location
}

resource "azurerm_log_analytics_workspace" "this" {
  name                = "log-${local.eln}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

resource "azurerm_virtual_network" "this" {
  name                = "vnet-${local.eln}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = [var.network.virtual_network_address_space]
}

resource "azurerm_subnet" "this" {
  name                 = "snet-${local.eln}-ca"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.network.subnet_address_prefix]
}

resource "azurerm_container_app_environment" "this" {
  name                           = "me-${local.eln}"
  location                       = azurerm_resource_group.this.location
  resource_group_name            = azurerm_resource_group.this.name
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.this.id
  infrastructure_subnet_id       = azurerm_subnet.this.id
  internal_load_balancer_enabled = false
}

resource "azurerm_container_registry" "this" {
  name                = "cr${replace(local.eln, "-", "")}${var.unique_suffix}"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  sku                 = "Standard"
  admin_enabled       = true
}

resource "random_password" "acr_proxy_static_secret" {
  length  = 32
  special = false
}

resource "azurerm_container_app" "this" {
  name                         = "acr-proxy"
  container_app_environment_id = azurerm_container_app_environment.this.id
  resource_group_name          = azurerm_resource_group.this.name
  revision_mode                = "Single"

  template {
    min_replicas = 0
    max_replicas = 1

    http_scale_rule {
      name                = "scale-to-zero"
      concurrent_requests = 1
    }

    container {
      name   = "acr-proxy"
      image  = "${var.acr_proxy_image}:${var.acr_proxy_version}"
      cpu    = 0.25
      memory = "0.5Gi"

      args = concat(["--allowed-tenant-ids"], var.allowed_tenant_ids, [
        "--azure-container-registry-name",
        azurerm_container_registry.this.name,
        "--azure-container-registry-user",
        azurerm_container_registry.this.admin_username,
      ])

      liveness_probe {
        port      = 8080
        path      = "/healthz"
        transport = "HTTP"
      }

      readiness_probe {
        port      = 8080
        path      = "/healthz"
        transport = "HTTP"
      }

      startup_probe {
        port      = 8080
        path      = "/healthz"
        transport = "HTTP"
      }

      env {
        name        = "AZURE_CONTAINER_REGISTRY_PASSWORD"
        secret_name = "container-registry-password"
      }

      env {
        name        = "STATIC_SECRET"
        secret_name = "static-secret"
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8080
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  secret {
    name  = "container-registry-password"
    value = azurerm_container_registry.this.admin_password
  }

  secret {
    name  = "static-secret"
    value = random_password.acr_proxy_static_secret.result
  }

  registry {
    server               = azurerm_container_registry.this.login_server
    password_secret_name = "container-registry-password"
    username             = azurerm_container_registry.this.admin_username
  }
}
