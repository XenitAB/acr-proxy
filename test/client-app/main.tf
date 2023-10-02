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

data "azurerm_container_app_environment" "this" {
  name                = var.azurerm_container_app_environment_name
  resource_group_name = var.resource_group_name
}

resource "azurerm_container_app" "this" {
  name                         = "customer-test-app"
  container_app_environment_id = data.azurerm_container_app_environment.this.id
  resource_group_name          = var.resource_group_name
  revision_mode                = "Single"

  identity {
    type = "SystemAssigned"
  }

  template {
    min_replicas = 1
    max_replicas = 1

    container {
      name   = "customer-test-container"
      image  = "${var.acr_proxy_fqdn}/${var.image}"
      cpu    = 0.25
      memory = "0.5Gi"
    }
  }

  registry {
    server   = var.acr_proxy_fqdn
    identity = "System"
  }
}
