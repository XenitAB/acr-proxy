variable "azurerm_container_app_environment_name" {
  type        = string
  description = "The Container App Environment name."
}

variable "resource_group_name" {
  type        = string
  description = "The Resource Group name."
}

variable "acr_proxy_fqdn" {
  type        = string
  description = "The acr-proxy FQDN. Do not include https://."
}

variable "image" {
  type        = string
  description = "The image that should be pulled through acr-proxy. Should not contain the acr-proxy fqdn."
}
