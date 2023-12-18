variable "location" {
  description = "The location for the platform"
  type        = string
}

variable "location_short" {
  description = "The location shortname for the platform"
  type        = string
}

variable "environment" {
  description = "The environment name to use for the platform"
  type        = string
}

variable "name" {
  description = "The name to use for the platform"
  type        = string
}

variable "unique_suffix" {
  description = "Unique suffix that is used in globally unique resources names"
  type        = string
}

variable "allowed_tenant_ids" {
  description = "A list of the allowed tenants"
  type        = list(string)
}

variable "acr_proxy_image" {
  description = "The version of acr-proxy to use"
  type        = string
  default     = "ghcr.io/xenitab/acr-proxy"
}

variable "acr_proxy_version" {
  description = "The version of acr-proxy to use"
  type        = string
}

variable "network" {
  description = "The network configuration"
  type = object({
    virtual_network_address_space = string
    subnet_address_prefix         = string
  })
  default = {
    virtual_network_address_space = "10.0.0.0/16"
    subnet_address_prefix         = "10.0.0.0/20"
  }
}
