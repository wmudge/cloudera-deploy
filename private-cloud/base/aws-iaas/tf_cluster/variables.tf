# Copyright 2023 Cloudera, Inc.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# ------- General and Provider Resources -------

variable "ssh_public_key_file" {
  type        = string
  description = "Local SSH public key file"
}

variable "prefix" {
  type        = string
  description = "Deployment prefix for all cloud-provider assets"

  validation {
    condition     = length(var.prefix) < 8 || length(var.prefix) > 4
    error_message = "Valid length for prefix is between 4-7 characters."
  }
}

variable "region" {
  type        = string
  description = "AWS region"
}

variable "asset_tags" {
  type        = map(string)
  default     = {}
  description = "Map of tags applied to all cloud-provider assets"
}

# ------- Network Resources -------

variable "vpc_name" {
  type        = string
  description = "VPC name"
  default     = ""
}

# TODO Convert to list of CIDR blocks
variable "vpc_cidr" {
  type        = string
  description = "VPC CIDR Block (primary)"
  default     = "10.10.0.0/16"
}

variable "igw_name" {
  type        = string
  description = "Internet Gateway name"
  default     = ""
}

variable "public_domain" {
  type        = string
  description = "Domain for public hosts"
  default     = "pvc.cloudera-labs.com"
}

variable "vpc_ingress_cidr" {
  type        = list(string)
  description = "List of CIDR to limit ingress for SSH and Knox Proxy"
}

variable "private_domain" {
  type        = string
  description = "Domain for private hosts"
  default     = "cldr.internal"
}

variable "ssh_security_group_name" {
  type = string
  description = "Security Group name for SSH"
  default = ""
}

variable "knox_gateway_security_group_name" {
  type        = string
  description = "Security Group name for the Knox Gateway"
  default     = ""
}

variable "knox_gateway_port" {
  type        = number
  description = "Knox Gateway HTTPS port"
  default     = 8443
}

variable "freeipa_ui_security_group_name" {
  type        = string
  description = "Security Group name for the FreeIPA UI"
  default     = ""
}

variable "freeipa_ui_port" {
  type        = number
  description = "FreeIPA UI HTTPS port"
  default     = 443
}

variable "http_proxy_security_group_name" {
  type = string
  description = "Security Group name for the HTTP Proxy"
  default = ""
}

variable "http_proxy_port" {
  type = number
  description = "HTTP Proxy port"
  default = 8899
}
