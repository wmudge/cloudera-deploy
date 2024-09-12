# Copyright 2024 Cloudera, Inc.
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

terraform {
  required_version = ">= 0.13"
  required_providers {
    aws = {
      source  = "hashicorp/aws",
      version = ">= 4.60.0",
    }
    ansible = {
      source  = "ansible/ansible"
      version = ">= 1.0.0"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = var.asset_tags
  }
}

locals {
  # RedHat 8.6
  ami_user   = "ec2-user"
  ami_owners = ["309956199498"]
  ami_filters = {
    name         = ["RHEL-8.6*"]
    architecture = ["x86_64"]
  }
  vpc_name = var.vpc_name != "" ? var.vpc_name : "${var.prefix}-pvc-base"
  igw_name = var.igw_name != "" ? var.igw_name : "${var.prefix}-pvc-base-igw"
}

# ------- AMI -------

data "aws_ami" "pvc_base" {
  owners      = local.ami_owners
  most_recent = true

  dynamic "filter" {
    for_each = local.ami_filters

    content {
      name   = filter.key
      values = filter.value
    }
  }
}

# ------- SSH -------

data "local_file" "ssh_public_key_file" {
  filename = var.ssh_public_key_file
}

resource "aws_key_pair" "pvc_base" {
  key_name   = "${var.prefix}-pvc-base"
  public_key = data.local_file.ssh_public_key_file.content
}

# ------- VPC -------

resource "aws_vpc" "pvc_base" {
  cidr_block           = var.vpc_cidr
  tags                 = { Name = local.vpc_name }
  instance_tenancy     = "default"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_internet_gateway" "pvc_base" {
  vpc_id = aws_vpc.pvc_base.id
  tags   = { Name = local.igw_name }
}

# ------- Network  -------

module "cluster_network" {
  source = "../tf_network"

  region = var.region
  prefix = var.prefix
  vpc_id = aws_vpc.pvc_base.id
}

resource "aws_vpc_security_group_egress_rule" "pvc_base" {
  security_group_id = module.cluster_network.intra_cluster_security_group.id
  description       = "All traffic"
  ip_protocol       = -1
  cidr_ipv4         = "0.0.0.0/0"
  tags              = { Name = "${var.prefix}-pvc-base-intra" }
}

resource "aws_vpc_security_group_ingress_rule" "pvc_base" {
  security_group_id = module.cluster_network.intra_cluster_security_group.id
  description       = "Cluster ingress traffic"
  prefix_list_id    = aws_ec2_managed_prefix_list.pvc_base.id
  ip_protocol       = -1
  tags              = { Name = "${var.prefix}-pvc-base-intra" }
}

resource "aws_ec2_managed_prefix_list" "pvc_base" {
  name           = "${var.prefix}-pvc-base-intra"
  address_family = "IPv4"
  max_entries    = length(var.vpc_ingress_cidr)
}

resource "aws_ec2_managed_prefix_list_entry" "pvc_base" {
  for_each = { for idx, cidr in var.vpc_ingress_cidr : idx => cidr }

  prefix_list_id = aws_ec2_managed_prefix_list.pvc_base.id
  cidr           = each.value
  description    = "${var.prefix}-pvc-base-intra cluster ingress"
}


# ------- Cluster  -------

module "masters" {
  source     = "../tf_hosts"
  depends_on = [aws_key_pair.pvc_base, data.aws_ami.pvc_base]

  prefix          = var.prefix
  name            = "${var.prefix}-master"
  image_id        = data.aws_ami.pvc_base.image_id
  instance_type   = "m5.4xlarge"
  ssh_key_pair    = aws_key_pair.pvc_base.key_name
  subnet_ids      = module.cluster_network.public_subnets[*].id
  security_groups = [module.cluster_network.intra_cluster_security_group.id]
  public_ip       = true

  root_volume = {
    volume_size = 250
  }
}

module "workers" {
  source     = "../tf_hosts"
  depends_on = [aws_key_pair.pvc_base, data.aws_ami.pvc_base]

  prefix          = var.prefix
  name            = "${var.prefix}-worker"
  quantity        = 2
  image_id        = data.aws_ami.pvc_base.image_id
  instance_type   = "c5.2xlarge"
  ssh_key_pair    = aws_key_pair.pvc_base.key_name
  subnet_ids      = module.cluster_network.public_subnets[*].id
  security_groups = [module.cluster_network.intra_cluster_security_group.id]
  public_ip       = true

  root_volume = {
    volume_size = 250
  }
}

module "freeipa" {
  source     = "../tf_hosts"
  depends_on = [aws_key_pair.pvc_base, data.aws_ami.pvc_base]

  prefix        = var.prefix
  name          = "${var.prefix}-freeipa"
  image_id      = data.aws_ami.pvc_base.image_id
  instance_type = "m5.large" # TODO Look up via region
  ssh_key_pair  = aws_key_pair.pvc_base.key_name
  subnet_ids    = module.cluster_network.public_subnets[*].id
  security_groups = [
    module.cluster_network.intra_cluster_security_group.id,
    module.cluster_network.acme_tls_security_group.id
  ]
  public_ip = true
}

resource "aws_eip" "pvc-base" {
  for_each = { for idx, host in concat(module.masters.hosts, module.workers.hosts, module.freeipa.hosts) : idx => host }

  instance = each.value.id
  domain   = "vpc"
  tags     = { Name = each.value.tags.Name }
}



# ------- Ansible Inventory  -------

resource "ansible_group" "dnsmasq" {
  name = "dnsmasq"
}

resource "ansible_group" "freeipa" {
  name = "freeipa"
}

resource "ansible_group" "db" {
  name = "db_server"
}

resource "ansible_group" "cm" {
  name = "cloudera_manager"
}

resource "ansible_group" "workers" {
  name = "cluster_workers"
  variables = {
    host_template = "Workers"
  }
}

resource "ansible_group" "masters" {
  name = "cluster_masters"
  variables = {
    host_template = "Masters"
  }
}

resource "ansible_group" "cluster" {
  name = "cluster"
  children = [
    ansible_group.masters.name,
    ansible_group.workers.name
  ]
  variables = {
    tls = "True"
  }
}

resource "ansible_group" "deployment" {
  name = "deployment"
  children = [
    ansible_group.cluster.name,
    ansible_group.cm.name,
    ansible_group.db.name,
    ansible_group.freeipa.name
  ]
}

resource "ansible_host" "masters" {
  for_each = { for idx, host in module.masters.hosts : idx => host }

  name = format("%s.%s.%s", each.value.tags["Name"], replace(aws_eip.pvc-base[each.key].public_ip, ".", "-"), var.domain)

  groups = [
    ansible_group.masters.name,
    ansible_group.cm.name,
    ansible_group.db.name
  ]

  variables = {
    ansible_user = local.ami_user
  }
}

resource "ansible_host" "workers" {
  for_each = { for idx, host in module.workers.hosts : idx => host }

  name = format("%s.%s.%s", each.value.tags["Name"], replace(aws_eip.pvc-base[each.key + length(module.masters.hosts)].public_ip, ".", "-"), var.domain)

  groups = [
    ansible_group.workers.name
  ]

  variables = {
    ansible_user = local.ami_user
  }
}

resource "ansible_host" "freeipa" {
  for_each = { for idx, host in module.freeipa.hosts : idx => host }

  name = format("%s.%s.%s", each.value.tags["Name"], replace(aws_eip.pvc-base[each.key + length(module.masters.hosts) + length(module.workers.hosts)].public_ip, ".", "-"), var.domain)

  groups = [
    ansible_group.freeipa.name,
    ansible_group.dnsmasq.name
  ]

  variables = {
    ansible_user = local.ami_user
  }
}
