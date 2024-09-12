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
  vpc_name             = var.vpc_name != "" ? var.vpc_name : "${var.prefix}-pvc-base"
  igw_name             = var.igw_name != "" ? var.igw_name : "${var.prefix}-pvc-base-igw"

  sg_ssh_name   = var.ssh_security_group_name != "" ? var.ssh_security_group_name : "${var.prefix}-pvc-base-ssh"
  sg_knox_gateway_name = var.knox_gateway_security_group_name != "" ? var.knox_gateway_security_group_name : "${var.prefix}-pvc-base-knox-gateway"
  sg_freeipa_ui_name   = var.freeipa_ui_security_group_name != "" ? var.freeipa_ui_security_group_name : "${var.prefix}-pvc-base-freeipa-ui"
  sg_http_proxy_name = var.http_proxy_security_group_name != "" ? var.http_proxy_security_group_name : "${var.prefix}-pvc-base-http-proxy"
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

# ------- Cluster Network and Prefix List -------

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
  tags              = { Name = "${var.prefix}-pvc-base" }
}

resource "aws_ec2_managed_prefix_list" "pvc_base" {
  name           = "${var.prefix}-pvc-base-ingress"
  address_family = "IPv4"
  max_entries    = length(var.vpc_ingress_cidr)
}

resource "aws_ec2_managed_prefix_list_entry" "pvc_base" {
  for_each = { for idx, cidr in var.vpc_ingress_cidr : idx => cidr }

  prefix_list_id = aws_ec2_managed_prefix_list.pvc_base.id
  cidr           = each.value
  description    = "${var.prefix}-pvc-base-ingress"
}

resource "aws_security_group" "ssh" {
  vpc_id      = aws_vpc.pvc_base.id
  name        = local.sg_ssh_name
  description = "SSH traffic [${var.prefix}]"
  tags        = { Name = local.sg_ssh_name }
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.ssh.id
  description       = "SSH traffic"
  prefix_list_id    = aws_ec2_managed_prefix_list.pvc_base.id
  from_port         = 22
  ip_protocol       = "tcp"
  to_port           = 22
  tags              = { Name = "${var.prefix}-pvc-base-ssh" }
}

# ------- Cluster, Bastion, and Service instances and networking -------

resource "aws_security_group" "http_proxy" {
  vpc_id      = aws_vpc.pvc_base.id
  name        = local.sg_http_proxy_name
  description = "HTTP Proxy traffic [${var.prefix}]"
  tags        = { Name = local.sg_http_proxy_name }
}

resource "aws_vpc_security_group_ingress_rule" "http_proxy" {
  security_group_id = aws_security_group.http_proxy.id
  description       = "HTTP Proxy traffic"
  prefix_list_id    = aws_ec2_managed_prefix_list.pvc_base.id
  from_port         = var.http_proxy_port
  ip_protocol       = "tcp"
  to_port           = var.http_proxy_port
  tags              = { Name = "${var.prefix}-pvc-base-http-proxy" }
}

module "bastion" {
  source     = "../tf_hosts"
  depends_on = [aws_key_pair.pvc_base, data.aws_ami.pvc_base]

  prefix        = var.prefix
  name          = "${var.prefix}-bastion"
  image_id      = data.aws_ami.pvc_base.image_id # Should use a free-tier Linux
  instance_type = "t2.micro"
  subnet_ids    = module.cluster_network.public_subnets[*].id # Will use the first public subnet
  ssh_key_pair  = aws_key_pair.pvc_base.key_name
  security_groups = [
    module.cluster_network.intra_cluster_security_group.id,
    aws_security_group.ssh.id,
    aws_security_group.http_proxy.id
  ]
  public_ip = true
}

module "proxy" {
  source     = "../tf_hosts"
  depends_on = [aws_key_pair.pvc_base, data.aws_ami.pvc_base]

  prefix        = var.prefix
  name          = "${var.prefix}-proxy"
  image_id      = data.aws_ami.pvc_base.image_id
  instance_type = "t3.medium"
  subnet_ids    = module.cluster_network.public_subnets[*].id # Will use the first public subnet
  ssh_key_pair  = aws_key_pair.pvc_base.key_name
  security_groups = [
    module.cluster_network.intra_cluster_security_group.id,
    module.cluster_network.acme_tls_security_group.id,
    aws_security_group.ssh.id,
    aws_security_group.knox_gateway.id
  ]
  public_ip = true
}

resource "aws_security_group" "knox_gateway" {
  vpc_id      = aws_vpc.pvc_base.id
  name        = local.sg_knox_gateway_name
  description = "ACME Directory challenge traffic [${var.prefix}]"
  tags        = { Name = local.sg_knox_gateway_name }
}

resource "aws_vpc_security_group_ingress_rule" "knox_gateway" {
  security_group_id = aws_security_group.knox_gateway.id
  description       = "Knox Gateway traffic"
  prefix_list_id    = aws_ec2_managed_prefix_list.pvc_base.id
  from_port         = var.knox_gateway_port
  ip_protocol       = "tcp"
  to_port           = var.knox_gateway_port
  tags              = { Name = "${var.prefix}-pvc-base-knox-gateway" }
}

module "masters" {
  source     = "../tf_hosts"
  depends_on = [aws_key_pair.pvc_base, data.aws_ami.pvc_base]

  prefix          = var.prefix
  name            = "${var.prefix}-master"
  image_id        = data.aws_ami.pvc_base.image_id
  instance_type   = "m6i.2xlarge"
  ssh_key_pair    = aws_key_pair.pvc_base.key_name
  subnet_ids      = module.cluster_network.private_subnets[*].id # Will use the first subnet
  security_groups = [module.cluster_network.intra_cluster_security_group.id]
  public_ip       = false

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
  instance_type   = "m6i.large"
  ssh_key_pair    = aws_key_pair.pvc_base.key_name
  subnet_ids      = module.cluster_network.private_subnets[*].id
  security_groups = [module.cluster_network.intra_cluster_security_group.id]
  public_ip       = false

  root_volume = {
    volume_size = 250
  }
}

module "workers_free" {
  source     = "../tf_hosts"
  depends_on = [aws_key_pair.pvc_base, data.aws_ami.pvc_base]

  prefix          = var.prefix
  name            = "${var.prefix}-worker-free"
  quantity        = 3
  image_id        = data.aws_ami.pvc_base.image_id
  instance_type   = "m6i.large"
  ssh_key_pair    = aws_key_pair.pvc_base.key_name
  subnet_ids      = module.cluster_network.private_subnets[*].id
  security_groups = [module.cluster_network.intra_cluster_security_group.id]
  public_ip       = false

  root_volume = {
    volume_size = 250
  }
}

module "services" {
  source     = "../tf_hosts"
  depends_on = [aws_key_pair.pvc_base, data.aws_ami.pvc_base]

  prefix        = var.prefix
  name          = "${var.prefix}-services"
  image_id      = data.aws_ami.pvc_base.image_id
  instance_type = "m6i.large" # TODO Look up via region
  ssh_key_pair  = aws_key_pair.pvc_base.key_name
  subnet_ids    = module.cluster_network.public_subnets[*].id
  security_groups = [
    module.cluster_network.intra_cluster_security_group.id,
    module.cluster_network.acme_tls_security_group.id,
    aws_security_group.freeipa_ui.id,
    aws_security_group.ssh.id
  ]
  public_ip = true
}

resource "aws_security_group" "freeipa_ui" {
  vpc_id      = aws_vpc.pvc_base.id
  name        = local.sg_freeipa_ui_name
  description = "FreeIPA UI traffic [${var.prefix}]"
  tags        = { Name = local.sg_freeipa_ui_name }
}

resource "aws_vpc_security_group_ingress_rule" "freeipa_ui" {
  security_group_id = aws_security_group.freeipa_ui.id
  description       = "FreeIPA UI traffic"
  prefix_list_id    = aws_ec2_managed_prefix_list.pvc_base.id
  from_port         = var.freeipa_ui_port
  ip_protocol       = "tcp"
  to_port           = var.freeipa_ui_port
  tags              = { Name = "${var.prefix}-pvc-base-freeipa-ui" }
}

resource "aws_eip" "pvc-base" {
  for_each = { for idx, host in concat(module.services.hosts, module.proxy.hosts) : idx => host }

  instance = each.value.id
  domain   = "vpc"
  tags     = { Name = each.value.tags.Name }
}

# ------- Ansible Inventory  -------

resource "ansible_group" "bastion" {
  name = "jump_host"
}

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

resource "ansible_group" "workers_free" {
  name = "cluster_workers_free"
}

resource "ansible_group" "masters" {
  name = "cluster_masters"
  variables = {
    host_template = "Masters"
  }
}

resource "ansible_group" "knox_gateway" {
  name = "knox_gateway"
  variables = {
    host_template = "Gateway"
  }
}

resource "ansible_group" "proxied_servers" {
  name = "proxied_servers"
  children = [
    ansible_group.masters.name,
    ansible_group.workers.name,
    ansible_group.workers_free.name,
    ansible_group.cm.name
  ]
  variables = {
    ansible_ssh_common_args = "-o ProxyCommand='ssh -i {{ lookup('ansible.builtin.env', 'SSH_PRIVATE_KEY_FILE') }} -o User=${local.ami_user} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -W %h:%p -q ${module.bastion.hosts[0].public_ip}'"
  }
}

resource "ansible_group" "cluster" {
  name = "cluster"
  children = [
    ansible_group.masters.name,
    ansible_group.workers.name,
    ansible_group.workers_free.name,
    ansible_group.knox_gateway.name
  ]
  variables = {
    tls = "True"
  }
}

resource "ansible_group" "deployment" {
  name = "deployment"
  children = [
    ansible_group.cluster.name,
    ansible_group.cm.name
  ]
}

resource "ansible_host" "masters" {
  for_each = { for idx, host in module.masters.hosts : idx => host }

  name = format("%s.%s", each.value.tags["Name"], var.private_domain)

  groups = [
    ansible_group.masters.name,
    ansible_group.cm.name
  ]

  variables = {
    ansible_host = each.value.private_ip
    ansible_user = local.ami_user
  }
}

resource "ansible_host" "workers" {
  for_each = { for idx, host in module.workers.hosts : idx => host }

  name = format("%s.%s", each.value.tags["Name"], var.private_domain)

  groups = [
    ansible_group.workers.name
  ]

  variables = {
    ansible_host = each.value.private_ip
    ansible_user = local.ami_user
  }
}

resource "ansible_host" "workers_free" {
  for_each = { for idx, host in module.workers_free.hosts : idx => host }

  name = format("%s.%s", each.value.tags["Name"], var.private_domain)

  groups = [
    ansible_group.workers_free.name
  ]

  variables = {
    ansible_host = each.value.private_ip
    ansible_user = local.ami_user
  }
}

resource "ansible_host" "services" {
  for_each = { for idx, host in module.services.hosts : idx => host }

  # Replace the IP regex if using a non-"magic" DNS resolver
  name = format("%s.%s.%s", each.value.tags["Name"], replace(aws_eip.pvc-base[each.key].public_ip, ".", "-"), var.public_domain)

  groups = [
    ansible_group.freeipa.name
  ]

  variables = {
    ansible_host = aws_eip.pvc-base[each.key].public_ip
    ansible_user = local.ami_user
  }
}

resource "ansible_host" "proxy" {
  for_each = { for idx, host in module.proxy.hosts : idx => host }

  # Replace the IP regex if using a non-"magic" DNS resolver
  name = format("%s.%s.%s", each.value.tags["Name"], replace(aws_eip.pvc-base[each.key + length(module.services.hosts)].public_ip, ".", "-"), var.public_domain)

  groups = [
    ansible_group.knox_gateway.name,
    ansible_group.db.name
  ]

  variables = {
    ansible_host = aws_eip.pvc-base[each.key + length(module.services.hosts)].public_ip
    ansible_user = local.ami_user
  }
}

resource "ansible_host" "bastion" {
  for_each = { for idx, host in module.bastion.hosts : idx => host }

  name = format("%s.%s", each.value.tags["Name"], var.private_domain)

  groups = [
    ansible_group.bastion.name,
    ansible_group.dnsmasq.name
  ]

  variables = {
    ansible_host = each.value.public_ip
    ansible_user = local.ami_user
  }
}
