terraform {
  required_providers {
    cdp = {
      source  = "cloudera/cdp"
      version = "0.1.4-pre"
    }
  }

  required_version = ">= 0.13"
}

provider "aws" {
  region = var.aws_region
}

# Use the CDP Terraform Provider to find the xaccount account and external ids
data "cdp_environments_aws_credential_prerequisites" "cdp_prereqs" {}

# Create the AWS pre-requisite resources for CDP using the terraform-cdp-aws-pre-reqs module
module "cdp_aws_prereqs" {
  source = "git::https://github.com/cloudera-labs/terraform-cdp-modules.git//modules/terraform-cdp-aws-pre-reqs?ref=v0.2.0"

  env_prefix = var.env_prefix
  aws_region = var.aws_region

  deployment_template           = var.deployment_template
  ingress_extra_cidrs_and_ports = var.ingress_extra_cidrs_and_ports

  # Using CDP TF Provider cred pre-reqs data source for values of xaccount account_id and external_id
  xaccount_account_id  = data.cdp_environments_aws_credential_prerequisites.cdp_prereqs.account_id
  xaccount_external_id = data.cdp_environments_aws_credential_prerequisites.cdp_prereqs.external_id


}