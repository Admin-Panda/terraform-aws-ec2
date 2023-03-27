provider "aws" {
  region = "eu-west-1"
}

module "vpc" {
  source  = "git::git@github.com:Admin-Panda/terraform-aws-vpc"

  name        = "vpc"
  environment = "test"
  label_order = ["name", "environment"]

  cidr_block = "172.16.0.0/16"
}

module "public_subnets" {
  source  = "git::git@github.com:Admin-Panda/terrafrom-aws-subnet"

  name        = "public-subnet"
  environment = "test"
  label_order = ["name", "environment"]

  availability_zones = ["eu-west-1b", "eu-west-1c"]
  vpc_id             = module.vpc.vpc_id
  cidr_block         = module.vpc.vpc_cidr_block
  type               = "public"
  igw_id             = module.vpc.igw_id
  ipv6_cidr_block    = module.vpc.ipv6_cidr_block
}

module "http-https" {
  source      = "git::git@github.com:Admin-Panda/terraform-aws-security-group"
  name        = "http-https"
  environment = "test"
  label_order = ["name", "environment"]

  vpc_id        = module.vpc.vpc_id
  allowed_ip    = ["0.0.0.0/0"]
  allowed_ports = [80, 443]
}

module "keypair" {
  source  = "git::git@github.com:Admin-Panda/terraform-aws-keypair"

  public_key      = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDhd5utmOz+J4/lNL5sXGC6/m/QwKq8zYEY1/kgixZfi+Dy6Fvzez4SugvqwFq434dhZ7FuaW2zb5v/myY1BhdgnBG+x3ixypUV8djKzrcHvkdIV6z2DF6vVHYtLb9w9KDgvcpPu1Vs3GWC+ZMf0M7qVbGnxVe1zrnqM2Sw5JHvpH4jogcMVOlduMt1/snbl8Yu6OU0hv4UMKqA/LKW9uf9jkmbTbBvoZ0Fd7ZCf3/yDx9rdjSBDbK3eXiuckgns1wRxYDyEmjtyjSrHDfBs1JP5qZ5sYaERr8SYk7MICJZiIB91vjKxnPjAj484/QXbcLYgPhApLGmlAeMUuxrHt8LA7jNsXFCNBawOuBBqkNqWNHvk7N/EItdRAeuVt0sB5maCSgW/Ku9aLuu4JgXwIh6NKmxZ3qtb52aRApUQIny"
  key_name        = "devops"
  environment     = "test"
  label_order     = ["name", "environment"]
  enable_key_pair = true
}


module "ssh" {
  source      = "git::git@github.com:Admin-Panda/terraform-aws-security-group"
  name        = "ssh"
  environment = "test"
  label_order = ["name", "environment"]

  vpc_id        = module.vpc.vpc_id
  allowed_ip    = [module.vpc.vpc_cidr_block, "0.0.0.0/0"]
  allowed_ports = [22]
}

module "iam-role" {
  source  = "git::git@github.com:Admin-Panda/terraform-aws-iam-role.git"

  name               = "iam-role"
  environment        = "test"
  label_order        = ["name", "environment"]
  assume_role_policy = data.aws_iam_policy_document.default.json

  policy_enabled = true
  policy         = data.aws_iam_policy_document.iam-policy.json
}

module "kms_key" {
  source                  = "git::git@github.com:Admin-Panda/terraform-aws-kms.git"
  name                    = "kms"
  environment             = "test"
  label_order             = ["environment", "name"]
  enabled                 = true
  description             = "KMS key for ec2"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  alias                   = "alias/ec3"
  policy                  = data.aws_iam_policy_document.kms.json
}


data "aws_iam_policy_document" "kms" {
  version = "2012-10-17"
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

}

data "aws_iam_policy_document" "default" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "iam-policy" {
  statement {
    actions = [
      "ssm:UpdateInstanceInformation",
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
    "ssmmessages:OpenDataChannel"]
    effect    = "Allow"
    resources = ["*"]
  }
}

module "ec2" {
  source      = "./../"
  name        = "ec2"
  environment = "test"
  label_order = ["name", "environment"]

  #instance
  instance_enabled = true
  instance_count   = 1
  ami              = "ami-08d658f84a6d84a80"
  instance_type    = "t2.nano"
  monitoring       = false
  tenancy          = "default"
  hibernation      = false

  #Networking
  vpc_security_group_ids_list = [module.ssh.security_group_ids, module.http-https.security_group_ids]
  subnet_ids                  = tolist(module.public_subnets.public_subnet_id)
  assign_eip_address          = true
  associate_public_ip_address = true

  #Keypair
  key_name = module.keypair.name

  #IAM
  instance_profile_enabled = true
  iam_instance_profile     = module.iam-role.name

  #Root Volume
  root_block_device = [
    {
      volume_type           = "gp3"
      volume_size           = 15
      delete_on_termination = true
      kms_key_id            = module.kms_key.key_arn
    }
  ]

  #EBS Volume
  multi_attach_enabled = true
  ebs_optimized      = false
  ebs_volume_enabled = true
  ebs_volume_type    = "gp3"
  ebs_volume_size    = 30

  #DNS
  dns_enabled = false
  dns_zone_id = "Z1XJD7SSBKXLC1"
  hostname    = "ec2"

  #Tags
  instance_tags = { "snapshot" = true }

  # Metadata
  metadata_http_tokens_required        = "optional"
  metadata_http_endpoint_enabled       = "enabled"
  metadata_http_put_response_hop_limit = 2

}
