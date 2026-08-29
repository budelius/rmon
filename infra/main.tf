# A self-hosted GitLab CI runner for rMon, on EC2.
#
# Why this exists: GitLab.com's free tier ran out of compute minutes, and
# rMon cannot fall back to a Linux runner -- rmon-core calls Win32, WMI and
# NVML with no cfg(target_os) gates anywhere, so it only compiles on
# Windows. That makes Hetzner Cloud a non-starter too (it has no Windows
# images at all), which leaves EC2.
#
# Shape: one persistent instance, stopped by default, that starts when you
# need a pipeline and stops itself when the build tools go quiet. See
# infra/README.md for the cost reasoning behind that rather than an
# always-on box or a per-job autoscaler.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# Newest Microsoft-published Windows Server 2022 image. Resolved at plan
# time rather than pinned: the instance is long-lived and only ever built
# from this once, so tracking the current patch level costs nothing and
# starts the box on a supported image.
data "aws_ami" "windows" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }
  filter {
    name   = "state"
    values = ["available"]
  }
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# --- the runner token -------------------------------------------------------
# Held as a SecureString and read by the instance at boot. Passing it through
# user-data instead would publish it to anyone with
# ec2:DescribeInstanceAttribute, and it is a credential that can register
# CI runners against the project.
resource "aws_ssm_parameter" "runner_token" {
  name        = var.ssm_token_parameter
  description = "GitLab runner authentication token for the rMon CI runner"
  type        = "SecureString"
  value       = var.gitlab_runner_token

  tags = local.tags
}

# --- identity ---------------------------------------------------------------
resource "aws_iam_role" "runner" {
  name = "${var.name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = local.tags
}

# Session Manager is the only administrative access path. It is what lets
# the security group below have no inbound rules at all: no RDP, no SSH,
# nothing listening for the internet to find.
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.runner.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Read access to exactly one parameter -- not ssm:GetParameter on "*".
resource "aws_iam_role_policy" "read_token" {
  name = "${var.name}-read-token"
  role = aws_iam_role.runner.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ssm:GetParameter"]
      Resource = aws_ssm_parameter.runner_token.arn
    }]
  })
}

resource "aws_iam_instance_profile" "runner" {
  name = "${var.name}-profile"
  role = aws_iam_role.runner.name
  tags = local.tags
}

# --- network ----------------------------------------------------------------
# Egress only. The runner polls GitLab outbound and needs to reach crates.io,
# GitHub and Microsoft's download hosts; nothing ever needs to reach in.
resource "aws_security_group" "runner" {
  name        = "${var.name}-sg"
  description = "rMon CI runner: outbound only, administered via SSM"
  vpc_id      = data.aws_vpc.default.id

  egress {
    description = "All outbound (GitLab, crates.io, GitHub, Microsoft)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${var.name}-sg" })
}

# --- the instance -----------------------------------------------------------
resource "aws_instance" "runner" {
  ami                    = data.aws_ami.windows.id
  instance_type          = var.instance_type
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.runner.id]
  iam_instance_profile   = aws_iam_instance_profile.runner.name

  # The idle task shuts down from inside the guest. "stop" makes that halt
  # billing instead of destroying the instance -- and it means nothing on the
  # box needs ec2:StopInstances to do it.
  instance_initiated_shutdown_behavior = "stop"

  user_data = templatefile("${path.module}/bootstrap.ps1", {
    region              = var.region
    gitlab_url          = var.gitlab_url
    runner_name         = var.name
    ssm_token_parameter = var.ssm_token_parameter
  })

  root_block_device {
    volume_size = var.disk_gb
    volume_type = "gp3"
    encrypted   = true
    # Survives stop/start, which is the whole point: the warm cargo registry
    # and target/ directory are what make this runner fast.
    delete_on_termination = true
  }

  metadata_options {
    http_tokens   = "required" # IMDSv2 only
    http_endpoint = "enabled"
  }

  tags = merge(local.tags, { Name = var.name })

  lifecycle {
    # Editing the bootstrap script must not silently destroy a runner that
    # has a warm cache and a registered token. Re-provision deliberately.
    ignore_changes = [user_data, ami]
  }
}

locals {
  tags = {
    Project   = "rMon"
    Component = "ci-runner"
    ManagedBy = "terraform"
  }
}
