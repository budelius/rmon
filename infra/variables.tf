variable "region" {
  description = "AWS region for the runner. Frankfurt by default: nearest to where rMon is developed, and the account already has an eu-central-1 profile."
  type        = string
  default     = "eu-central-1"
}

variable "name" {
  description = "Name for the instance and its supporting resources. Also the runner's display name in GitLab."
  type        = string
  default     = "rmon-ci-runner"
}

variable "instance_type" {
  description = <<-EOT
    8 vCPU / 16 GB. Sized for the link step rather than the compile: rMon
    builds under `[profile.release] lto = true`, so the fat LTO link over
    wgpu/eframe is single-threaded and wants fast cores, while the rest of
    the build parallelises. Going wider mostly buys Windows licence cost,
    which EC2 bills per vCPU.
  EOT
  type        = string
  default     = "c5.2xlarge"
}

variable "disk_gb" {
  description = <<-EOT
    Root volume size. Windows plus VS Build Tools is roughly 40 GB before
    anything is compiled; the rest is the cargo registry and a release
    target/ directory with debug info, which together run to several GB per
    profile. This is the one cost incurred while the instance is stopped.
  EOT
  type        = number
  default     = 120
}

variable "gitlab_url" {
  description = "GitLab instance the runner registers against."
  type        = string
  default     = "https://gitlab.com/"
}

variable "gitlab_runner_token" {
  description = <<-EOT
    Runner authentication token (starts with `glrt-`), created under
    Settings -> CI/CD -> Runners -> New project runner, with the tag
    matching `.gitlab-ci.yml`. Never commit this: pass it with
    `-var-file=secrets.auto.tfvars` (gitignored) or TF_VAR_gitlab_runner_token.
  EOT
  type        = string
  sensitive   = true
}

variable "ssm_token_parameter" {
  description = "SSM Parameter Store path holding the runner token, read by the instance at boot through its instance role."
  type        = string
  default     = "/rmon/ci/gitlab-runner-token"
}
