output "instance_id" {
  description = "Instance id, which is what scripts/ci-runner.ps1 acts on."
  value       = aws_instance.runner.id
}

output "region" {
  value = var.region
}

output "start_command" {
  description = "Bring the runner up before pushing."
  value       = "aws ec2 start-instances --region ${var.region} --instance-ids ${aws_instance.runner.id}"
}

output "stop_command" {
  description = "Stop it early. The instance also stops itself after ~30 minutes idle."
  value       = "aws ec2 stop-instances --region ${var.region} --instance-ids ${aws_instance.runner.id}"
}

output "session_command" {
  description = "Administrative shell. There is no RDP or SSH -- the security group has no inbound rules."
  value       = "aws ssm start-session --region ${var.region} --target ${aws_instance.runner.id}"
}

output "bootstrap_progress" {
  description = "First boot takes 30-45 minutes, most of it Visual Studio Build Tools. Tail this to watch it."
  value       = "aws ssm start-session --region ${var.region} --target ${aws_instance.runner.id} --document-name AWS-StartInteractiveCommand --parameters command='Get-Content C:\\bootstrap.log -Wait'"
}
