<#
.SYNOPSIS
    Start, stop, or check the self-hosted GitLab CI runner.

.DESCRIPTION
    The runner is an EC2 Windows instance that is stopped by default,
    because it bills by the hour while running and rMon's CI is bursty.
    Push, start it, let the pipeline run; it shuts itself down after about
    30 minutes with no build tools active.

    A pipeline queued while the runner is stopped does not fail -- it sits
    pending until the runner comes online and picks it up. So "start" can
    come before or after the push.

.EXAMPLE
    .\scripts\ci-runner.ps1 start
    .\scripts\ci-runner.ps1 status
    .\scripts\ci-runner.ps1 stop
    .\scripts\ci-runner.ps1 shell     # SSM session; there is no RDP
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('start', 'stop', 'status', 'shell', 'log')]
    [string]$Action,

    [string]$Region = 'eu-central-1',
    [string]$Name = 'rmon-ci-runner'
)

$ErrorActionPreference = 'Stop'

function Get-RunnerInstance {
    $id = aws ec2 describe-instances --region $Region `
        --filters "Name=tag:Name,Values=$Name" "Name=instance-state-name,Values=pending,running,stopping,stopped" `
        --query 'Reservations[].Instances[0].InstanceId' --output text
    if ($LASTEXITCODE -ne 0) { throw 'aws ec2 describe-instances failed' }
    if ([string]::IsNullOrWhiteSpace($id) -or $id -eq 'None') {
        throw "No instance tagged Name=$Name in $Region. Has infra/ been applied?"
    }
    # describe-instances returns tab-separated ids if several matched; the
    # filter above should make that impossible, but do not silently act on
    # the first of an unexpected set.
    $ids = $id -split '\s+' | Where-Object { $_ }
    if ($ids.Count -gt 1) { throw "Expected one runner, found $($ids.Count): $id" }
    $ids[0]
}

function Get-RunnerState($id) {
    aws ec2 describe-instances --region $Region --instance-ids $id `
        --query 'Reservations[0].Instances[0].State.Name' --output text
}

$instance = Get-RunnerInstance
$state = Get-RunnerState $instance

switch ($Action) {
    'status' {
        "runner : $Name"
        "id     : $instance"
        "region : $Region"
        "state  : $state"
        if ($state -eq 'running') {
            $since = aws ec2 describe-instances --region $Region --instance-ids $instance `
                --query 'Reservations[0].Instances[0].LaunchTime' --output text
            "up since: $since  (stops itself after ~30 min idle)"
        }
    }

    'start' {
        if ($state -eq 'running') { "already running ($instance)"; break }
        "starting $instance ..."
        aws ec2 start-instances --region $Region --instance-ids $instance | Out-Null
        aws ec2 wait instance-running --region $Region --instance-ids $instance
        # Running is not the same as ready: the runner service needs Windows
        # to finish booting before it polls GitLab for jobs.
        "instance running; the runner service typically registers within a minute or two"
    }

    'stop' {
        if ($state -eq 'stopped') { "already stopped ($instance)"; break }
        "stopping $instance ..."
        aws ec2 stop-instances --region $Region --instance-ids $instance | Out-Null
        aws ec2 wait instance-stopped --region $Region --instance-ids $instance
        'stopped'
    }

    'shell' {
        aws ssm start-session --region $Region --target $instance
    }

    'log' {
        aws ssm start-session --region $Region --target $instance `
            --document-name AWS-StartInteractiveCommand `
            --parameters "command='Get-Content C:\bootstrap.log -Tail 40 -Wait'"
    }
}
