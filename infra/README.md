# Self-hosted CI runner

GitLab.com's free tier ran out of compute minutes and both jobs started
failing with `ci_quota_exceeded`. This provisions our own runner instead.

## Why EC2 and not Hetzner

rMon only compiles on Windows. `rmon-core` calls Win32, WMI and NVML with
**no `cfg(target_os)` gates anywhere**, so there is no Linux build to fall
back to — the runner has to be Windows.

Hetzner Cloud has no Windows images at all. Windows there means a dedicated
root server plus a purchased licence and a monthly commitment, which is a
poor shape for bursty CI. EC2 publishes Windows Server AMIs with the licence
included in the hourly rate, and the account already has working credentials
and an `eu-central-1` profile.

## Why one persistent instance, stopped by default

A bare Windows AMI has no MSVC linker. Installing Visual Studio Build Tools
takes 30–45 minutes, which is why this is **not** a per-job autoscaler: every
pipeline would pay that before compiling a line. A persistent instance pays
it once.

Persistence is also where the speed comes from. The SaaS runner rebuilt
every dependency from scratch on every pipeline — that is most of why `build`
took ~45 minutes and `installer` over two hours. Here the cargo registry and
`target/` survive between jobs on the root volume.

The instance bills by the hour while running, so it stops itself once
`cargo`/`rustc`/`link` have been quiet for ~30 minutes. Starting is explicit.
A pipeline queued while it is stopped waits as `pending` rather than failing,
so the order of push and start does not matter.

## Cost

Indicative on-demand rates for `c5.2xlarge` Windows in eu-central-1 — the
account has no `pricing:` API access, so **confirm these against the AWS
console** rather than trusting the figures here:

| state | rough cost |
|---|---|
| running | ~$0.75/hour (Windows licence is roughly half of that; EC2 bills it per vCPU) |
| stopped | ~$10/month for the 120 GB gp3 root volume |
| a pipeline with a warm cache | a few minutes, so well under a dollar |

Always-on would be ~$550/month, which is the reason for the idle stop. If
pipelines become frequent enough that the stop/start dance is annoying,
the next step is a scheduled start during working hours rather than 24/7.

## First run

1. Create a **project runner** in GitLab: Settings → CI/CD → Runners → New
   project runner. Give it the tag `rmon-windows` (this must match
   `.gitlab-ci.yml`). Copy the `glrt-…` authentication token.

2. Put the token somewhere Terraform can read it, but **not** in git:

   ```powershell
   $env:TF_VAR_gitlab_runner_token = 'glrt-...'
   ```

3. Apply:

   ```powershell
   cd infra
   terraform init
   terraform plan      # read this before applying; it creates billable resources
   terraform apply
   ```

4. Watch the first boot. It is slow and it is worth confirming it finished,
   because a half-provisioned box fails jobs with a confusing "link.exe not
   found" rather than an obvious error:

   ```powershell
   ..\scripts\ci-runner.ps1 log      # tails C:\bootstrap.log
   ```

   The last line should be `bootstrap complete`.

## Day to day

```powershell
.\scripts\ci-runner.ps1 start     # before (or after) pushing
.\scripts\ci-runner.ps1 status
.\scripts\ci-runner.ps1 stop      # optional; it stops itself when idle
.\scripts\ci-runner.ps1 shell     # administrative session
```

## Access

The security group has **no inbound rules** — no RDP, no SSH, nothing
listening for the internet to find. Administration is via SSM Session
Manager, which is outbound-only from the instance, so `ci-runner.ps1 shell`
is the way in.

The runner token is stored as an SSM `SecureString` and read at boot through
the instance role, which can read that one parameter and nothing else. It is
deliberately kept out of user-data, which is readable by anyone holding
`ec2:DescribeInstanceAttribute`.

## Tearing it down

```powershell
cd infra
terraform destroy
```

Also delete the runner in GitLab's UI; `destroy` removes the instance and
the token parameter, but GitLab keeps the (now dead) runner registration.
