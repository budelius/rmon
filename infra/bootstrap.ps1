<powershell>
# First-boot provisioning for the rMon GitLab CI runner.
#
# Runs once, on a fresh Windows Server 2022 instance, and takes roughly
# 30-45 minutes -- almost all of it Visual Studio Build Tools. That cost is
# why this runner is a persistent instance rather than one spawned per job:
# a bare Windows AMI has no MSVC linker, so a per-job instance would pay
# this before every pipeline.
#
# Everything here is idempotent enough to re-run by hand over SSM if a step
# fails; each step short-circuits when its artifact already exists.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is ~10x faster without it

$Log = 'C:\bootstrap.log'
function Step($msg) {
    $line = "[{0:yyyy-MM-dd HH:mm:ss}] {1}" -f (Get-Date), $msg
    Write-Output $line
    Add-Content -Path $Log -Value $line -Encoding utf8
}

Step 'bootstrap starting'

# --- TLS ------------------------------------------------------------------
# Server 2022 defaults are fine, but pin it: several of the downloads below
# reject anything below 1.2 and the failure mode is an opaque reset.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Tools = 'C:\tools'
New-Item -ItemType Directory -Force -Path $Tools | Out-Null

# --- Visual Studio Build Tools -------------------------------------------
# The MSVC linker. rustup's stable-x86_64-pc-windows-msvc toolchain cannot
# link a single binary without this, and the error it gives ("link.exe not
# found") is the single most common way this box comes up broken.
if (-not (Test-Path 'C:\BuildTools\VC\Tools\MSVC')) {
    Step 'installing Visual Studio Build Tools (this is the slow one)'
    $vs = "$Tools\vs_buildtools.exe"
    Invoke-WebRequest -Uri 'https://aka.ms/vs/17/release/vs_buildtools.exe' -OutFile $vs
    # --wait --quiet --norestart: unattended. The VCTools workload pulls the
    # compiler/linker; the Windows SDK supplies the import libraries the
    # windows crate links against.
    $p = Start-Process -FilePath $vs -Wait -PassThru -ArgumentList @(
        '--quiet', '--wait', '--norestart', '--nocache',
        '--installPath', 'C:\BuildTools',
        '--add', 'Microsoft.VisualStudio.Workload.VCTools',
        '--add', 'Microsoft.VisualStudio.Component.Windows11SDK.22621',
        '--includeRecommended'
    )
    # 3010 is "success, reboot required" and is normal here.
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
        throw "VS Build Tools installer exited $($p.ExitCode)"
    }
    Step "VS Build Tools done (exit $($p.ExitCode))"
} else {
    Step 'VS Build Tools already present, skipping'
}

# --- Rust -----------------------------------------------------------------
$CargoBin = "$env:USERPROFILE\.cargo\bin"
if (-not (Test-Path "$CargoBin\cargo.exe")) {
    Step 'installing rustup + stable-msvc'
    $rustup = "$Tools\rustup-init.exe"
    Invoke-WebRequest -Uri 'https://win.rustup.rs/x86_64' -OutFile $rustup
    & $rustup -y --default-toolchain stable-x86_64-pc-windows-msvc --profile minimal --component clippy rustfmt
    if ($LASTEXITCODE -ne 0) { throw "rustup-init exited $LASTEXITCODE" }
} else {
    Step 'rust already present, skipping'
}
$env:Path = "$CargoBin;$env:Path"

# --- WiX 3.11 -------------------------------------------------------------
# Portable rather than the chocolatey package: cargo-wix only needs candle
# and light on disk plus the WIX variable, and a zip has no installer to
# fail unattended. Layout must be <WIX>\bin\candle.exe -- cargo-wix appends
# the bin segment itself.
$WixHome = "$Tools\wix"
if (-not (Test-Path "$WixHome\bin\candle.exe")) {
    Step 'installing WiX 3.11 (portable)'
    $zip = "$Tools\wix311-binaries.zip"
    Invoke-WebRequest -OutFile $zip `
        -Uri 'https://github.com/wixtoolset/wix3/releases/download/wix3112rtm/wix311-binaries.zip'
    New-Item -ItemType Directory -Force -Path "$WixHome\bin" | Out-Null
    Expand-Archive -Path $zip -DestinationPath "$WixHome\bin" -Force
    Remove-Item $zip -Force
} else {
    Step 'WiX already present, skipping'
}

# --- persistent machine environment --------------------------------------
# The runner service does not inherit this session, so these have to land in
# the machine environment block or every job starts without a linker.
Step 'writing machine environment'
[Environment]::SetEnvironmentVariable('WIX', $WixHome, 'Machine')
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
foreach ($dir in @($CargoBin, "$WixHome\bin")) {
    if ($machinePath -notlike "*$dir*") { $machinePath = "$machinePath;$dir" }
}
[Environment]::SetEnvironmentVariable('Path', $machinePath, 'Machine')
# CARGO_HOME on the same volume as the build dir keeps the registry cache
# warm across jobs, which is most of why this runner is faster than SaaS.
[Environment]::SetEnvironmentVariable('CARGO_HOME', "$env:USERPROFILE\.cargo", 'Machine')

# --- cargo-wix ------------------------------------------------------------
# Baked in rather than `cargo install`ed per job: on the SaaS runner that
# compile was a meaningful slice of the two-hour installer job.
if (-not (Test-Path "$CargoBin\cargo-wix.exe")) {
    Step 'installing cargo-wix'
    & "$CargoBin\cargo.exe" install cargo-wix --locked
    if ($LASTEXITCODE -ne 0) { throw "cargo install cargo-wix exited $LASTEXITCODE" }
} else {
    Step 'cargo-wix already present, skipping'
}

# --- GitLab Runner --------------------------------------------------------
$RunnerDir = 'C:\GitLab-Runner'
$RunnerExe = "$RunnerDir\gitlab-runner.exe"
if (-not (Test-Path $RunnerExe)) {
    Step 'installing GitLab Runner'
    New-Item -ItemType Directory -Force -Path $RunnerDir | Out-Null
    Invoke-WebRequest -OutFile $RunnerExe `
        -Uri 'https://gitlab-runner-downloads.s3.amazonaws.com/latest/binaries/gitlab-runner-windows-amd64.exe'
} else {
    Step 'GitLab Runner binary already present, skipping'
}

# The registration token is deliberately NOT in user-data: user-data is
# readable by anyone holding ec2:DescribeInstanceAttribute, which is a much
# wider audience than the token deserves. It lives in SSM Parameter Store as
# a SecureString and is read here through the instance role.
Step 'reading runner token from SSM'
$token = (aws ssm get-parameter --name '${ssm_token_parameter}' --with-decryption `
    --region '${region}' --query 'Parameter.Value' --output text)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($token) -or $token -eq 'None') {
    throw 'could not read the runner token from SSM'
}

if (-not (Test-Path "$RunnerDir\config.toml")) {
    Step 'registering runner'
    & $RunnerExe register --non-interactive `
        --url '${gitlab_url}' `
        --token $token `
        --executor shell `
        --shell powershell `
        --name '${runner_name}'
    if ($LASTEXITCODE -ne 0) { throw "runner register exited $LASTEXITCODE" }

    & $RunnerExe install
    & $RunnerExe start
    Step 'runner service installed and started'
} else {
    Step 'runner already registered, skipping'
}

# --- idle auto-stop -------------------------------------------------------
# The instance bills by the hour while running, and CI is bursty, so it
# stops itself once the build tools have been quiet for a while. Shutting
# down from inside works because the instance is created with
# instance_initiated_shutdown_behavior = "stop", which means no IAM
# permission is needed here -- nothing has to be trusted to call the EC2 API.
Step 'installing idle auto-stop task'
$idleScript = @'
$ErrorActionPreference = "SilentlyContinue"
$StateFile = "C:\idle-ticks.txt"
# Anything a pipeline runs while it is genuinely working. The runner process
# itself is always alive and so must not be part of this list.
$Busy = @("cargo","rustc","link","cl","candle","light","rustup","msiexec","vs_buildtools")
$running = Get-Process -Name $Busy -ErrorAction SilentlyContinue
if ($running) {
    Set-Content -Path $StateFile -Value "0"
    exit
}
$ticks = 0
if (Test-Path $StateFile) { $ticks = [int](Get-Content $StateFile) }
$ticks++
Set-Content -Path $StateFile -Value "$ticks"
# Task runs every 5 minutes, so 6 consecutive idle ticks is ~30 minutes.
if ($ticks -ge 6) {
    Add-Content -Path "C:\bootstrap.log" -Value "[$(Get-Date)] idle 30m, stopping instance"
    Stop-Computer -Force
}
'@
Set-Content -Path 'C:\idle-stop.ps1' -Value $idleScript -Encoding utf8

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NonInteractive -NoProfile -ExecutionPolicy Bypass -File C:\idle-stop.ps1'
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(15) `
    -RepetitionInterval (New-TimeSpan -Minutes 5)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'rmon-ci-idle-stop' -Action $action -Trigger $trigger `
    -Principal $principal -Force | Out-Null

Step 'bootstrap complete'
</powershell>
<persist>true</persist>
