# ── Auth: JWT + Bearer Token ─────────────────────────────────────
# Signs a JWT with the agent's RSA key and exchanges it for a
# bearer token. Auto-calibrates time offset from server response.
# ─────────────────────────────────────────────────────────────────
function Get-AgentToken {
    param([hashtable]$AgentInfo)

    function ConvertTo-Base64Url([byte[]]$Bytes) {
        [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
    }

    function Build-SignedJwt([int]$EpochNow) {
        $headerB64 = ConvertTo-Base64Url([Text.Encoding]::UTF8.GetBytes('{"alg":"RS256","typ":"JWT"}'))

        $payload = @{
            sub = $AgentInfo.ClientId
            iss = $AgentInfo.ClientId
            aud = $AgentInfo.TokenUrl
            nbf = $EpochNow
            iat = $EpochNow
            exp = $EpochNow + 300
            jti = [guid]::NewGuid().ToString()
        } | ConvertTo-Json -Compress

        $payloadB64 = ConvertTo-Base64Url([Text.Encoding]::UTF8.GetBytes($payload))

        $dataToSign = [Text.Encoding]::UTF8.GetBytes("$headerB64.$payloadB64")
        $sig = $AgentInfo.Rsa.SignData(
            $dataToSign,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $sigB64 = ConvertTo-Base64Url($sig)

        return "$headerB64.$payloadB64.$sigB64"
    }

    $tokenBody = @{
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        grant_type            = "client_credentials"
    }

    # Try with offset 0 first, then auto-calibrate from server error
    $timeOffset = 0
    $maxAttempts = 2

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $now = [int][double]::Parse((Get-Date -UFormat %s)) + $timeOffset
        $jwt = Build-SignedJwt $now
        $tokenBody["client_assertion"] = $jwt

        if ($attempt -eq 1) {
            Write-Log "JWT signed (clientId=$($AgentInfo.ClientId))" -Severity Success
        } else {
            Write-Log "JWT re-signed with offset ${timeOffset}s" -Severity Success
        }

        try {
            $tokenResponse = Invoke-RestMethod -Uri $AgentInfo.TokenUrl -Method POST -Body $tokenBody -ContentType "application/x-www-form-urlencoded" -TimeoutSec 15
            $token = $tokenResponse.access_token -replace "`r|`n|\s", ""
            if (-not $token) { throw "Empty access_token in response" }

            Write-Log "Bearer token obtained" -Severity Success
            break
        } catch {
            $errDetails = $null
            try { $errDetails = $_.ErrorDetails.Message } catch {}

            # Try to extract server time vs JWT time from error and auto-calibrate
            if ($errDetails -and $attempt -lt $maxAttempts) {
                # Pattern: "not valid until <date>. Current server time is <date>."
                $datePattern = '(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M)'
                $dates = [regex]::Matches($errDetails, $datePattern)

                if ($dates.Count -ge 2) {
                    $jwtTimeStr    = $dates[0].Value
                    $serverTimeStr = $dates[1].Value
                    try {
                        $jwtTime    = [DateTime]::ParseExact($jwtTimeStr, "M/d/yyyy h:mm:ss tt", $null)
                        $serverTime = [DateTime]::ParseExact($serverTimeStr, "M/d/yyyy h:mm:ss tt", $null)
                        $deltaSec   = [int]($serverTime - $jwtTime).TotalSeconds

                        Write-Log "Time mismatch detected - auto-calibrating" -Severity Warning
                        Write-Detail "JWT nbf:      $jwtTimeStr"
                        Write-Detail "Server time:  $serverTimeStr"
                        Write-Detail "Delta:        ${deltaSec}s"

                        # Apply delta minus 60s buffer so nbf is safely in the past
                        $timeOffset = $deltaSec - 60
                        Write-Detail "Retrying with offset: ${timeOffset}s"
                        continue
                    } catch {
                        Write-Detail "Could not parse dates from server response" "Yellow"
                    }
                }
            }

            # Final failure
            Write-Log "Failed to exchange JWT for bearer token" -Severity Error
            Write-Detail "Exception: $($_.Exception.Message)" "Red"
            if ($errDetails) {
                Write-Detail "Server response:" "Yellow"
                Write-Detail $errDetails "Yellow"
            }
            exit 1
        }
    }

    # ── Build API headers ──
    $apiHeaders = @{
        Authorization           = "Bearer $token"
        "Content-Type"          = "application/json"
        "User-Agent"            = "VSServices/$($AgentInfo.Version)"
        "X-VSS-E2EID"           = [guid]::NewGuid().ToString()
        "X-TFS-FedAuthRedirect" = "Suppress"
        "X-TFS-Session"         = [guid]::NewGuid().ToString()
    }

    return @{
        Token      = $token
        ApiHeaders = $apiHeaders
    }
}
