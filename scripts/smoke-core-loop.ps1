#Requires -Version 5.1
<#
.SYNOPSIS
  Core closed-loop smoke test: asset scan -> CVE match -> patch task ->
  approval -> agent fetch -> execution/report -> success.

.DESCRIPTION
  Starts the docker-compose stack (PostgreSQL + server), registers a real
  agent container, seeds one deterministic CVE for busybox, waits for the
  match, generates and approves a patch task, and waits for the agent to
  fetch and report it. Defaults to dry-run so the smoke is safe anywhere;
  pass -ExecuteForReal to run "apk upgrade busybox" for real.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts/smoke-core-loop.ps1
  powershell -ExecutionPolicy Bypass -File scripts/smoke-core-loop.ps1 -ExecuteForReal
#>
[CmdletBinding()]
param(
    [string]$ComposeFile = "deploy/docker-compose/docker-compose.yml",
    [int]$HTTPPort = 8080,
    [int]$GRPCPort = 9090,
    [int]$PostgresPort = 15433,
    [string]$ApiKey = "sk-change-me",
    [switch]$ExecuteForReal,
    [switch]$KeepRunning
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
$dryRun = -not $ExecuteForReal
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $root

function Fail([string]$msg) {
    Write-Host "SMOKE FAIL: $msg" -ForegroundColor Red
    exit 1
}

function Wait-Health([int]$port, [int]$timeoutSec) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest -Uri "http://localhost:$port/health" -TimeoutSec 2 -ErrorAction Stop
            if ($r.StatusCode -eq 200) {
                Write-Host "server healthy" -ForegroundColor Green
                return
            }
        }
        catch { }
        Start-Sleep 2
    }
    Fail "server did not become healthy on port $port"
}

$cveID = "CVE-SMOKE-BUSYBOX"
$agentHost = "smoke-agent"
$headers = @{ "X-API-Key" = $ApiKey }

Write-Host ">>> compose up (postgres=$PostgresPort dry_run=$dryRun)"
$env:POSTGRES_PORT = "$PostgresPort"
$env:HTTP_PORT = "$HTTPPort"
$env:GRPC_PORT = "$GRPCPort"
$env:PATCH_DRY_RUN = if ($dryRun) { "true" } else { "false" }
docker compose -f $ComposeFile up -d --build
if ($LASTEXITCODE -ne 0) { Fail "docker compose up failed" }
Wait-Health $HTTPPort 120

Write-Host ">>> create agent"
$agentBody = @{ hostname = $agentHost; platform = "linux-amd64" } | ConvertTo-Json
$agentResp = Invoke-RestMethod -Uri "http://localhost:$HTTPPort/api/v1/agents" -Method Post `
    -Headers $headers -ContentType "application/json" -Body $agentBody
$agentID = $agentResp.agent_id
if (-not $agentID) { Fail "agent creation returned no agent_id" }
Write-Host "agent_id=$agentID"

Write-Host ">>> seed CVE feed"
$pgID = (docker compose -f $ComposeFile ps -q postgres).Trim()
if (-not $pgID) { Fail "postgres container not found" }
$sql = @"
INSERT INTO cve_feed (source, source_key, cve_id, cve_url, affected, severity, cvss_score, summary, published_at, fetched_at, ttl_seconds)
VALUES ('custom','smoke-busybox','$cveID','https://example.invalid/smoke','[{"name":"busybox","max_ver":"99.99.99","fixed_in":"99.99.99"}]'::jsonb,'HIGH',8.0,'core loop smoke',now(),now(),86400)
ON CONFLICT (source, source_key, cve_id) DO UPDATE SET affected=EXCLUDED.affected, severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score, fetched_at=now();
"@
$sql | docker exec -i $pgID psql -U vulnscan -d vulnscan -v ON_ERROR_STOP=1
if ($LASTEXITCODE -ne 0) { Fail "seed CVE feed failed" }

Write-Host ">>> start agent container"
$serverID = (docker compose -f $ComposeFile ps -q server).Trim()
if (-not $serverID) { Fail "server container not found" }
$image = (docker inspect -f '{{.Config.Image}}' $serverID).Trim()
$net = (docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' $serverID).Trim().Split(' ')[0]
if (-not $net) { Fail "could not resolve compose network" }

$agentCfg = "server:`n  addr: server:9090`nagent:`n  id: $agentID`n  hostname: $agentHost`n  patch_enabled: true`n  patch_timeout_seconds: 600`n  wua_collect: false`n  wua_timeout_seconds: 60`n"
$cfgPath = Join-Path $env:TEMP ("vuln-smoke-agent-" + [guid]::NewGuid().ToString("N") + ".yaml")
Set-Content -Path $cfgPath -Value $agentCfg -Encoding ascii -NoNewline
$agentName = "agent-smoke-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
docker run -d --name $agentName --network $net `
    -v "${cfgPath}:/root/.vuln-scanner/agent.yaml" `
    $image ./agents/linux-amd64 run | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "agent container start failed" }

try {
    Write-Host ">>> wait for agent online"
    $deadline = (Get-Date).AddSeconds(120)
    $online = $false
    while ((Get-Date) -lt $deadline) {
        Start-Sleep 3
        try {
            $a = Invoke-RestMethod -Uri "http://localhost:$HTTPPort/api/v1/agents/$agentID" -Headers $headers
            if ($a.status -eq "online") { $online = $true; break }
        }
        catch { }
    }
    if (-not $online) { Fail "agent did not come online" }
    Write-Host "agent online"

    Write-Host ">>> trigger match and wait for CVE"
    Invoke-RestMethod -Uri "http://localhost:$HTTPPort/api/v1/agents/$agentID/scan" -Method Post `
        -Headers $headers | Out-Null
    $deadline = (Get-Date).AddSeconds(120)
    $matched = $null
    while ((Get-Date) -lt $deadline) {
        Start-Sleep 5
        try {
            $v = Invoke-RestMethod -Uri "http://localhost:$HTTPPort/api/v1/agents/$agentID/vulns" -Headers $headers
            $matched = $v.vulnerabilities | Where-Object { $_.cve_id -eq $cveID -and $_.status -eq "active" } | Select-Object -First 1
            if ($matched) { break }
        }
        catch { }
    }
    if (-not $matched) { Fail "CVE $cveID never matched" }
    Write-Host ("matched: " + $matched.asset_name + "@" + $matched.asset_version + " (" + $matched.severity + ")")

    Write-Host ">>> generate and approve patch task"
    $genBody = @{ asset_names = @($matched.asset_name); cve_ids = @($cveID); approval_required = $true } | ConvertTo-Json
    $gen = Invoke-RestMethod -Uri "http://localhost:$HTTPPort/api/v1/agents/$agentID/patch-tasks/generate" -Method Post `
        -Headers $headers -ContentType "application/json" -Body $genBody
    if ($gen.created -ne 1 -or -not $gen.tasks) { Fail "patch task was not created" }
    $taskID = $gen.tasks[0].id
    Write-Host ("task_id=$taskID command=" + $gen.tasks[0].command)
    Invoke-RestMethod -Uri "http://localhost:$HTTPPort/api/v1/patch-tasks/$taskID/approve" -Method Post `
        -Headers $headers | Out-Null

    Write-Host ">>> wait for agent to fetch and report (up to 150s)"
    $deadline = (Get-Date).AddSeconds(150)
    $task = $null
    while ((Get-Date) -lt $deadline) {
        Start-Sleep 5
        $task = Invoke-RestMethod -Uri "http://localhost:$HTTPPort/api/v1/patch-tasks/$taskID" -Headers $headers
        if ($task.status -in @("success", "failed", "cancelled")) { break }
    }
    if (-not $task -or $task.status -notin @("success", "failed", "cancelled")) {
        Fail "patch task $taskID did not reach a terminal state"
    }

    Write-Host ""
    Write-Host ("=== PATCH TASK " + $taskID + " status=" + $task.status + " exit=" + $task.result.exit_code + " ===")
    Write-Host $task.result.output
    if ($task.status -ne "success") {
        Fail "patch task ended with status $($task.status)"
    }

    Write-Host ">>> wait for post-patch verification (up to 120s)"
    $deadline = (Get-Date).AddSeconds(120)
    $postPatchStatus = $null
    while ((Get-Date) -lt $deadline) {
        Start-Sleep 5
        $task = Invoke-RestMethod -Uri "http://localhost:$HTTPPort/api/v1/patch-tasks/$taskID" -Headers $headers
        if ($task.post_patch_status -in @("passed", "failed", "na")) {
            $postPatchStatus = $task.post_patch_status
            break
        }
    }
    if (-not $postPatchStatus) {
        Fail "post-patch verification never completed for task $taskID"
    }
    if ($dryRun -and $postPatchStatus -ne "failed") {
        Fail "dry-run post-patch status expected failed, got $postPatchStatus"
    }
    Write-Host ("post_patch_status=" + $postPatchStatus + " detail=" + $task.post_patch_detail)

    Write-Host ""
    Write-Host "SMOKE PASS: asset scan -> CVE match -> patch approval -> agent execution -> success -> post-patch verification" -ForegroundColor Green
}
finally {
    try { docker rm -f $agentName 2>$null | Out-Null } catch { }
    Remove-Item -Path $cfgPath -Force -ErrorAction SilentlyContinue
    if (-not $KeepRunning) {
        Write-Host ">>> compose down"
        docker compose -f $ComposeFile down
    }
}
