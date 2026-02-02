<#
Detection and alert resolver v2.1 - Josh Bjorklund

MSSP eddition - No site IDs needed. 

How to use: Within the script, fill in the console URL, then after running, provide your API key and the file's hash. 

This will optionally unquarantine any threats for the given hash (if user confirms),
then clear both alerts and detections. Additionally, within user config, you can
change the analyst verdict to what is desired. Default is false positive.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ApiToken,

    [Parameter(Mandatory = $true)]
    [string]$FileHash
)

# ===================== USER CONFIG =====================

# Management console base URL – NO trailing slash.
# Example: "https://usea1-123.sentinelone.net"
$Server = "https://XXXXXXXXXX.sentinelone.net"

# Threats: what analyst verdict to apply when resolving
# Options: undefined, true_positive, false_positive, suspicious
$ThreatAnalystVerdict = "false_positive"

# Alerts (STAR custom alerts): analyst verdict when resolving
$AlertAnalystVerdict = "false_positive"

# Max per-call limits
$ThreatsBatchLimit = 5000   
$AlertsBatchLimit  = 500   

# Optional: delay between batches to be gentle with rate limits
$BatchDelaySeconds = 1

# ================= INTERNAL HELPERS ====================

function Get-HashFilterKeyForAlerts {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Hash
    )

    switch ($Hash.Length) {
        32 { return "sourceProcessFileHashMd5__contains" }      # MD5
        40 { return "sourceProcessFileHashSha1__contains" }     # SHA1
        64 { return "sourceProcessFileHashSha256__contains" }   # SHA256
        default {
            Write-Warning "Unknown hash length ($($Hash.Length)). Defaulting to SHA1 filter."
            return "sourceProcessFileHashSha1__contains"
        }
    }
}

$Headers = @{
    "Authorization" = "ApiToken $ApiToken"
}

# ============== UNQUARANTINE (OPTIONAL STEP) ===========

function Unquarantine-ThreatsByHash {
    param(
        [string]$Hash
    )

    # Uses the mitigate/un-quarantine endpoint and filters by hash.
    $endpoint = "$Server/web/api/v2.1/threats/mitigate/un-quarantine"

    $totalUnquarantined = 0
    $batch = 0

    while ($true) {
        $batch++

        $body = @{
            filter = @{
                limit         = $ThreatsBatchLimit
                contentHashes = @($Hash)
            }
        } | ConvertTo-Json -Depth 5

        Write-Host "[-] Unquarantine batch #${batch}: sending unquarantine for threats with hash $Hash ..." -ForegroundColor Yellow

        try {
            $response = Invoke-RestMethod -Uri $endpoint -Headers $Headers `
                                          -Method Post -ContentType "application/json" `
                                          -Body $body -ErrorAction Stop
        }
        catch {
            Write-Error "Error sending unquarantine command: $($_.Exception.Message)"
            break
        }

        $affected = 0
        if ($response -and $response.data -and $response.data.affected -ne $null) {
            $affected = [int]$response.data.affected
        }

        Write-Host "[+] Unquarantine batch #$batch affected (unquarantine commands sent): $affected"

        $totalUnquarantined += $affected

        if ($affected -lt $ThreatsBatchLimit -or $affected -eq 0) {
            break
        }

        Start-Sleep -Seconds $BatchDelaySeconds
    }

    Write-Host "[=] Total threats with unquarantine command sent for hash ${Hash}: $totalUnquarantined" -ForegroundColor Green
}

# ================= THREATS (INCIDENTS) =================

function Resolve-ThreatIncidentsByHash {
    param(
        [string]$Hash
    )

    $endpoint = "$Server/web/api/v2.1/threats/incident"

    $totalResolved = 0
    $batch = 0

    while ($true) {
        $batch++

        $body = @{
            filter = @{
                limit         = $ThreatsBatchLimit
                contentHashes = @($Hash)
            }
            data = @{
                incidentStatus = "resolved"
                analystVerdict = $ThreatAnalystVerdict
            }
        } | ConvertTo-Json -Depth 5

        Write-Host "[-] Threats batch #${batch}: resolving incidents for hash $Hash ..." -ForegroundColor Cyan

        try {
            $response = Invoke-RestMethod -Uri $endpoint -Headers $Headers `
                                          -Method Post -ContentType "application/json" `
                                          -Body $body -ErrorAction Stop
        }
        catch {
            Write-Error "Error resolving threat incidents: $($_.Exception.Message)"
            break
        }

        $affected = 0
        if ($response -and $response.data -and $response.data.affected -ne $null) {
            $affected = [int]$response.data.affected
        }

        Write-Host "[+] Threats batch #$batch affected: $affected"

        $totalResolved += $affected

        if ($affected -lt $ThreatsBatchLimit -or $affected -eq 0) {
            break
        }

        Start-Sleep -Seconds $BatchDelaySeconds
    }

    Write-Host "[=] Total threat incidents resolved for hash ${Hash}: $totalResolved" -ForegroundColor Green
}

# ================= ALERTS (STAR) =======================

function Resolve-CloudDetectionAlertsByHash {
    param(
        [string]$Hash
    )

    $endpoint = "$Server/web/api/v2.1/cloud-detection/alerts/incident"

    $hashFilterKey = Get-HashFilterKeyForAlerts -Hash $Hash

    $totalResolved = 0
    $batch = 0

    while ($true) {
        $batch++

        # Filter unresolved STAR alerts whose source-process file hash matches
        $filter = @{
            limit          = $AlertsBatchLimit
            incidentStatus = "UNRESOLVED"  
        }
        $filter[$hashFilterKey] = @($Hash)

        $body = @{
            filter = $filter
            data   = @{
                incidentStatus = "resolved"
                analystVerdict = $AlertAnalystVerdict
            }
        } | ConvertTo-Json -Depth 5

        Write-Host "[-] Alerts batch #${batch}: resolving STAR alerts for hash $Hash using filter '$hashFilterKey' ..." -ForegroundColor Cyan

        try {
            $response = Invoke-RestMethod -Uri $endpoint -Headers $Headers `
                                          -Method Post -ContentType "application/json" `
                                          -Body $body -ErrorAction Stop
        }
        catch {
            Write-Error "Error resolving STAR alerts: $($_.Exception.Message)"
            break
        }

        $affected = 0
        if ($response -and $response.data -and $response.data.affected -ne $null) {
            $affected = [int]$response.data.affected
        }

        Write-Host "[+] Alerts batch #$batch affected: $affected"

        $totalResolved += $affected

        if ($affected -lt $AlertsBatchLimit -or $affected -eq 0) {
            break
        }

        Start-Sleep -Seconds $BatchDelaySeconds
    }

    Write-Host "[=] Total STAR alerts resolved for hash ${Hash}: $totalResolved" -ForegroundColor Green
}

# ===================== MAIN ============================

Write-Host "=== SentinelOne hash workflow: $FileHash ===" -ForegroundColor Yellow
Write-Host "Console: $Server"
Write-Host ""

# BIG RED PROMPT: ASK ABOUT UNQUARANTINE
Write-Host "**********************************************************************" -ForegroundColor Red
Write-Host "YOU ARE ABOUT TO RESOLVE THREATS & ALERTS FOR HASH: $FileHash" -ForegroundColor Red
Write-Host "Optionally, you can also UNQUARANTINE any files associated with this" -ForegroundColor Red
Write-Host "hash BEFORE resolving the incidents (equivalent to Threats > Unquarantine)." -ForegroundColor Red
Write-Host "**********************************************************************" -ForegroundColor Red

$unqChoice = Read-Host "Do you want to send UNQUARANTINE commands for this hash first? (Y/N)"

if ($unqChoice -match '^(Y|y)$') {
    Write-Host ""
    Write-Host ">>> User chose to UNQUARANTINE files before resolving incidents..." -ForegroundColor Yellow
    Unquarantine-ThreatsByHash -Hash $FileHash
} else {
    Write-Host ""
    Write-Host ">>> Skipping unquarantine. Proceeding directly to resolve incidents..." -ForegroundColor Yellow
}

Write-Host ""
Resolve-ThreatIncidentsByHash -Hash $FileHash
Write-Host ""
Resolve-CloudDetectionAlertsByHash -Hash $FileHash

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Yellow
