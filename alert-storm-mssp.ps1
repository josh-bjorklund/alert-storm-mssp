<#
.SYNOPSIS
Detection and alert resolver v2.1 - Josh Bjorklund

MSSP edition - No site IDs needed.

.DESCRIPTION
Optionally unquarantines any threats for the given hash (if the user confirms),
then resolves both threats and STAR alerts for that hash.

Threats are first looked up with GET /threats (all filters live there). Only the
resulting threat ids are sent to the un-quarantine and incident endpoints, which
works around /threats/incident not passing its limit to its internal query. Ids
are spooled to a temporary file so memory use stays flat for very large hashes.

Exit code: 0 on success (including "nothing matched"), 1 if any chunk or lookup failed.

.PARAMETER Server
Management console base URL, e.g. https://usea1-123.sentinelone.net (a trailing slash is trimmed).

.PARAMETER ApiToken
API token, as a SecureString.

.PARAMETER FileHash
SHA1 (40 hex) or SHA256 (64 hex) of the file to resolve threats and alerts for.

.PARAMETER ThreatAnalystVerdict
Analyst verdict applied when resolving threats. Default: false_positive.

.PARAMETER AlertAnalystVerdict
Analyst verdict applied when resolving STAR alerts. Default: false_positive.

.PARAMETER ThreatsPageSize
Page size for the GET /threats lookup (1-1000). Default: 1000.

.PARAMETER ThreatsBatchLimit
Number of threat ids sent per un-quarantine / resolve call (1-5000). Default: 5000.

.PARAMETER AlertsBatchLimit
Per-call limit for STAR alert calls. Default: 500.

.PARAMETER BatchDelaySeconds
Delay between batches, to be gentle with rate limits (0-3600). Default: 1.

.EXAMPLE
$token = Read-Host -AsSecureString -Prompt 'API token'
./alert-storm-mssp.ps1 -Server https://usea1-123.sentinelone.net -ApiToken $token -FileHash <sha1-or-sha256>
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^https://')]
    [string]$Server,

    [Parameter(Mandatory = $true)]
    [securestring]$ApiToken,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$')]
    [string]$FileHash,

    [ValidateSet('undefined', 'true_positive', 'false_positive', 'suspicious')]
    [string]$ThreatAnalystVerdict = 'false_positive',

    [ValidateSet('undefined', 'true_positive', 'false_positive', 'suspicious')]
    [string]$AlertAnalystVerdict = 'false_positive',

    [ValidateRange(1, 1000)]
    [int]$ThreatsPageSize = 1000,

    [ValidateRange(1, 5000)]
    [int]$ThreatsBatchLimit = 5000,

    [ValidateRange(1, 5000)]
    [int]$AlertsBatchLimit = 500,

    [ValidateRange(0, 3600)]
    [int]$BatchDelaySeconds = 1
)

$Server = $Server.TrimEnd('/')
$ThreatAnalystVerdict = $ThreatAnalystVerdict.ToLowerInvariant()
$AlertAnalystVerdict = $AlertAnalystVerdict.ToLowerInvariant()

# Run totals, reported in the final summary
$script:ThreatsFound = 0
$script:ThreatsUnquarantined = 0
$script:ThreatsResolved = 0
$script:AlertsResolved = 0
$script:FailedChunks = 0
$script:LookupFailed = $false

# ================= INTERNAL HELPERS ====================

function Get-HashFilterKeyForAlerts {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Hash
    )

    switch ($Hash.Length) {
        40 { return "sourceProcessFileHashSha1__contains" }     # SHA1
        64 { return "sourceProcessFileHashSha256__contains" }   # SHA256
        default { throw "Unsupported hash length ($($Hash.Length)); expected SHA1 (40) or SHA256 (64)." }
    }
}

# NetworkCredential converts a SecureString to plaintext on Windows PowerShell 5.1 and PowerShell 7+ on every OS.
$PlainToken = [System.Net.NetworkCredential]::new('', $ApiToken).Password
$Headers = @{
    "Authorization" = "ApiToken $PlainToken"
}
$PlainToken = $null

function Get-AffectedCount {
    param($Response)

    if ($Response -and $Response.data -and $null -ne $Response.data.affected) {
        return [int]$Response.data.affected
    }
    return 0
}

# ================= THREATS LOOKUP ======================

# Pages through GET /threats and writes only the threat ids to $SpoolPath, one per line.
# Returns the number of ids written. Page objects are discarded after each page.
function Export-ThreatIdsByHash {
    param(
        [string]$Hash,
        [string]$SpoolPath
    )

    $endpoint = "$Server/web/api/v2.1/threats"
    $count = 0
    $cursor = $null
    $page = 0

    $writer = [System.IO.StreamWriter]::new($SpoolPath, $false)
    try {
        do {
            $page++
            $uri = "${endpoint}?limit=$ThreatsPageSize&contentHashes=$([uri]::EscapeDataString($Hash))&incidentStatuses=unresolved"
            if ($cursor) {
                $uri += "&cursor=$([uri]::EscapeDataString($cursor))"
            }

            $response = Invoke-RestMethod -Uri $uri -Headers $Headers -Method Get -ErrorAction Stop

            foreach ($threat in @($response.data)) {
                if ($threat.id) {
                    $writer.WriteLine([string]$threat.id)
                    $count++
                }
            }

            $cursor = $null
            if ($response.pagination -and $response.pagination.nextCursor) {
                $cursor = [string]$response.pagination.nextCursor
            }
            $response = $null

            Write-Host "[-] Threat lookup page #${page}: $count ids so far ..." -ForegroundColor Cyan
        } while ($cursor)
    }
    finally {
        $writer.Dispose()
    }

    return $count
}

# Reads $SpoolPath in chunks of $ChunkSize ids and invokes $Action with each chunk (a string[]).
function Invoke-ForEachIdChunk {
    param(
        [string]$SpoolPath,
        [int]$ChunkSize,
        [scriptblock]$Action
    )

    $reader = [System.IO.StreamReader]::new($SpoolPath)
    try {
        $chunk = [System.Collections.Generic.List[string]]::new()
        while ($null -ne ($line = $reader.ReadLine())) {
            if ($line) { $chunk.Add($line) }
            if ($chunk.Count -ge $ChunkSize) {
                & $Action $chunk.ToArray()
                $chunk.Clear()
            }
        }
        if ($chunk.Count -gt 0) {
            & $Action $chunk.ToArray()
        }
    }
    finally {
        $reader.Dispose()
    }
}

# ================= THREATS (UN-QUARANTINE + RESOLVE) ===

function Send-ThreatIdChunk {
    param(
        [string[]]$Ids,
        [int]$ChunkNumber,
        [int]$ChunkCount,
        [bool]$Unquarantine
    )

    if ($Unquarantine) {
        $body = @{ filter = @{ ids = $Ids } } | ConvertTo-Json -Depth 5
        Write-Host "[-] Chunk $ChunkNumber/${ChunkCount}: sending unquarantine for $($Ids.Count) threats ..." -ForegroundColor Yellow
        try {
            $response = Invoke-RestMethod -Uri "$Server/web/api/v2.1/threats/mitigate/un-quarantine" -Headers $Headers `
                                          -Method Post -ContentType "application/json" `
                                          -Body $body -ErrorAction Stop
            $script:ThreatsUnquarantined += Get-AffectedCount $response
        }
        catch {
            # Leave the chunk unresolved so a re-run picks it up and its files are not resolved while still quarantined.
            Write-Error "Chunk $ChunkNumber/${ChunkCount}: unquarantine failed, chunk skipped: $($_.Exception.Message)" -ErrorAction Continue
            $script:FailedChunks++
            return
        }
    }

    $body = @{
        filter = @{ ids = $Ids }
        data   = @{
            incidentStatus = "resolved"
            analystVerdict = $ThreatAnalystVerdict
        }
    } | ConvertTo-Json -Depth 5

    Write-Host "[-] Chunk $ChunkNumber/${ChunkCount}: resolving $($Ids.Count) threat incidents ..." -ForegroundColor Cyan
    try {
        $response = Invoke-RestMethod -Uri "$Server/web/api/v2.1/threats/incident" -Headers $Headers `
                                      -Method Post -ContentType "application/json" `
                                      -Body $body -ErrorAction Stop
        $affected = Get-AffectedCount $response
        $script:ThreatsResolved += $affected
        Write-Host "[+] Chunk $ChunkNumber/${ChunkCount} affected: $affected"
    }
    catch {
        Write-Error "Chunk $ChunkNumber/${ChunkCount}: error resolving threat incidents: $($_.Exception.Message)" -ErrorAction Continue
        $script:FailedChunks++
    }
}

# ================= ALERTS (STAR) =======================

function Resolve-CloudDetectionAlertsByHash {
    param(
        [string]$Hash
    )

    $verdictEndpoint = "$Server/web/api/v2.1/cloud-detection/alerts/analyst-verdict"
    $incidentEndpoint = "$Server/web/api/v2.1/cloud-detection/alerts/incident"

    $hashFilterKey = Get-HashFilterKeyForAlerts -Hash $Hash

    $batch = 0

    while ($true) {
        $batch++

        # Filter unresolved STAR alerts whose source-process file hash matches
        $filter = @{
            limit          = $AlertsBatchLimit
            incidentStatus = "UNRESOLVED"
        }
        $filter[$hashFilterKey] = @($Hash)

        # The verdict goes through its own endpoint and must be set first, while the alerts still match UNRESOLVED.
        $verdictBody = @{
            filter = $filter
            data   = @{ analystVerdict = $AlertAnalystVerdict }
        } | ConvertTo-Json -Depth 5

        $incidentBody = @{
            filter = $filter
            data   = @{ incidentStatus = "resolved" }
        } | ConvertTo-Json -Depth 5

        Write-Host "[-] Alerts batch #${batch}: resolving STAR alerts for hash $Hash using filter '$hashFilterKey' ..." -ForegroundColor Cyan

        try {
            Invoke-RestMethod -Uri $verdictEndpoint -Headers $Headers `
                              -Method Post -ContentType "application/json" `
                              -Body $verdictBody -ErrorAction Stop | Out-Null

            $response = Invoke-RestMethod -Uri $incidentEndpoint -Headers $Headers `
                                          -Method Post -ContentType "application/json" `
                                          -Body $incidentBody -ErrorAction Stop
        }
        catch {
            Write-Error "Error resolving STAR alerts: $($_.Exception.Message)" -ErrorAction Continue
            $script:FailedChunks++
            break
        }

        $affected = Get-AffectedCount $response
        Write-Host "[+] Alerts batch #$batch affected: $affected"

        $script:AlertsResolved += $affected

        if ($affected -lt $AlertsBatchLimit -or $affected -eq 0) {
            break
        }

        Start-Sleep -Seconds $BatchDelaySeconds
    }

    Write-Host "[=] Total STAR alerts resolved for hash ${Hash}: $($script:AlertsResolved)" -ForegroundColor Green
}

# ===================== MAIN ============================

Write-Host "=== SentinelOne hash workflow: $FileHash ===" -ForegroundColor Yellow
Write-Host "Console: $Server"
Write-Host ""

# ---- Threats: look up ids first, then ask about unquarantine, then act ----
$spoolPath = [System.IO.Path]::GetTempFileName()
try {
    try {
        $script:ThreatsFound = Export-ThreatIdsByHash -Hash $FileHash -SpoolPath $spoolPath
    }
    catch {
        Write-Error "Threat lookup failed: $($_.Exception.Message)" -ErrorAction Continue
        $script:LookupFailed = $true
    }

    if (-not $script:LookupFailed) {
        Write-Host "[=] Found $($script:ThreatsFound) unresolved threats for hash $FileHash" -ForegroundColor Green

        if ($script:ThreatsFound -eq 0) {
            Write-Host "[=] No threats to resolve, skipping threats step." -ForegroundColor Yellow
        }
        else {
            # BIG RED PROMPT: ASK ABOUT UNQUARANTINE
            Write-Host "**********************************************************************" -ForegroundColor Red
            Write-Host "YOU ARE ABOUT TO RESOLVE $($script:ThreatsFound) THREATS & ALERTS FOR HASH: $FileHash" -ForegroundColor Red
            Write-Host "Optionally, you can also UNQUARANTINE any files associated with this" -ForegroundColor Red
            Write-Host "hash BEFORE resolving the incidents (equivalent to Threats > Unquarantine)." -ForegroundColor Red
            Write-Host "**********************************************************************" -ForegroundColor Red

            $unqChoice = Read-Host "Do you want to send UNQUARANTINE commands for this hash first? (Y/N)"
            $unquarantine = $unqChoice -match '^(Y|y)$'

            Write-Host ""
            if ($unquarantine) {
                Write-Host ">>> User chose to UNQUARANTINE files before resolving incidents..." -ForegroundColor Yellow
            }
            else {
                Write-Host ">>> Skipping unquarantine. Proceeding directly to resolve incidents..." -ForegroundColor Yellow
            }

            $chunkCount = [int][math]::Ceiling($script:ThreatsFound / $ThreatsBatchLimit)
            $script:chunkNumber = 0
            Invoke-ForEachIdChunk -SpoolPath $spoolPath -ChunkSize $ThreatsBatchLimit -Action {
                param([string[]]$Ids)
                $script:chunkNumber++
                Send-ThreatIdChunk -Ids $Ids -ChunkNumber $script:chunkNumber -ChunkCount $chunkCount -Unquarantine $unquarantine
                if ($script:chunkNumber -lt $chunkCount) {
                    Start-Sleep -Seconds $BatchDelaySeconds
                }
            }

            Write-Host "[=] Total threat incidents resolved for hash ${FileHash}: $($script:ThreatsResolved)" -ForegroundColor Green
        }
    }
}
finally {
    Remove-Item -LiteralPath $spoolPath -Force -ErrorAction SilentlyContinue
}

# ---- Alerts ----
Write-Host ""
Resolve-CloudDetectionAlertsByHash -Hash $FileHash

# ---- Summary ----
Write-Host ""
Write-Host "=== Summary for hash $FileHash ===" -ForegroundColor Yellow
Write-Host "Threats found:          $($script:ThreatsFound)"
Write-Host "Threats unquarantined:  $($script:ThreatsUnquarantined)"
Write-Host "Threats resolved:       $($script:ThreatsResolved)"
Write-Host "Alerts resolved:        $($script:AlertsResolved)"
Write-Host "Failed chunks:          $($script:FailedChunks)"
if ($script:LookupFailed) {
    Write-Host "Threat lookup:          FAILED" -ForegroundColor Red
}
if ($script:ThreatsFound -eq 0 -and $script:AlertsResolved -eq 0 -and -not $script:LookupFailed -and $script:FailedChunks -eq 0) {
    Write-Host "Nothing matched this hash (no unresolved threats or alerts)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Yellow

if ($script:LookupFailed -or $script:FailedChunks -gt 0) {
    exit 1
}
exit 0
