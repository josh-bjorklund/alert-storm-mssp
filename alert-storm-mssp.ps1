<#
.SYNOPSIS
Detection and alert resolver v2.1 - Josh Bjorklund

MSSP edition - No site IDs needed.

.DESCRIPTION
Optionally unquarantines any threats for the given hash(es) (if the user confirms), then resolves both threats and STAR alerts for all of them.

All hashes are looked up and remediated together, not one at a time: a single GET /threats call (contentHashes accepts a list) finds every matching threat across all hashes, the user is prompted once for unquarantine, and the resulting threat ids are resolved as one batch. STAR alerts are resolved per hash algorithm (SHA1 vs SHA256, since that's what the alerts filter field is keyed on) in at most two batched calls covering every hash of that type, rather than one call per hash.

Threats are first looked up with GET /threats (all filters live there). Only the resulting threat ids are sent to the un-quarantine and incident endpoints, which works around /threats/incident not passing its limit to its internal query. Ids are spooled to a temporary file so memory use stays flat for very large hashes.

Exit code: 0 on success (including "nothing matched"), 1 if any chunk or lookup failed.

.PARAMETER Server
Management console base URL, e.g. https://usea1-123.sentinelone.net (a trailing slash is trimmed).

.PARAMETER ApiToken
API token, as a SecureString.

.PARAMETER FileHash
One or more SHA1 (40 hex) or SHA256 (64 hex) hashes of the files to resolve threats and alerts for. Pass them as a PowerShell array, e.g. -FileHash hash1,hash2 (no quotes around the whole list), or a variable holding an array. This needs a PowerShell session or pwsh -Command; pwsh -File delivers "hash1,hash2" as a single string, which fails validation. Hashes are lowercased and duplicates are ignored. All hashes are looked up and remediated together as a single batch, not one at a time.

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

.PARAMETER MaxRetries
Retries per API call when the console answers HTTP 429 (rate limited), 0-10. Waits for the Retry-After header if sent, otherwise backs off exponentially (2s, 4s, ... capped at 60s). Default: 5.

.EXAMPLE
$token = Read-Host -AsSecureString -Prompt 'API token'
./alert-storm-mssp.ps1 -Server https://usea1-123.sentinelone.net -ApiToken $token -FileHash <sha1-or-sha256>

.EXAMPLE
$token = Read-Host -AsSecureString -Prompt 'API token'
./alert-storm-mssp.ps1 -Server https://usea1-123.sentinelone.net -ApiToken $token -FileHash <hash1>,<hash2>,<hash3>

.EXAMPLE
# From a shell, use -Command (pwsh -File cannot pass an array).
pwsh -Command "./alert-storm-mssp.ps1 -Server https://usea1-123.sentinelone.net -FileHash <hash1>,<hash2>"
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^https://')]
    [string]$Server,

    [Parameter(Mandatory = $true)]
    [securestring]$ApiToken,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$')]
    [string[]]$FileHash,

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
    [int]$BatchDelaySeconds = 1,

    [ValidateRange(0, 10)]
    [int]$MaxRetries = 5
)

$Server = $Server.TrimEnd('/')
$ThreatAnalystVerdict = $ThreatAnalystVerdict.ToLowerInvariant()
$AlertAnalystVerdict = $AlertAnalystVerdict.ToLowerInvariant()

# Lowercase and dedupe (Select-Object -Unique is case-sensitive).
$FileHash = @($FileHash | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)

# GET /threats allows 10 requests per second per token; keep lookup requests at least this far apart.
$LookupMinIntervalMs = 150
# GET /threats takes the hashes in the URL; keep the hash list per request short enough for common proxy URL limits (~8 KB). More hashes than fit are looked up in several requests that feed the same single batch.
$LookupMaxHashParamChars = 3500
# Longest we will wait on a single 429, even if Retry-After asks for more.
$RateLimitMaxWaitSeconds = 300

# Run totals, reported in the final summary
$script:ThreatsFound = 0
$script:ThreatsUnquarantined = 0
$script:ThreatsResolved = 0
$script:AlertsResolved = 0
$script:FailedChunks = 0
$script:LookupFailed = $false

# Console release (e.g. S-26.3.4) from GET /system/info; $null if it could not be read. Available for gating features by version.
$script:ConsoleRelease = $null

# ================= INTERNAL HELPERS ====================

function Get-HashFilterKeyForAlerts {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Hash
    )

    switch ($Hash.Length) {
        40 {
            return "sourceProcessFileHashSha1__contains" 
        }     # SHA1
        64 {
            return "sourceProcessFileHashSha256__contains" 
        }   # SHA256
        default {
            throw "Unsupported hash length ($($Hash.Length)); expected SHA1 (40) or SHA256 (64)." 
        }
    }
}

# Groups hashes by the alerts filter field they belong under (SHA1 vs SHA256), since the alerts endpoint has to be told which field to match on but can match a whole list of hashes of that type in one call.
function Group-HashesByAlertFilterKey {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Hashes
    )

    $groups = [ordered]@{}
    foreach ($h in $Hashes) {
        $key = Get-HashFilterKeyForAlerts -Hash $h
        if (-not $groups.Contains($key)) {
            $groups[$key] = [System.Collections.Generic.List[string]]::new()
        }
        $groups[$key].Add($h)
    }
    return $groups
}

# NetworkCredential converts a SecureString to plaintext on Windows PowerShell 5.1 and PowerShell 7+ on every OS.
$PlainToken = [System.Net.NetworkCredential]::new('', $ApiToken).Password
$Headers = @{
    "Authorization" = "ApiToken $PlainToken"
}
$PlainToken = $null

# ================= API CALLS (429 HANDLING) ============

function Get-HttpStatusCode {
    param($ErrorRecord)

    # HttpResponseMessage (PowerShell 7+) and HttpWebResponse (Windows PowerShell 5.1) both expose StatusCode.
    $response = $ErrorRecord.Exception.Response
    if ($response -and $null -ne $response.StatusCode) {
        return [int]$response.StatusCode
    }
    return $null
}

# Seconds from a Retry-After header (delta-seconds or HTTP date), or $null if absent or unparseable.
function Get-RetryAfterSeconds {
    param($ErrorRecord)

    $response = $ErrorRecord.Exception.Response
    $value = $null
    try {
        if ($response.Headers -is [System.Net.Http.Headers.HttpHeaders]) {
            $values = $null
            if ($response.Headers.TryGetValues('Retry-After', [ref]$values)) {
                $value = @($values)[0]
            }
        }
        elseif ($response.Headers) {
            $value = $response.Headers['Retry-After']
        }
    }
    catch {
        return $null
    }

    if ($value -match '^\s*\d+\s*$') {
        return [int]$value
    }
    $date = [datetime]::MinValue
    if ($value -and [datetime]::TryParse([string]$value, [ref]$date)) {
        return [math]::Max(0, [int][math]::Ceiling(($date.ToUniversalTime() - [datetime]::UtcNow).TotalSeconds))
    }
    return $null
}

# Invoke-RestMethod that waits and retries on HTTP 429, up to $MaxRetries times. Other errors, and 429s that outlast the retries, are thrown to the caller.
function Invoke-S1Api {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [ValidateSet('Get', 'Post')]
        [string]$Method = 'Get',
        [string]$Body
    )

    $attempt = 0
    while ($true) {
        try {
            if ($Method -eq 'Post') {
                return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Post -ContentType "application/json" `
                    -Body $Body -ErrorAction Stop
            }
            return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get -ErrorAction Stop
        }
        catch {
            if ((Get-HttpStatusCode $_) -ne 429) {
                throw 
            }

            $attempt++
            if ($attempt -gt $MaxRetries) {
                throw "Rate limited (HTTP 429) on $Method $Uri after $MaxRetries retries: $($_.Exception.Message)"
            }

            $wait = Get-RetryAfterSeconds $_
            if ($null -eq $wait) {
                $wait = [math]::Min([math]::Pow(2, $attempt), 60)
            }
            $wait = [math]::Min($wait, $RateLimitMaxWaitSeconds)
            Write-Warning "Rate limited (HTTP 429) on $Method $Uri; waiting ${wait}s before retry $attempt/$MaxRetries."
            Start-Sleep -Seconds $wait
        }
    }
}

# Returns data.release from GET /system/info, or $null (with a warning) if the call fails. Never stops the run.
function Get-ConsoleRelease {
    try {
        $response = Invoke-S1Api -Uri "$Server/web/api/v2.1/system/info"
        if ($response -and $response.data -and $response.data.release) {
            return [string]$response.data.release
        }
    }
    catch {
        Write-Warning "Could not read console version from /system/info: $($_.Exception.Message)"
    }
    return $null
}

function Get-AffectedCount {
    param($Response)

    if ($Response -and $Response.data -and $null -ne $Response.data.affected) {
        return [int]$Response.data.affected
    }
    return 0
}

# ================= THREATS LOOKUP ======================

# Splits hashes into lists whose comma-joined length stays within $MaxChars, so each lookup URL stays short.
function Split-HashesForLookup {
    param(
        [string[]]$Hashes,
        [int]$MaxChars
    )

    $batches = [System.Collections.Generic.List[string[]]]::new()
    $current = [System.Collections.Generic.List[string]]::new()
    $length = 0
    foreach ($h in $Hashes) {
        if ($current.Count -gt 0 -and ($length + 1 + $h.Length) -gt $MaxChars) {
            $batches.Add($current.ToArray())
            $current.Clear()
            $length = 0
        }
        $length += $h.Length + $(if ($current.Count -gt 0) { 1 } else { 0 })
        $current.Add($h)
    }
    if ($current.Count -gt 0) {
        $batches.Add($current.ToArray())
    }
    return , $batches.ToArray()
}

# Pages through GET /threats (contentHashes takes the whole list of hashes in one call) and writes only the threat ids to $SpoolPath, one per line. Returns the number of ids written. Page objects are discarded after each page.
function Export-ThreatIdsByHashes {
    param(
        [string[]]$Hashes,
        [string]$SpoolPath
    )

    $endpoint = "$Server/web/api/v2.1/threats"
    $hashBatches = Split-HashesForLookup -Hashes $Hashes -MaxChars $LookupMaxHashParamChars
    $count = 0
    $page = 0

    $lastRequest = $null
    $writer = [System.IO.StreamWriter]::new($SpoolPath, $false)
    try {
        foreach ($hashBatch in $hashBatches) {
            $contentHashesParam = $hashBatch -join ','
            $cursor = $null
            do {
                $page++
                # Keep request starts at least $LookupMinIntervalMs apart (GET /threats: 10 requests/second per token), across all hash batches.
                if ($lastRequest) {
                    $wait = $LookupMinIntervalMs - [int]$lastRequest.ElapsedMilliseconds
                    if ($wait -gt 0) {
                        Start-Sleep -Milliseconds $wait
                    }
                }
                $lastRequest = [System.Diagnostics.Stopwatch]::StartNew()
                $uri = "${endpoint}?limit=$ThreatsPageSize&contentHashes=$contentHashesParam&incidentStatuses=unresolved"
                if ($cursor) {
                    $uri += "&cursor=$([uri]::EscapeDataString($cursor))"
                }

                $response = Invoke-S1Api -Uri $uri -Method Get

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
            if ($line) {
                $chunk.Add($line) 
            }
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
            $response = Invoke-S1Api -Uri "$Server/web/api/v2.1/threats/mitigate/un-quarantine" -Method Post -Body $body
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
        $response = Invoke-S1Api -Uri "$Server/web/api/v2.1/threats/incident" -Method Post -Body $body
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

function Resolve-CloudDetectionAlertsByHashes {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HashFilterKey,
        [Parameter(Mandatory = $true)]
        [string[]]$Hashes
    )

    $verdictEndpoint = "$Server/web/api/v2.1/cloud-detection/alerts/analyst-verdict"
    $incidentEndpoint = "$Server/web/api/v2.1/cloud-detection/alerts/incident"

    $batch = 0
    $groupAlertsResolved = 0

    while ($true) {
        $batch++

        # Filter unresolved STAR alerts whose source-process file hash matches any of $Hashes
        $filter = @{
            limit          = $AlertsBatchLimit
            incidentStatus = "UNRESOLVED"
        }
        $filter[$HashFilterKey] = @($Hashes)

        # The verdict goes through its own endpoint and must be set first, while the alerts still match UNRESOLVED.
        $verdictBody = @{
            filter = $filter
            data   = @{ analystVerdict = $AlertAnalystVerdict }
        } | ConvertTo-Json -Depth 5

        $incidentBody = @{
            filter = $filter
            data   = @{ incidentStatus = "resolved" }
        } | ConvertTo-Json -Depth 5

        Write-Host "[-] Alerts batch #${batch}: resolving STAR alerts for $($Hashes.Count) hash(es) using filter '$HashFilterKey' ..." -ForegroundColor Cyan

        try {
            Invoke-S1Api -Uri $verdictEndpoint -Method Post -Body $verdictBody | Out-Null

            $response = Invoke-S1Api -Uri $incidentEndpoint -Method Post -Body $incidentBody
        }
        catch {
            Write-Error "Error resolving STAR alerts: $($_.Exception.Message)" -ErrorAction Continue
            $script:FailedChunks++
            break
        }

        $affected = Get-AffectedCount $response
        Write-Host "[+] Alerts batch #$batch affected: $affected"

        $script:AlertsResolved += $affected
        $groupAlertsResolved += $affected

        if ($affected -lt $AlertsBatchLimit -or $affected -eq 0) {
            break
        }

        Start-Sleep -Seconds $BatchDelaySeconds
    }

    Write-Host "[=] Total STAR alerts resolved for filter '${HashFilterKey}' ($($Hashes.Count) hash(es)): $groupAlertsResolved" -ForegroundColor Green
}

# ===================== MAIN ============================

Write-Host "=== SentinelOne hash workflow: $($FileHash.Count) hash(es) ===" -ForegroundColor Yellow
Write-Host "Console: $Server"
$script:ConsoleRelease = Get-ConsoleRelease
if ($script:ConsoleRelease) {
    Write-Host "Console release: $($script:ConsoleRelease)"
}
else {
    Write-Host "Console release: unknown" -ForegroundColor Yellow
}
Write-Host "Hashes:  $($FileHash -join ', ')"
Write-Host ""

# ---- Threats: look up ids for ALL hashes at once, ask about unquarantine once, then act ----
$spoolPath = [System.IO.Path]::GetTempFileName()
try {
    try {
        $script:ThreatsFound = Export-ThreatIdsByHashes -Hashes $FileHash -SpoolPath $spoolPath
    }
    catch {
        Write-Error "Threat lookup failed: $($_.Exception.Message)" -ErrorAction Continue
        $script:LookupFailed = $true
    }

    if (-not $script:LookupFailed) {
        Write-Host "[=] Found $($script:ThreatsFound) unresolved threats across $($FileHash.Count) hash(es)" -ForegroundColor Green

        if ($script:ThreatsFound -eq 0) {
            Write-Host "[=] No threats to resolve, skipping threats step." -ForegroundColor Yellow
        }
        else {
            # BIG RED PROMPT: ASK ABOUT UNQUARANTINE (once, for all hashes together)
            Write-Host "**********************************************************************" -ForegroundColor Red
            Write-Host "YOU ARE ABOUT TO RESOLVE $($script:ThreatsFound) THREATS & ALERTS FOR $($FileHash.Count) HASH(ES): $($FileHash -join ', ')" -ForegroundColor Red
            Write-Host "Optionally, you can also UNQUARANTINE any files associated with these" -ForegroundColor Red
            Write-Host "hashes BEFORE resolving the incidents (equivalent to Threats > Unquarantine)." -ForegroundColor Red
            Write-Host "**********************************************************************" -ForegroundColor Red

            $unqChoice = Read-Host "Do you want to send UNQUARANTINE commands for these hashes first? (Y/N)"
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

            Write-Host "[=] Total threat incidents resolved: $($script:ThreatsResolved)" -ForegroundColor Green
        }
    }
}
finally {
    Remove-Item -LiteralPath $spoolPath -Force -ErrorAction SilentlyContinue
}

# ---- Alerts: resolved per hash algorithm (SHA1 / SHA256), each call covering every hash of that type ----
Write-Host ""
$hashGroups = Group-HashesByAlertFilterKey -Hashes $FileHash
foreach ($hashFilterKey in $hashGroups.Keys) {
    Resolve-CloudDetectionAlertsByHashes -HashFilterKey $hashFilterKey -Hashes $hashGroups[$hashFilterKey]
}

# ---- Summary ----
Write-Host ""
Write-Host "=== Summary for $($FileHash.Count) hash(es): $($FileHash -join ', ') ===" -ForegroundColor Yellow
Write-Host "Threats found:          $($script:ThreatsFound)"
Write-Host "Threats unquarantined:  $($script:ThreatsUnquarantined)"
Write-Host "Threats resolved:       $($script:ThreatsResolved)"
Write-Host "Alerts resolved:        $($script:AlertsResolved)"
Write-Host "Failed chunks:          $($script:FailedChunks)"
if ($script:LookupFailed) {
    Write-Host "Threat lookup:          FAILED" -ForegroundColor Red
}
if ($script:ThreatsFound -eq 0 -and $script:AlertsResolved -eq 0 -and -not $script:LookupFailed -and $script:FailedChunks -eq 0) {
    Write-Host "Nothing matched any of the supplied hashes (no unresolved threats or alerts)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Yellow

if ($script:LookupFailed -or $script:FailedChunks -gt 0) {
    exit 1
}
exit 0
