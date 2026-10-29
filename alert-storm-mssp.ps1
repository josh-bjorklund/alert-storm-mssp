<#
.SYNOPSIS
Detection and alert resolver v2.1 - Josh Bjorklund (MSSP edition: no site IDs needed).

.DESCRIPTION
Resolves the threats and STAR alerts for one or more file hashes, optionally un-quarantining the threats first. All hashes are handled as one batch, with one un-quarantine prompt.

Threats are looked up with GET /threats and only their ids are sent to the un-quarantine and resolve endpoints, which works around /threats/incident ignoring its limit. The ids are spooled to a temporary file, so memory stays flat. STAR alerts are resolved per hash type (SHA1 or SHA256). HTTP 429 and 500 responses are retried (500 with smaller batches).

Exit code: 0 on success (including nothing matched), 1 if any chunk or the lookup failed.

.PARAMETER Server
Console base URL, e.g. https://usea1-123.sentinelone.net.

.PARAMETER ApiToken
API token, as a SecureString.

.PARAMETER FileHash
One or more SHA1 or SHA256 hashes. Pass an array (-FileHash hash1,hash2); pwsh -File can't. Hashes are lowercased and deduplicated.

.PARAMETER ThreatAnalystVerdict
Verdict applied to resolved threats: undefined, true_positive, false_positive or suspicious. Default: false_positive.

.PARAMETER AlertAnalystVerdict
Verdict applied to resolved STAR alerts (same values). Default: false_positive.

.PARAMETER ThreatsPageSize
Page size of the threat lookup (1-1000). Default: 1000.

.PARAMETER ThreatsBatchLimit
Threat ids per un-quarantine/resolve call (1-5000). Default: 5000.

.PARAMETER AlertsBatchLimit
Alerts per call (1-5000). Default: 500.

.PARAMETER BatchDelaySeconds
Pause between batches (0-3600). Default: 1.

.PARAMETER MaxRetries
Retries on HTTP 429 (waits for Retry-After, else backs off) and HTTP 500 (the first retry keeps the batch size, later ones shrink it), 0-10. Default: 5.

.PARAMETER LogPath
Structured (logfmt) log, appended and tagged with a run_id; the token is masked. Default: ./alert-storm-mssp.log. The run stops if it can't be written.

.NOTES
Required RBAC permissions: see "Required permissions" in README.md. create-role.ps1 creates a role with them.

.EXAMPLE
$token = Read-Host -AsSecureString -Prompt 'API token'
./alert-storm-mssp.ps1 -Server https://usea1-123.sentinelone.net -ApiToken $token -FileHash <sha1-or-sha256>

.EXAMPLE
./alert-storm-mssp.ps1 -Server https://usea1-123.sentinelone.net -ApiToken $token -FileHash <hash1>,<hash2>,<hash3>

.EXAMPLE
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
    [int]$MaxRetries = 5,

    [string]$LogPath = './alert-storm-mssp.log'
)

$Server = $Server.TrimEnd('/')
$ThreatAnalystVerdict = $ThreatAnalystVerdict.ToLowerInvariant()
$AlertAnalystVerdict = $AlertAnalystVerdict.ToLowerInvariant()

# Lowercase and dedupe (Select-Object -Unique is case-sensitive).
$FileHash = @($FileHash | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)

$script:RunId = [guid]::NewGuid().ToString('N').Substring(0, 12)
$script:RunTimer = [System.Diagnostics.Stopwatch]::StartNew()
$script:LogEnabled = $false
$script:LogFile = $null

# GET /threats allows 10 requests per second per token; keep lookup requests at least this far apart.
$LookupMinIntervalMs = 150
# GET /threats takes the hashes in the URL; keep the hash list per request short enough for common proxy URL limits (~8 KB). More hashes than fit are looked up in several requests that feed the same single batch.
$LookupMaxHashParamChars = 3500
# On HTTP 500, the first reduction shrinks the batch by this many items; each further consecutive reduction doubles the step (100, 200, 400, ...). The step starts over after a success.
$BatchReductionStep = 100
# Longest we will wait on a single 429, even if Retry-After asks for more.
$RateLimitMaxWaitSeconds = 300

# Run totals, reported in the final summary
$script:ThreatsFound = 0
$script:ThreatsUnquarantined = 0
$script:ThreatsResolved = 0
$script:AlertsResolved = 0
$script:FailedChunks = 0
$script:ThreatsUnprocessed = 0
# What the lookup saw, for the log: the API's own total (summed over each hash batch's first page) and counts by incident/mitigation status.
$script:LookupStats = @{ ApiTotalItems = 0; Incident = @{}; Mitigation = @{} }
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

# ================= LOGGING (logfmt) ====================

# One event per line as key=value pairs (logfmt, the same shape as structlog's key-value renderer). Values with spaces, quotes or '=' are double-quoted with \ and \" escaped. Logging problems never stop the run once it has started.
function ConvertTo-LogfmtValue {
    param($Value)

    if ($null -eq $Value) {
        return '""'
    }
    if ($Value -is [bool]) {
        return $Value.ToString().ToLowerInvariant()
    }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        return [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $Value)
    }
    $text = [string]$Value
    if ($text -match '^[A-Za-z0-9_.:/@+*\-]+$') {
        return $text
    }
    $text = $text.Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n')
    return '"' + $text + '"'
}

function Write-Log {
    param(
        [ValidateSet('info', 'warn', 'error')]
        [string]$Level,
        [string]$EventName,
        [System.Collections.IDictionary]$Fields
    )

    if (-not $script:LogEnabled) {
        return
    }

    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add('ts=' + [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))
    $parts.Add("level=$Level")
    $parts.Add("run_id=$($script:RunId)")
    $parts.Add('event=' + (ConvertTo-LogfmtValue $EventName))
    if ($Fields) {
        foreach ($key in $Fields.Keys) {
            $parts.Add("$key=" + (ConvertTo-LogfmtValue $Fields[$key]))
        }
    }

    try {
        [System.IO.File]::AppendAllText($script:LogFile, ($parts -join ' ') + "`n", [System.Text.UTF8Encoding]::new($false))
    }
    catch {
        $script:LogEnabled = $false
        Write-Warning "Logging to '$($script:LogFile)' failed and is now disabled for this run: $($_.Exception.Message)"
    }
}

# Resolves the log path against the PowerShell location, creates its folder, and proves it is writable. Throws if not, so a run never starts unlogged.
function Initialize-Log {
    param([string]$Path)

    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $dir = [System.IO.Path]::GetDirectoryName($full)
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        [void](New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop)
    }
    [System.IO.File]::AppendAllText($full, '', [System.Text.UTF8Encoding]::new($false))
    $script:LogFile = $full
    $script:LogEnabled = $true
}

# First 10 and last 10 characters with ***** between, e.g. eyJraWQiOi*****Y4HWg8hF3g. A token shorter than 40 characters is masked entirely.
function Get-MaskedToken {
    param([string]$Token)

    if ($Token.Length -lt 40) {
        return '*****'
    }
    return $Token.Substring(0, 10) + '*****' + $Token.Substring($Token.Length - 10)
}

# One red line per error, in the same style as the [-] / [+] / [=] progress lines. Write-Error prints a multi-line block that repeats the call site, which buries the message.
function Write-ErrorLine {
    param([string]$Message)

    Write-Host "[!] $Message" -ForegroundColor Red
}

# NetworkCredential converts a SecureString to plaintext on Windows PowerShell 5.1 and PowerShell 7+ on every OS.
$PlainToken = [System.Net.NetworkCredential]::new('', $ApiToken).Password
$Headers = @{
    "Authorization" = "ApiToken $PlainToken"
}
$MaskedToken = Get-MaskedToken $PlainToken
$PlainToken = $null

Initialize-Log -Path $LogPath

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

# Invoke-RestMethod that waits and retries on HTTP 429, up to $MaxRetries times. Other errors, and 429s that outlast the retries, are thrown to the caller. Every attempt is logged (event=api_attempt). -Operation, -BatchSize (items requested) and -SizeRetry (the caller's 500-retry count) are only used for the log.
function Invoke-S1Api {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [ValidateSet('Get', 'Post')]
        [string]$Method = 'Get',
        [string]$Body,
        [string]$Operation = 'api_call',
        [int]$BatchSize = 0,
        [int]$SizeRetry = 0
    )

    $path = ([uri]$Uri).AbsolutePath
    $attempt = 0
    while ($true) {
        $attempt++
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            if ($Method -eq 'Post') {
                $response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Post -ContentType "application/json" `
                    -Body $Body -ErrorAction Stop
            }
            else {
                $response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get -ErrorAction Stop
            }
            $timer.Stop()

            $fields = [ordered]@{
                operation   = $Operation
                method      = $Method.ToUpperInvariant()
                endpoint    = $path
                batch_size  = $BatchSize
                size_retry  = $SizeRetry
                attempt     = $attempt
                outcome     = 'ok'
                duration_ms = [int]$timer.ElapsedMilliseconds
            }
            if ($Method -eq 'Post') {
                $fields['affected'] = Get-AffectedCount $response
            }
            elseif ($response -and $response.data -is [array]) {
                $fields['returned'] = $response.data.Count
            }
            Write-Log info api_attempt $fields
            return $response
        }
        catch {
            $timer.Stop()
            $status = Get-HttpStatusCode $_
            $outcome = switch ($status) {
                429 { 'rate_limited' }
                500 { 'server_error' }
                default { 'error' }
            }
            $fields = [ordered]@{
                operation   = $Operation
                method      = $Method.ToUpperInvariant()
                endpoint    = $path
                batch_size  = $BatchSize
                size_retry  = $SizeRetry
                attempt     = $attempt
                outcome     = $outcome
                duration_ms = [int]$timer.ElapsedMilliseconds
            }
            if ($null -ne $status) {
                $fields['http_status'] = $status
            }
            $errorText = [string]$_.Exception.Message
            $fields['error'] = $errorText.Substring(0, [math]::Min(300, $errorText.Length))
            Write-Log $(if ($outcome -eq 'error') { 'error' } else { 'warn' }) api_attempt $fields

            if ($status -ne 429) {
                throw
            }

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
        $response = Invoke-S1Api -Uri "$Server/web/api/v2.1/system/info" -Operation system_info
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

# Adds incident_<status> and mitigation_<status> counts to a log field set. The known statuses are always present (as 0 when unseen) so lines have a stable shape; anything else the API returns is added as it appears.
function Add-StatusFields {
    param(
        [System.Collections.IDictionary]$Fields,
        [hashtable]$Incident,
        [hashtable]$Mitigation
    )

    foreach ($k in 'unresolved', 'in_progress', 'resolved') {
        $Fields["incident_$k"] = [int]$Incident[$k]
    }
    foreach ($k in @($Incident.Keys) | Where-Object { $_ -notin 'unresolved', 'in_progress', 'resolved' } | Sort-Object) {
        $Fields["incident_$k"] = [int]$Incident[$k]
    }
    foreach ($k in 'not_mitigated', 'mitigated', 'marked_as_benign') {
        $Fields["mitigation_$k"] = [int]$Mitigation[$k]
    }
    foreach ($k in @($Mitigation.Keys) | Where-Object { $_ -notin 'not_mitigated', 'mitigated', 'marked_as_benign' } | Sort-Object) {
        $Fields["mitigation_$k"] = [int]$Mitigation[$k]
    }
}

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

# Pages through GET /threats (contentHashes takes the whole list of hashes in one call) and writes only the threat ids to $SpoolPath, one per line. Returns the number of ids written. Page objects are discarded after each page. On HTTP 500 the same page is retried with a smaller page size; a page is only consumed once it succeeds, so no ids are skipped.
function Export-ThreatIdsByHashes {
    param(
        [string[]]$Hashes,
        [string]$SpoolPath
    )

    $endpoint = "$Server/web/api/v2.1/threats"
    $hashBatches = Split-HashesForLookup -Hashes $Hashes -MaxChars $LookupMaxHashParamChars
    $count = 0
    $page = 0
    $pageSize = $ThreatsPageSize
    $serverErrors = 0
    $retriedSameSize = $false
    $reductions = 0

    $lastRequest = $null
    $writer = [System.IO.StreamWriter]::new($SpoolPath, $false)
    try {
        foreach ($hashBatch in $hashBatches) {
            $contentHashesParam = $hashBatch -join ','
            $cursor = $null
            do {
                $page++
                $firstPageOfBatch = -not $cursor
                $response = $null
                $succeeded = $false
                while (-not $succeeded) {
                    # Keep request starts at least $LookupMinIntervalMs apart (GET /threats: 10 requests/second per token), across all hash batches and retries.
                    if ($lastRequest) {
                        $wait = $LookupMinIntervalMs - [int]$lastRequest.ElapsedMilliseconds
                        if ($wait -gt 0) {
                            Start-Sleep -Milliseconds $wait
                        }
                    }
                    $lastRequest = [System.Diagnostics.Stopwatch]::StartNew()
                    $uri = "${endpoint}?limit=$pageSize&contentHashes=$contentHashesParam&incidentStatusesNin=resolved"
                    if ($cursor) {
                        $uri += "&cursor=$([uri]::EscapeDataString($cursor))"
                    }

                    try {
                        $response = Invoke-S1Api -Uri $uri -Method Get -Operation threat_lookup -BatchSize $pageSize -SizeRetry $serverErrors
                        $succeeded = $true
                        $serverErrors = 0
                        $retriedSameSize = $false
                        $reductions = 0
                    }
                    catch {
                        if ((Get-HttpStatusCode $_) -ne 500) {
                            throw
                        }
                        $serverErrors++
                        if ($serverErrors -gt $MaxRetries) {
                            Write-Log error retries_exhausted ([ordered]@{ operation = 'threat_lookup'; batch_size = $pageSize; retries = $MaxRetries })
                            throw "Server error (HTTP 500) on threat lookup after $MaxRetries retries (page size reduced to $pageSize): $($_.Exception.Message)"
                        }
                        if (-not $retriedSameSize) {
                            # A 500 may be transient, so the first retry keeps the size; only a second consecutive 500 shrinks it.
                            $retriedSameSize = $true
                            Write-Log warn retry_same_size ([ordered]@{ operation = 'threat_lookup'; batch_size = $pageSize; retry = $serverErrors; max_retries = $MaxRetries })
                            Write-Warning "Server error (HTTP 500) on threat lookup; retrying the same page at the same page size $pageSize (retry $serverErrors/$MaxRetries)."
                        }
                        else {
                            $previousSize = $pageSize
                            $step = $BatchReductionStep * [int][math]::Pow(2, $reductions)
                            $reductions++
                            $pageSize = [math]::Max(1, $pageSize - $step)
                            Write-Log warn batch_size_reduced ([ordered]@{ operation = 'threat_lookup'; from = $previousSize; to = $pageSize; step = $step; retry = $serverErrors; max_retries = $MaxRetries })
                            Write-Warning "Server error (HTTP 500) on threat lookup; retrying the same page with page size $pageSize (retry $serverErrors/$MaxRetries)."
                        }
                        Start-Sleep -Seconds $BatchDelaySeconds
                    }
                }

                $pageIncident = @{}
                $pageMitigation = @{}
                $pageReturned = 0
                foreach ($threat in @($response.data)) {
                    if ($threat.id) {
                        $writer.WriteLine([string]$threat.id)
                        $count++
                        $pageReturned++
                        $incidentStatus = if ($threat.threatInfo.incidentStatus) { [string]$threat.threatInfo.incidentStatus } else { 'unknown' }
                        $mitigationStatus = if ($threat.threatInfo.mitigationStatus) { [string]$threat.threatInfo.mitigationStatus } else { 'unknown' }
                        $pageIncident[$incidentStatus]++
                        $pageMitigation[$mitigationStatus]++
                        $script:LookupStats.Incident[$incidentStatus]++
                        $script:LookupStats.Mitigation[$mitigationStatus]++
                    }
                }
                $apiTotal = $response.pagination.totalItems
                if ($firstPageOfBatch -and $null -ne $apiTotal) {
                    $script:LookupStats.ApiTotalItems += [int]$apiTotal
                }
                $pageFields = [ordered]@{ page = $page; returned = $pageReturned; ids_so_far = $count }
                # The API only reports totalItems on a batch's first page (later cursor pages return 0), so log it only there.
                if ($firstPageOfBatch -and $null -ne $apiTotal) {
                    $pageFields['total_items'] = [int]$apiTotal
                }
                Add-StatusFields -Fields $pageFields -Incident $pageIncident -Mitigation $pageMitigation
                Write-Log info lookup_page $pageFields

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

# ================= THREATS (UN-QUARANTINE + RESOLVE) ===

# Sends one chunk of threat ids: un-quarantine (if requested and not already done for these ids), then resolve. Returns @{ Status = 'ok' | 'failed' | 'server-error'; Unquarantined = <bool> }. 'server-error' (HTTP 500) means the ids were NOT processed and the caller should retry with fewer; 'failed' is any other error.
function Send-ThreatIdChunk {
    param(
        [string[]]$Ids,
        [int]$ChunkNumber,
        [bool]$Unquarantine,
        [bool]$AlreadyUnquarantined,
        [int]$SizeRetry = 0
    )

    $result = @{ Status = 'ok'; Unquarantined = $AlreadyUnquarantined }

    if ($Unquarantine -and -not $AlreadyUnquarantined) {
        $body = @{ filter = @{ ids = $Ids } } | ConvertTo-Json -Depth 5
        Write-Host "[-] Chunk ${ChunkNumber}: sending unquarantine for $($Ids.Count) threats ..." -ForegroundColor Yellow
        try {
            $response = Invoke-S1Api -Uri "$Server/web/api/v2.1/threats/mitigate/un-quarantine" -Method Post -Body $body -Operation threat_unquarantine -BatchSize $Ids.Count -SizeRetry $SizeRetry
            $script:ThreatsUnquarantined += Get-AffectedCount $response
            $result.Unquarantined = $true
        }
        catch {
            if ((Get-HttpStatusCode $_) -eq 500) {
                Write-Warning "Chunk ${ChunkNumber}: server error (HTTP 500) on unquarantine of $($Ids.Count) threats: $($_.Exception.Message)"
                $result.Status = 'server-error'
            }
            else {
                # Leave the chunk unresolved so a re-run picks it up and its files are not resolved while still quarantined.
                Write-ErrorLine "Chunk ${ChunkNumber}: unquarantine failed, chunk skipped: $($_.Exception.Message)"
                $result.Status = 'failed'
            }
            return $result
        }
    }

    $body = @{
        filter = @{ ids = $Ids }
        data   = @{
            incidentStatus = "resolved"
            analystVerdict = $ThreatAnalystVerdict
        }
    } | ConvertTo-Json -Depth 5

    Write-Host "[-] Chunk ${ChunkNumber}: resolving $($Ids.Count) threat incidents ..." -ForegroundColor Cyan
    try {
        $response = Invoke-S1Api -Uri "$Server/web/api/v2.1/threats/incident" -Method Post -Body $body -Operation threat_resolve -BatchSize $Ids.Count -SizeRetry $SizeRetry
        $affected = Get-AffectedCount $response
        $script:ThreatsResolved += $affected
        Write-Host "[+] Chunk $ChunkNumber affected: $affected"
    }
    catch {
        if ((Get-HttpStatusCode $_) -eq 500) {
            Write-Warning "Chunk ${ChunkNumber}: server error (HTTP 500) resolving $($Ids.Count) threat incidents: $($_.Exception.Message)"
            $result.Status = 'server-error'
        }
        else {
            Write-ErrorLine "Chunk ${ChunkNumber}: error resolving threat incidents: $($_.Exception.Message)"
            $result.Status = 'failed'
        }
    }
    return $result
}

# Streams $SpoolPath through Send-ThreatIdChunk in chunks of $ThreatsBatchLimit ids. On HTTP 500 the same ids are retried in a smaller chunk (reduced by $BatchReductionStep each time, never below 1) and nothing is dropped: ids stay in $pending until their chunk succeeds. The retry count resets on success; the reduced size is kept. After $MaxRetries consecutive 500s the step stops and the remaining ids are left unresolved (and counted).
function Resolve-ThreatIdsFromSpool {
    param(
        [string]$SpoolPath,
        [bool]$Unquarantine
    )

    $size = $ThreatsBatchLimit
    $serverErrors = 0
    $retriedSameSize = $false
    $reductions = 0
    $chunkNumber = 0
    $removed = 0                # ids taken off $pending, whether they succeeded or failed
    $unquarantinedAhead = 0     # leading ids in $pending already un-quarantined (their resolve hit a 500), so a retry does not repeat it
    $pending = [System.Collections.Generic.List[string]]::new()

    $reader = [System.IO.StreamReader]::new($SpoolPath)
    try {
        while ($true) {
            while ($pending.Count -lt $size -and $null -ne ($line = $reader.ReadLine())) {
                if ($line) {
                    $pending.Add($line)
                }
            }
            if ($pending.Count -eq 0) {
                break
            }

            $take = [math]::Min($size, $pending.Count)
            $ids = $pending.GetRange(0, $take).ToArray()
            $chunkNumber++
            $result = Send-ThreatIdChunk -Ids $ids -ChunkNumber $chunkNumber -Unquarantine $Unquarantine -AlreadyUnquarantined ($unquarantinedAhead -ge $take) -SizeRetry $serverErrors

            switch ($result.Status) {
                'ok' {
                    $pending.RemoveRange(0, $take)
                    $removed += $take
                    $unquarantinedAhead = [math]::Max(0, $unquarantinedAhead - $take)
                    $serverErrors = 0
                    $retriedSameSize = $false
                    $reductions = 0
                    if ($pending.Count -gt 0 -or $reader.Peek() -ge 0) {
                        Start-Sleep -Seconds $BatchDelaySeconds
                    }
                }
                'failed' {
                    $pending.RemoveRange(0, $take)
                    $removed += $take
                    $unquarantinedAhead = [math]::Max(0, $unquarantinedAhead - $take)
                    $script:FailedChunks++
                    $script:ThreatsUnprocessed += $take
                }
                'server-error' {
                    if ($Unquarantine -and $result.Unquarantined) {
                        $unquarantinedAhead = [math]::Max($unquarantinedAhead, $take)
                    }
                    $serverErrors++
                    if ($serverErrors -gt $MaxRetries) {
                        $left = $script:ThreatsFound - $removed
                        Write-Log error retries_exhausted ([ordered]@{ operation = 'threat_resolve'; batch_size = $size; retries = $MaxRetries; unprocessed_ids = $left })
                        Write-ErrorLine "Server error (HTTP 500) persisted after $MaxRetries retries (chunk size reduced to $size). Stopping; $left threat ids were not processed and remain unresolved, so a re-run will pick them up."
                        $script:FailedChunks++
                        $script:ThreatsUnprocessed += $left
                        return
                    }
                    if (-not $retriedSameSize) {
                        # A 500 may be transient, so the first retry keeps the size; only a second consecutive 500 shrinks it.
                        $retriedSameSize = $true
                        Write-Log warn retry_same_size ([ordered]@{ operation = 'threat_resolve'; batch_size = $size; retry = $serverErrors; max_retries = $MaxRetries; pending_ids = $pending.Count })
                        Write-Warning "Retrying the same pending ids at the same chunk size $size (retry $serverErrors/$MaxRetries)."
                    }
                    else {
                        $previousSize = $size
                        $step = $BatchReductionStep * [int][math]::Pow(2, $reductions)
                        $reductions++
                        $size = [math]::Max(1, $size - $step)
                        Write-Log warn batch_size_reduced ([ordered]@{ operation = 'threat_resolve'; from = $previousSize; to = $size; step = $step; retry = $serverErrors; max_retries = $MaxRetries; pending_ids = $pending.Count })
                        Write-Warning "Retrying the same $($pending.Count) pending ids in chunks of up to $size (retry $serverErrors/$MaxRetries)."
                    }
                    Start-Sleep -Seconds $BatchDelaySeconds
                }
            }
        }
    }
    finally {
        $reader.Dispose()
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
    $limit = $AlertsBatchLimit
    $serverErrors = 0
    $retriedSameSize = $false
    $reductions = 0

    while ($true) {
        $batch++

        # Filter unresolved STAR alerts whose source-process file hash matches any of $Hashes
        $filter = @{
            limit          = $limit
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

        Write-Host "[-] Alerts batch #${batch}: resolving STAR alerts for $($Hashes.Count) hash(es) using filter '$HashFilterKey' (limit $limit) ..." -ForegroundColor Cyan

        try {
            Invoke-S1Api -Uri $verdictEndpoint -Method Post -Body $verdictBody -Operation alert_verdict -BatchSize $limit -SizeRetry $serverErrors | Out-Null

            $response = Invoke-S1Api -Uri $incidentEndpoint -Method Post -Body $incidentBody -Operation alert_resolve -BatchSize $limit -SizeRetry $serverErrors
        }
        catch {
            if ((Get-HttpStatusCode $_) -eq 500) {
                # The filter selects alerts server-side, so retrying with a smaller limit cannot skip any: whatever is still UNRESOLVED is picked up by the next call.
                $serverErrors++
                if ($serverErrors -gt $MaxRetries) {
                    Write-Log error retries_exhausted ([ordered]@{ operation = 'alert_resolve'; batch_size = $limit; retries = $MaxRetries; filter = $HashFilterKey })
                    Write-ErrorLine "Server error (HTTP 500) resolving STAR alerts persisted after $MaxRetries retries (limit reduced to $limit): $($_.Exception.Message)"
                    $script:FailedChunks++
                    break
                }
                if (-not $retriedSameSize) {
                    # A 500 may be transient, so the first retry keeps the limit; only a second consecutive 500 shrinks it.
                    $retriedSameSize = $true
                    Write-Log warn retry_same_size ([ordered]@{ operation = 'alert_resolve'; batch_size = $limit; retry = $serverErrors; max_retries = $MaxRetries; filter = $HashFilterKey })
                    Write-Warning "Server error (HTTP 500) resolving STAR alerts; retrying at the same limit $limit (retry $serverErrors/$MaxRetries)."
                }
                else {
                    $previousLimit = $limit
                    $step = $BatchReductionStep * [int][math]::Pow(2, $reductions)
                    $reductions++
                    $limit = [math]::Max(1, $limit - $step)
                    Write-Log warn batch_size_reduced ([ordered]@{ operation = 'alert_resolve'; from = $previousLimit; to = $limit; step = $step; retry = $serverErrors; max_retries = $MaxRetries; filter = $HashFilterKey })
                    Write-Warning "Server error (HTTP 500) resolving STAR alerts; retrying with limit $limit (retry $serverErrors/$MaxRetries)."
                }
                Start-Sleep -Seconds $BatchDelaySeconds
                $batch--
                continue
            }
            Write-ErrorLine "Error resolving STAR alerts: $($_.Exception.Message)"
            $script:FailedChunks++
            break
        }

        $serverErrors = 0
        $retriedSameSize = $false
        $reductions = 0
        $affected = Get-AffectedCount $response
        Write-Host "[+] Alerts batch #$batch affected: $affected"

        $script:AlertsResolved += $affected
        $groupAlertsResolved += $affected

        if ($affected -lt $limit -or $affected -eq 0) {
            break
        }

        Start-Sleep -Seconds $BatchDelaySeconds
    }

    Write-Host "[=] Total STAR alerts resolved for filter '${HashFilterKey}' ($($Hashes.Count) hash(es)): $groupAlertsResolved" -ForegroundColor Green
}

# ===================== MAIN ============================

Write-Log info run_start ([ordered]@{
        server                = ([uri]$Server).Host
        token                 = $MaskedToken
        hash_count            = $FileHash.Count
        hashes                = ($FileHash -join ',')
        threat_verdict        = $ThreatAnalystVerdict
        alert_verdict         = $AlertAnalystVerdict
        threats_page_size     = $ThreatsPageSize
        threats_batch_limit   = $ThreatsBatchLimit
        alerts_batch_limit    = $AlertsBatchLimit
        batch_delay_seconds   = $BatchDelaySeconds
        max_retries           = $MaxRetries
        powershell            = $PSVersionTable.PSVersion.ToString()
        os                    = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
        log_file              = $script:LogFile
    })

Write-Host "=== SentinelOne hash workflow: $($FileHash.Count) hash(es) ===" -ForegroundColor Yellow
Write-Host "Console: $Server"
Write-Host "Log:     $($script:LogFile) (run_id $($script:RunId))"
$script:ConsoleRelease = Get-ConsoleRelease
Write-Log info console_release ([ordered]@{ release = $(if ($script:ConsoleRelease) { $script:ConsoleRelease } else { 'unknown' }) })
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
        Write-ErrorLine "Threat lookup failed: $($_.Exception.Message)"
        Write-Log error lookup_failed ([ordered]@{ error = [string]$_.Exception.Message })
        $script:LookupFailed = $true
    }

    if (-not $script:LookupFailed) {
        Write-Host "[=] Found $($script:ThreatsFound) unresolved threats across $($FileHash.Count) hash(es)" -ForegroundColor Green
        $completeFields = [ordered]@{ threats_found = $script:ThreatsFound; api_total_items = $script:LookupStats.ApiTotalItems; hash_count = $FileHash.Count }
        Add-StatusFields -Fields $completeFields -Incident $script:LookupStats.Incident -Mitigation $script:LookupStats.Mitigation
        Write-Log info lookup_complete $completeFields

        if ($script:ThreatsFound -eq 0) {
            Write-Host "[=] No threats to resolve, skipping threats step." -ForegroundColor Yellow
        }
        else {
            # BIG YELLOW PROMPT (black on yellow, like a caution sign: stands out without implying an error): ASK ABOUT UNQUARANTINE (once, for all hashes together)
            Write-Host "**********************************************************************" -ForegroundColor Black -BackgroundColor Yellow
            Write-Host "YOU ARE ABOUT TO RESOLVE $($script:ThreatsFound) THREATS & ALERTS FOR $($FileHash.Count) HASH(ES): $($FileHash -join ', ')" -ForegroundColor Black -BackgroundColor Yellow
            Write-Host "Optionally, you can also UNQUARANTINE any files associated with these" -ForegroundColor Black -BackgroundColor Yellow
            Write-Host "hashes BEFORE resolving the incidents (equivalent to Threats > Unquarantine)." -ForegroundColor Black -BackgroundColor Yellow
            Write-Host "**********************************************************************" -ForegroundColor Black -BackgroundColor Yellow

            $unqChoice = Read-Host "Do you want to send UNQUARANTINE commands for these hashes first? (Y/N)"
            $unquarantine = $unqChoice -match '^(Y|y)$'
            Write-Log info operator_choice ([ordered]@{ unquarantine = [bool]$unquarantine })

            Write-Host ""
            if ($unquarantine) {
                Write-Host ">>> User chose to UNQUARANTINE files before resolving incidents..." -ForegroundColor Yellow
            }
            else {
                Write-Host ">>> Skipping unquarantine. Proceeding directly to resolve incidents..." -ForegroundColor Yellow
            }

            Resolve-ThreatIdsFromSpool -SpoolPath $spoolPath -Unquarantine $unquarantine

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
if ($script:ThreatsUnprocessed -gt 0) {
    Write-Host "Threat ids NOT resolved: $($script:ThreatsUnprocessed) (still unresolved; re-run to pick them up)" -ForegroundColor Red
}
if ($script:LookupFailed) {
    Write-Host "Threat lookup:          FAILED" -ForegroundColor Red
}
if ($script:ThreatsFound -eq 0 -and $script:AlertsResolved -eq 0 -and -not $script:LookupFailed -and $script:FailedChunks -eq 0) {
    Write-Host "Nothing matched any of the supplied hashes (no unresolved threats or alerts)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Yellow

$exitCode = if ($script:LookupFailed -or $script:FailedChunks -gt 0) { 1 } else { 0 }
Write-Log $(if ($exitCode -eq 0) { 'info' } else { 'error' }) run_end ([ordered]@{
        exit_code            = $exitCode
        duration_s           = [math]::Round($script:RunTimer.Elapsed.TotalSeconds, 1)
        threats_found        = $script:ThreatsFound
        threats_unquarantined = $script:ThreatsUnquarantined
        threats_resolved     = $script:ThreatsResolved
        threats_unprocessed  = $script:ThreatsUnprocessed
        alerts_resolved      = $script:AlertsResolved
        failed_chunks        = $script:FailedChunks
        lookup_failed        = $script:LookupFailed
    })
exit $exitCode
