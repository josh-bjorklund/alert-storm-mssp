# alert-storm-mssp
The MSSP version of alert storm, no site IDs needed. This will clear all alerts for a given console, within the scope of the API token. 

PowerShell script to clear and resolve an alert storm in the SentinelOne console.

Pass the console URL, your API token (as a SecureString) and the hash value as parameters. Works on Windows PowerShell 5.1 and PowerShell 7+ (Windows, macOS, Linux). Run `Get-Help ./alert-storm-mssp.ps1 -Full` for every option.

The script takes the hash value of the false positive or desired threat (SHA1 or SHA256; MD5 is not supported) and resolves both threats and alerts, to include both the scenarios of a false positive threats, such as a VT reputation hit, and alerts, such as someone accidentally adding a hash to a block list or STAR rule.

By default the threat and analyst verdict is false positive, but this can be changed to any value you'd like. You will also be prompted to have the option to unquarantine files if desired. 

USAGE:

```powershell
$token = Read-Host -AsSecureString -Prompt 'API token'
./alert-storm-mssp.ps1 -Server https://usea1-123.sentinelone.net -ApiToken $token -FileHash <sha1-or-sha256>
```

Several hashes are handled together as one batch (one lookup, one un-quarantine prompt). Pass them as a comma-separated list, with no quotes around the whole list:

```powershell
./alert-storm-mssp.ps1 -Server https://usea1-123.sentinelone.net -ApiToken $token -FileHash <hash1>,<hash2>,<hash3>
```

Run it from a PowerShell session, or from a shell with `pwsh -Command "./alert-storm-mssp.ps1 ... -FileHash <hash1>,<hash2>"`. `pwsh -File` hands the list over as a single string, which fails validation.

## Logging

Every run appends structured logs to `-LogPath` (default `./alert-storm-mssp.log`), one [logfmt](https://brandur.org/logfmt) line per event, the same `key=value` shape as structlog's key-value renderer. Each line has `ts` (UTC), `level`, `run_id` and `event`. The run stops before any API call if the file can't be written. The log holds the console host name, endpoint paths, the hashes and a masked token (`first10*****last10`, or `*****` for a short one). It never holds the full token or URLs.

Events: `run_start`, `console_release`, `api_attempt` (one per request attempt), `lookup_page` (per lookup page: `returned`, the API's `total_items` (first page only, since the API reports 0 on later cursor pages), and counts by `incident_<status>` and `mitigation_<status>`), `retry_same_size`, `batch_size_reduced`, `retries_exhausted`, `lookup_complete` (adds `api_total_items` and the status totals), `operator_choice`, `lookup_failed`, `run_end`.

On an HTTP 500 the first retry keeps the batch size, since a 500 is often transient. Each further consecutive 500 reduces it (`batch_size_reduced`, with the `step` used) by 100, then 200, 400, 800 and so on, never below 1. The step starts over at 100 after a success. `size_retry` on an `api_attempt` shows where in that sequence the attempt was.

```
ts=2026-10-14T17:58:42.568Z level=info run_id=f1abc4de9b64 event=api_attempt operation=threat_resolve method=POST endpoint=/web/api/v2.1/threats/incident batch_size=500 size_retry=0 attempt=1 outcome=ok duration_ms=812 affected=500
ts=2026-10-14T17:58:44.102Z level=warn run_id=f1abc4de9b64 event=api_attempt operation=threat_resolve method=POST endpoint=/web/api/v2.1/threats/incident batch_size=500 size_retry=0 attempt=1 outcome=server_error duration_ms=30011 http_status=500 error="Response status code does not indicate success: 500 (Internal Server Error)."
```

`api_attempt` fields: `operation` (`threat_lookup`, `threat_unquarantine`, `threat_resolve`, `alert_verdict`, `alert_resolve`, `system_info`), `batch_size` (items requested), `size_retry` (consecutive 500 retries so far), `attempt` (429 retries within one request), `outcome` (`ok`, `rate_limited`, `server_error`, `error`), `duration_ms`, and `affected` (POST) or `returned` (GET).

To see which batch size succeeds most readily:

```powershell
Get-Content ./alert-storm-mssp.log |
  Where-Object { $_ -match 'event=api_attempt' -and $_ -match 'operation=threat_resolve' } |
  ForEach-Object { [pscustomobject]@{ Size = [int]([regex]::Match($_, 'batch_size=(\d+)').Groups[1].Value); Ok = $_ -match 'outcome=ok' } } |
  Group-Object Size | Sort-Object { [int]$_.Name } |
  ForEach-Object { [pscustomobject]@{ BatchSize = $_.Name; Attempts = $_.Count; SuccessRate = '{0:P0}' -f (($_.Group | Where-Object Ok).Count / $_.Count) } }
```

Tests: `Invoke-Pester ./alert-storm-mssp.Tests.ps1` (Pester 5.5+).

<img width="719" height="190" alt="image" src="https://github.com/user-attachments/assets/11e5997d-32b4-4fee-9b75-e2ffe8f7242b" />
