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

## Examples

Most runs only need `-Server`, `-ApiToken` and `-FileHash`. Everything else has a default and is only for tuning.

Store the token once per session; the examples below use `$token`:

```powershell
$token = Read-Host -AsSecureString -Prompt 'API token'
```

**1. Typical run.** Uses the defaults: `false_positive` for threats and alerts, and 5000-id chunks.

```powershell
./alert-storm-mssp.ps1 -Server https://usea1-123.sentinelone.net -ApiToken $token -FileHash <sha256>
```

**2. Several hashes.** One lookup, one un-quarantine prompt, resolved as one batch. SHA1 and SHA256 can be mixed.

```powershell
./alert-storm-mssp.ps1 -Server https://usea1-123.sentinelone.net -ApiToken $token -FileHash <sha1>,<sha256>,<sha256>
```

**3. Different verdicts.** The values are `undefined`, `true_positive`, `false_positive` and `suspicious`.

```powershell
./alert-storm-mssp.ps1 -Server https://usea1-123.sentinelone.net -ApiToken $token -FileHash <sha256> `
    -ThreatAnalystVerdict suspicious -AlertAnalystVerdict true_positive
```

**4. Gentler on a slow console.** Smaller chunks, longer pauses and more retries.

```powershell
./alert-storm-mssp.ps1 -Server https://usea1-123.sentinelone.net -ApiToken $token -FileHash <sha256> `
    -ThreatsBatchLimit 2000 -ThreatsPageSize 500 -AlertsBatchLimit 200 -BatchDelaySeconds 5 -MaxRetries 8
```

**5. One log per case.** Makes runs easy to compare later.

```powershell
./alert-storm-mssp.ps1 -Server https://usea1-123.sentinelone.net -ApiToken $token -FileHash <sha256> `
    -LogPath ./logs/case-12345.log
```

From a shell, `pwsh -File` can't pass a list of hashes. Use `-Command` with an array; the script prompts for the token:

```bash
pwsh -Command "./alert-storm-mssp.ps1 -Server https://usea1-123.sentinelone.net -FileHash @('<sha1>','<sha256>')"
```

When to change the tuning parameters: check `alert-storm-mssp.log` after a run.
- `outcome=server_error` (HTTP 500) on `threat_resolve`: try a smaller `-ThreatsBatchLimit`.
- `outcome=rate_limited` (HTTP 429): raise `-BatchDelaySeconds` or `-MaxRetries`.
- Slow lookups: leave `-ThreatsPageSize` at 1000 (its maximum) unless the lookup itself returns 500s.

The values in example 4 are illustrative, not tested recommendations.

## Creating the role

`create-role.ps1` creates a custom role with the permissions listed under [Required permissions](#required-permissions), which is the smallest set the scripts need. It is intended to be run by an administrative user (one allowed to create roles), not by the API user that runs `alert-storm-mssp.ps1`; that user only needs the role it creates. The API has no standalone permission catalog, so it reads the numeric permission ids from the predefined Viewer role (found with `GET /rbac/roles?name=Viewer&predefinedRole=true` and not changed), creates the new role (at the global level by default, or in an account, site or group), and then checks that every permission is granted on it.

Store the token once per session; the examples below use `$token`:

```powershell
$token = Read-Host -AsSecureString -Prompt 'API token'
```

**1. Site scope.** The role can only be assigned within that site, which is the narrower choice for least privilege.

```powershell
./create-role.ps1 -Server https://usea1-123.sentinelone.net -ApiToken $token -SiteId <site id>
```

**2. Global scope.** Above accounts and sites; this is the default when no scope is given.

```powershell
./create-role.ps1 -Server https://usea1-123.sentinelone.net -ApiToken $token
```

**3. Account scope, custom name, without un-quarantine.** The role grants 6 permissions.

```powershell
./create-role.ps1 -Server https://usea1-123.sentinelone.net -ApiToken $token -AccountId <account id> `
    -RoleName alert-storm-mssp-no-unquarantine -SkipUnquarantine
```

Run it with an administrative user's token: that user needs `Roles.create` (and permission to view roles). If the Viewer lookup fails, or you want a different role as the template, pass `-TemplateRoleId <role id>`. With no scope option the role is created at the global level (the API's tenant scope, where the predefined Viewer role lives), above any account or site, so it can be assigned anywhere. That's the widest scope, so prefer a narrower one for least privilege: pass one of `-AccountId`, `-SiteId` or `-GroupId` (at most one scope option; `-Global` just states the default explicitly). Use `-SkipUnquarantine` to leave out un-quarantine, `-IncludeTemplatePermissions` to also copy everything the template grants, and `-RoleName` / `-RoleDescription` to name it. Assign the new role to the API user afterwards. Logs go to `./create-role.log`.

## Required permissions

The API token's user needs these 7 RBAC permissions (API permission names from the console swagger, S-26.3.4), scoped to every account, site or group whose threats and alerts should be resolved. [`create-role.ps1`](#creating-the-role) creates a role with exactly these. To create it by hand in the console, grant these (page and permission names as the console's role editor shows them) and nothing else. The script doesn't check permissions up front; a missing one shows up as a failed call in the log, or, for un-quarantine, as `affected=0`.

| Console page | Permission | API permission name | Used for |
|---|---|---|---|
| Endpoint Threats | View | `Threats.view` | Look up threats (`GET /threats`); also a dependency of the Endpoint Threats update permissions |
| Endpoint Threats | Update Incident Status | `Threats.updateIncidentStatus` | Resolve threats (`POST /threats/incident`) |
| Endpoint Threats | Update Analyst Verdict | `Threats.updateAnalystVerdict` | Apply the threat verdict (`POST /threats/incident`) |
| Endpoint Threats | Unquarantine | `Threats.unquarantine` | Un-quarantine (`POST /threats/mitigate/un-quarantine`), only if you answer Y; the swagger also says the user's role must be allowed to mitigate (Admin, IR Team or SOC) |
| STAR Rule Alerts | View | `Custom Alerts.view` | Dependency of the STAR Rule Alerts update permissions |
| STAR Rule Alerts | Update Incident Status | `Custom Alerts.updateIncidentStatus` | Resolve alerts (`POST /cloud-detection/alerts/incident`) |
| STAR Rule Alerts | Update Analyst Verdict | `Custom Alerts.updateAnalystVerdict` | Apply the alert verdict (`POST /cloud-detection/alerts/analyst-verdict`) |

Both `View` permissions are listed because the role definition records each page's `View` as a dependency of that page's update permissions. A missing one is the likely cause of a 403 on the update calls. Without un-quarantine (`-SkipUnquarantine` in `create-role.ps1`) the role grants 6 permissions.

`GET /system/info` (the console release) lists no permission; a failure only logs the release as `unknown`.

Un-quarantine only counts threats you're permitted to mitigate as `affected`, so `affected=0` on every `threat_unquarantine` call means either nothing was quarantined or the token lacks permission.

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
