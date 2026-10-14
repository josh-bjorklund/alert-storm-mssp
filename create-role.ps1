<#
.SYNOPSIS
Creates the custom role that alert-storm-mssp.ps1 needs.

.DESCRIPTION
Creates a role with the permissions listed under "Required permissions" in README.md, plus the permissions they depend on. Permission ids are read from a template role (the predefined Viewer role unless -TemplateRoleId is given), and the new role is checked after it is created.

Intended to be run by an administrative user, not by the API user that runs alert-storm-mssp.ps1; that user only needs the role this script creates.

Exit code: 0 on success (including declining the prompt), 1 if anything failed.

.PARAMETER Server
Console base URL, e.g. https://usea1-123.sentinelone.net.

.PARAMETER ApiToken
API token, as a SecureString, of a user that can create roles (Roles.create).

.PARAMETER TemplateRoleId
Role to read permission ids from; it isn't changed. Default: the predefined Viewer role.

.PARAMETER AccountId
Create the role in this account. Give at most one of -AccountId, -SiteId, -GroupId or -Global.

.PARAMETER SiteId
Create the role in this site.

.PARAMETER GroupId
Create the role in this group.

.PARAMETER Global
Create the role at the global (tenant) level. This is the default with no scope option, and the widest scope; a narrower one is better for least privilege.

.PARAMETER RoleName
Name of the new role. Default: alert-storm-mssp.

.PARAMETER RoleDescription
Description of the new role. Default: Permissions required by alert-storm-mssp.ps1 to resolve alerts and threats.

.PARAMETER SkipUnquarantine
Leave out Threats.unquarantine (needed only if you answer Y to the un-quarantine prompt).

.PARAMETER IncludeTemplatePermissions
Also grant everything the template role grants.

.PARAMETER MaxRetries
Retries on HTTP 429 (waits for Retry-After, else backs off), 0-10. Default: 5.

.PARAMETER LogPath
Structured (logfmt) log, appended and tagged with a run_id; the token is masked. Default: ./create-role.log. The run stops if it can't be written.

.EXAMPLE
$token = Read-Host -AsSecureString -Prompt 'API token'
./create-role.ps1 -Server https://usea1-123.sentinelone.net -ApiToken $token -SiteId <site id>

.EXAMPLE
./create-role.ps1 -Server https://usea1-123.sentinelone.net -ApiToken $token -SiteId <site id> -TemplateRoleId <role id>
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^https://')]
    [string]$Server,

    [Parameter(Mandatory = $true)]
    [securestring]$ApiToken,

    [ValidatePattern('^\d+$')]
    [string]$TemplateRoleId,

    [ValidatePattern('^\d+$')]
    [string]$AccountId,

    [ValidatePattern('^\d+$')]
    [string]$SiteId,

    [ValidatePattern('^\d+$')]
    [string]$GroupId,

    [switch]$Global,

    [ValidateLength(1, 255)]
    [string]$RoleName = 'alert-storm-mssp',

    [ValidateLength(0, 255)]
    [string]$RoleDescription = 'Permissions required by alert-storm-mssp.ps1 to resolve alerts and threats.',

    [switch]$SkipUnquarantine,

    [switch]$IncludeTemplatePermissions,

    [ValidateRange(0, 10)]
    [int]$MaxRetries = 5,

    [string]$LogPath = './create-role.log'
)

$Server = $Server.TrimEnd('/')

# With no scope option the role is created at the global (tenant) level.
$GlobalByDefault = -not ($AccountId -or $SiteId -or $GroupId -or $Global)
$scopes = @(
    @(
        @{ Given = [bool]$AccountId; Name = 'accountIds'; Id = $AccountId; Filter = @{ accountIds = @($AccountId) }; Query = "accountIds=$AccountId" }
        @{ Given = [bool]$SiteId; Name = 'siteIds'; Id = $SiteId; Filter = @{ siteIds = @($SiteId) }; Query = "siteIds=$SiteId" }
        @{ Given = [bool]$GroupId; Name = 'groupIds'; Id = $GroupId; Filter = @{ groupIds = @($GroupId) }; Query = "groupIds=$GroupId" }
        @{ Given = ([bool]$Global -or $GlobalByDefault); Name = 'tenant'; Id = ''; Filter = @{ tenant = $true }; Query = 'tenant=true' }
    ) | Where-Object { $_.Given }
)
if ($scopes.Count -ne 1) {
    throw "Specify only one of -AccountId, -SiteId, -GroupId or -Global (with none, the role is created at the global level)."
}
$ScopeName = $scopes[0].Name
$ScopeId = $scopes[0].Id
$ScopeFilter = $scopes[0].Filter
$ScopeQuery = $scopes[0].Query

# Swagger permission name -> the console role page identifier and permission type it appears as in GET /rbac/role/{id}.
$NeededPermissions = @(
    @{ Name = 'Threats.view'; Page = 'threats'; Type = 'view' }
    @{ Name = 'Threats.updateIncidentStatus'; Page = 'threats'; Type = 'updateIncidentStatus' }
    @{ Name = 'Threats.updateAnalystVerdict'; Page = 'threats'; Type = 'updateAnalystVerdict' }
    @{ Name = 'Threats.unquarantine'; Page = 'threats'; Type = 'unquarantine'; Unquarantine = $true }
    @{ Name = 'Custom Alerts.view'; Page = 'customAlerts'; Type = 'view' }
    @{ Name = 'Custom Alerts.updateIncidentStatus'; Page = 'customAlerts'; Type = 'updateIncidentStatus' }
    @{ Name = 'Custom Alerts.updateAnalystVerdict'; Page = 'customAlerts'; Type = 'updateAnalystVerdict' }
)
if ($SkipUnquarantine) {
    $NeededPermissions = @($NeededPermissions | Where-Object { -not $_.Unquarantine })
}

$script:RunId = [guid]::NewGuid().ToString('N').Substring(0, 12)
$script:RunTimer = [System.Diagnostics.Stopwatch]::StartNew()
$script:LogEnabled = $false
$script:LogFile = $null
$script:Failed = $false
$script:NewRoleId = $null

# ================= LOGGING (logfmt) ====================

# One event per line as key=value pairs (logfmt). Values with spaces, quotes or '=' are double-quoted with \ and \" escaped. Logging problems never stop the run once it has started.
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

# One red line per error, in the same style as the [-] / [+] / [=] progress lines.
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

# Invoke-RestMethod that waits and retries on HTTP 429, up to $MaxRetries times. Other errors, and 429s that outlast the retries, are thrown to the caller with the response body (when the console sent one) in the message. Every attempt is logged (event=api_attempt).
function Invoke-S1Api {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [ValidateSet('Get', 'Post')]
        [string]$Method = 'Get',
        [string]$Body,
        [string]$Operation = 'api_call'
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
            Write-Log info api_attempt ([ordered]@{
                    operation   = $Operation
                    method      = $Method.ToUpperInvariant()
                    endpoint    = $path
                    attempt     = $attempt
                    outcome     = 'ok'
                    duration_ms = [int]$timer.ElapsedMilliseconds
                })
            return $response
        }
        catch {
            $timer.Stop()
            $status = Get-HttpStatusCode $_
            $detail = [string]$_.ErrorDetails.Message
            $errorText = [string]$_.Exception.Message
            if ($detail) {
                $errorText = "$errorText $detail"
            }
            $errorText = $errorText.Substring(0, [math]::Min(300, $errorText.Length))
            $fields = [ordered]@{
                operation   = $Operation
                method      = $Method.ToUpperInvariant()
                endpoint    = $path
                attempt     = $attempt
                outcome     = $(if ($status -eq 429) { 'rate_limited' } else { 'error' })
                duration_ms = [int]$timer.ElapsedMilliseconds
            }
            if ($null -ne $status) {
                $fields['http_status'] = $status
            }
            $fields['error'] = $errorText
            Write-Log $(if ($status -eq 429) { 'warn' } else { 'error' }) api_attempt $fields

            if ($status -ne 429) {
                throw $errorText
            }

            if ($attempt -gt $MaxRetries) {
                throw "Rate limited (HTTP 429) on $Method $path after $MaxRetries retries: $errorText"
            }

            $wait = Get-RetryAfterSeconds $_
            if ($null -eq $wait) {
                $wait = [math]::Min([math]::Pow(2, $attempt), 60)
            }
            $wait = [math]::Min($wait, 300)
            Write-Warning "Rate limited (HTTP 429) on $Method $path; waiting ${wait}s before retry $attempt/$MaxRetries."
            Start-Sleep -Seconds $wait
        }
    }
}

# ================= ROLE PERMISSIONS ====================

# Indexes a GET /rbac/role/{id} response: every permission by id and by "<page identifier>|<type>", with its page name, title, dependsOn and whether it is granted.
function Get-RolePermissionIndex {
    param($Role)

    $byId = @{}
    $byKey = @{}
    foreach ($page in @($Role.pages)) {
        foreach ($p in @($page.permissions)) {
            $entry = [pscustomobject]@{
                Id        = [string]$p.identifier
                Page      = [string]$page.identifier
                PageName  = [string]$page.name
                Type      = [string]$p.type
                Title     = [string]$p.title
                DependsOn = @($p.dependsOn | ForEach-Object { [string]$_ })
                Granted   = ($p.value -eq $true)
            }
            $byId[$entry.Id] = $entry
            $byKey["$($entry.Page)|$($entry.Type)"] = $entry
        }
    }
    return @{ ById = $byId; ByKey = $byKey }
}

# ===================== MAIN ============================

Write-Log info run_start ([ordered]@{
        server           = ([uri]$Server).Host
        token            = $MaskedToken
        template_role_id = $(if ($TemplateRoleId) { $TemplateRoleId } else { 'predefined Viewer (lookup)' })
        scope            = $ScopeName
        scope_id         = $ScopeId
        scope_default    = $GlobalByDefault
        role_name        = $RoleName
        skip_unquarantine = [bool]$SkipUnquarantine
        include_template_permissions = [bool]$IncludeTemplatePermissions
        max_retries      = $MaxRetries
        powershell       = $PSVersionTable.PSVersion.ToString()
        os               = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
        log_file         = $script:LogFile
    })

Write-Host "=== Create role '$RoleName' ===" -ForegroundColor Yellow
Write-Host "Console: $Server"
Write-Host "Scope:   $(if ($ScopeName -eq 'tenant') { 'global (tenant)' + $(if ($GlobalByDefault) { ' [default]' }) } else { $ScopeQuery })"
Write-Host "Log:     $($script:LogFile) (run_id $($script:RunId))"
Write-Host ""

$plan = $null
try {
    # ---- 0. Find the template role: the predefined Viewer role, unless -TemplateRoleId was given ----
    if (-not $TemplateRoleId) {
        $found = Invoke-S1Api -Uri "$Server/web/api/v2.1/rbac/roles?name=Viewer&predefinedRole=true" -Operation find_viewer_role
        $viewers = @(@($found.data) | Where-Object { $_.name -eq 'Viewer' })
        if ($viewers.Count -eq 0) {
            throw "Could not find the predefined Viewer role to use as the template. Pass -TemplateRoleId with the id of a role to read permission ids from."
        }
        if ($viewers.Count -gt 1) {
            throw "More than one predefined role is named Viewer (ids $(($viewers | ForEach-Object { $_.id }) -join ', ')). Pass -TemplateRoleId to choose one."
        }
        $TemplateRoleId = [string]$viewers[0].id
        Write-Host "[=] Template role: predefined Viewer (id $TemplateRoleId)"
        Write-Log info template_lookup ([ordered]@{ role_name = 'Viewer'; role_id = $TemplateRoleId })
    }

    # ---- 1. Read permission ids from the template role ----
    $templateResponse = Invoke-S1Api -Uri "$Server/web/api/v2.1/rbac/role/${TemplateRoleId}?$ScopeQuery" -Operation get_template_role
    $template = Get-RolePermissionIndex -Role $templateResponse.data
    $grantedInTemplate = @($template.ById.Values | Where-Object { $_.Granted })
    Write-Host "[=] Template role '$($templateResponse.data.name)': $($template.ById.Count) permissions, $($grantedInTemplate.Count) granted"
    Write-Log info template_loaded ([ordered]@{ role_name = [string]$templateResponse.data.name; permissions = $template.ById.Count; granted = $grantedInTemplate.Count })

    # ---- 2. Find the needed permissions and everything they depend on ----
    $plan = [ordered]@{}
    $missing = @()
    foreach ($need in $NeededPermissions) {
        $entry = $template.ByKey["$($need.Page)|$($need.Type)"]
        if ($entry) {
            $plan[$entry.Id] = @{ Entry = $entry; Why = $need.Name }
        }
        else {
            $missing += "$($need.Name) (page '$($need.Page)', type '$($need.Type)')"
        }
    }
    if ($missing) {
        throw "Not found in the template role's permission list: $($missing -join '; '). Use a template role in the same scope, or check the page and type names."
    }

    $queue = [System.Collections.Generic.Queue[string]]::new()
    foreach ($id in @($plan.Keys)) {
        $queue.Enqueue($id)
    }
    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        foreach ($dep in $plan[$current].Entry.DependsOn) {
            if (-not $plan.Contains($dep)) {
                $depEntry = $template.ById[$dep]
                if (-not $depEntry) {
                    throw "Permission $($plan[$current].Entry.Title) depends on id $dep, which is not in the template role's permission list."
                }
                $plan[$dep] = @{ Entry = $depEntry; Why = "dependency of $($plan[$current].Why)" }
                $queue.Enqueue($dep)
            }
        }
    }
    if ($IncludeTemplatePermissions) {
        foreach ($g in $grantedInTemplate) {
            if (-not $plan.Contains($g.Id)) {
                $plan[$g.Id] = @{ Entry = $g; Why = 'granted by the template role' }
            }
        }
    }

    Write-Host "[=] The new role will grant $($plan.Count) permissions:"
    foreach ($item in $plan.Values) {
        Write-Host ("      {0,-22} {1,-26} {2}" -f $item.Entry.PageName, $item.Entry.Title, $item.Why)
    }
    Write-Log info plan ([ordered]@{ permissions = $plan.Count; permission_ids = (@($plan.Keys) -join ',') })

    # ---- 3. Refuse to duplicate an existing role ----
    $existing = $null
    try {
        $roles = Invoke-S1Api -Uri "$Server/web/api/v2.1/rbac/roles?name=$([uri]::EscapeDataString($RoleName))&$ScopeQuery&limit=100" -Operation list_roles
        $existing = @($roles.data) | Where-Object { $_.name -eq $RoleName } | Select-Object -First 1
    }
    catch {
        Write-Warning "Could not check for an existing role named '$RoleName': $($_.Exception.Message)"
    }
    if ($existing) {
        throw "A role named '$RoleName' already exists in this scope (id $($existing.id)). Pick another -RoleName, or edit that role."
    }

    # ---- 4. Confirm, create, verify ----
    Write-Host ""
    $answer = Read-Host "Create role '$RoleName' with these $($plan.Count) permissions? (Y/N)"
    Write-Log info operator_choice ([ordered]@{ create = [bool]($answer -match '^(Y|y)$') })
    if ($answer -notmatch '^(Y|y)$') {
        Write-Host ">>> Cancelled. Nothing was created." -ForegroundColor Yellow
    }
    else {
        $body = @{
            data   = @{
                name          = $RoleName
                description   = $RoleDescription
                permissionIds = @($plan.Keys)
            }
            filter = $ScopeFilter
        } | ConvertTo-Json -Depth 5
        $created = Invoke-S1Api -Uri "$Server/web/api/v2.1/rbac/role" -Method Post -Body $body -Operation create_role
        $script:NewRoleId = [string]$created.data.id
        Write-Host "[+] Created role '$RoleName' (id $($script:NewRoleId))" -ForegroundColor Green
        Write-Log info role_created ([ordered]@{ role_id = $script:NewRoleId; permissions = $plan.Count })

        $check = Get-RolePermissionIndex -Role (Invoke-S1Api -Uri "$Server/web/api/v2.1/rbac/role/$($script:NewRoleId)?$ScopeQuery" -Operation verify_role).data
        $notGranted = @($plan.Keys | Where-Object { -not ($check.ById[$_] -and $check.ById[$_].Granted) })
        if ($notGranted) {
            $names = $notGranted | ForEach-Object { "$($plan[$_].Entry.PageName) / $($plan[$_].Entry.Title)" }
            throw "Role $($script:NewRoleId) was created but these permissions are not granted on it: $($names -join '; ')."
        }
        Write-Host "[+] Verified: all $($plan.Count) permissions are granted on the new role." -ForegroundColor Green
        Write-Log info role_verified ([ordered]@{ role_id = $script:NewRoleId; permissions = $plan.Count })
    }
}
catch {
    $script:Failed = $true
    Write-ErrorLine "$($_.Exception.Message)"
    Write-Log error run_failed ([ordered]@{ error = [string]$_.Exception.Message })
}

# ---- Summary ----
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Yellow
if ($script:NewRoleId) {
    Write-Host "Role id:  $($script:NewRoleId)"
    Write-Host "Next:     assign this role to the API user that runs alert-storm-mssp.ps1."
}
Write-Host "Result:   $(if ($script:Failed) { 'FAILED' } elseif ($script:NewRoleId) { 'role created' } else { 'nothing created' })"
Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Yellow

$exitCode = if ($script:Failed) { 1 } else { 0 }
Write-Log $(if ($exitCode -eq 0) { 'info' } else { 'error' }) run_end ([ordered]@{
        exit_code  = $exitCode
        duration_s = [math]::Round($script:RunTimer.Elapsed.TotalSeconds, 1)
        role_id    = $(if ($script:NewRoleId) { $script:NewRoleId } else { '' })
        failed     = $script:Failed
    })
exit $exitCode
