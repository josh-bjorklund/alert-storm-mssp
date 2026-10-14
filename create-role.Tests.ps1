#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Runs the whole script with Invoke-RestMethod / Read-Host / Start-Sleep mocked. The template role has the shape of GET /rbac/role/{id}: pages[].permissions[] with numeric identifiers, a type, a title, a dependsOn list, and value=true when granted.

BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot 'create-role.ps1'

    function global:New-CrPermission($id, $type, $title, $deps, $granted) {
        $p = [ordered]@{ identifier = $id; type = $type; title = $title; dependsOn = @($deps) }
        if ($granted) { $p.value = $true } else { $p.value = $null }
        [pscustomobject]$p
    }
    # 107 is a dependency-only permission (103 depends on it), 106 and 301 are extras the template grants.
    function global:New-CrTemplate {
        [pscustomobject]@{ data = [pscustomobject]@{
                id = '111'; name = 'n8-alert-storm'; predefinedRole = $false; scope = 'site'
                pages = @(
                    [pscustomobject]@{ name = 'Endpoint Threats'; identifier = 'threats'; permissions = @(
                            (New-CrPermission '101' 'view' 'View' @() $true)
                            (New-CrPermission '102' 'xdrActions' 'Xdr Actions' @('101') $false)
                            (New-CrPermission '103' 'updateIncidentStatus' 'Update Incident Status' @('101', '107') $true)
                            (New-CrPermission '104' 'updateAnalystVerdict' 'Update Analyst Verdict' @('101') $true)
                            (New-CrPermission '105' 'unquarantine' 'Unquarantine' @('101') $true)
                            (New-CrPermission '106' 'kill' 'Kill' @('104', '101') $true)
                            (New-CrPermission '107' 'markThreat' 'Mark Threat' @('101') $false)) }
                    [pscustomobject]@{ name = 'STAR Rule Alerts'; identifier = 'customAlerts'; permissions = @(
                            (New-CrPermission '201' 'view' 'View' @() $true)
                            (New-CrPermission '202' 'updateIncidentStatus' 'Update Incident Status' @('201') $true)
                            (New-CrPermission '203' 'updateAnalystVerdict' 'Update Analyst Verdict' @('201') $true)) }
                    [pscustomobject]@{ name = 'Dashboard'; identifier = 'dashboard'; permissions = @(
                            (New-CrPermission '301' 'view' 'View' @() $true)) })
            } }
    }
    function global:New-CrHttpError($code, $retryAfter) {
        $resp = [System.Net.Http.HttpResponseMessage]::new($code)
        if ($retryAfter) { $resp.Headers.Add('Retry-After', [string]$retryAfter) }
        $ex = [System.Exception]::new("$code error")
        $ex | Add-Member -NotePropertyName Response -NotePropertyValue $resp
        $ex
    }
}

Describe 'create-role.ps1' {
    BeforeEach {
        # Test state lives in a global hashtable: $script: resolves differently inside mocks invoked from the script under test.
        $global:Cr = @{}
        $global:Cr.Calls = [System.Collections.Generic.List[object]]::new()
        $global:Cr.Template = New-CrTemplate
        $global:Cr.Existing = @()
        $global:Cr.Answer = 'Y'
        $global:Cr.NotGranted = @()          # ids the verify step reports as not granted
        $global:Cr.PostError = $null         # message the server returns with a 400 on create
        $global:Cr.RateLimit = $null         # @{ Remaining; RetryAfter } -> the next N creates answer HTTP 429
        $global:Cr.Token = ConvertTo-SecureString ('eyJraWQiOi' + ('x' * 200) + 'Y4HWg8hF3g') -AsPlainText -Force
        $global:Cr.LogPath = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '.log')
        $global:Cr.Output = $null

        Mock Start-Sleep {}
        Mock Read-Host { $global:Cr.Answer }
        Mock Invoke-RestMethod {
            $method = "$Method".ToUpper()
            $global:Cr.Calls.Add([pscustomobject]@{ Method = $method; Uri = $Uri; Body = if ($Body) { $Body | ConvertFrom-Json -Depth 10 } else { $null } })
            $path = ([uri]$Uri).AbsolutePath
            $query = [System.Web.HttpUtility]::ParseQueryString(([uri]$Uri).Query)

            if ($method -eq 'POST' -and $path -eq '/web/api/v2.1/rbac/role') {
                $rl = $global:Cr.RateLimit
                if ($rl -and $rl.Remaining -gt 0) { $rl.Remaining--; throw (New-CrHttpError 429 $rl.RetryAfter) }
                if ($global:Cr.PostError) {
                    $er = [System.Management.Automation.ErrorRecord]::new((New-CrHttpError 400 $null), 'e', 'NotSpecified', $null)
                    $er.ErrorDetails = [System.Management.Automation.ErrorDetails]::new($global:Cr.PostError)
                    Write-Error -ErrorRecord $er -ErrorAction Stop
                }
                $b = $Body | ConvertFrom-Json -Depth 10 -AsHashtable
                # swagger: data.name and data.description required; filter required with exactly one scope list
                if (-not $b.data.name -or $null -eq $b.data.description) { throw 'data.name and data.description are required' }
                if (@($b.filter.Keys).Count -ne 1) { throw 'filter must hold exactly one scope' }
                $global:Cr.Created = $b
                return [pscustomobject]@{ data = [pscustomobject]@{ id = '999' } }
            }
            if ($method -eq 'GET' -and $path -eq '/web/api/v2.1/rbac/roles') {
                return [pscustomobject]@{ data = @($global:Cr.Existing) }
            }
            if ($method -eq 'GET' -and $path -eq '/web/api/v2.1/rbac/role/111') {
                return $global:Cr.Template
            }
            if ($method -eq 'GET' -and $path -eq '/web/api/v2.1/rbac/role/999') {
                # the created role: the template's permission list, granted only for the ids that were sent
                $sent = @($global:Cr.Created.data.permissionIds)
                $role = New-CrTemplate
                foreach ($pg in $role.data.pages) { foreach ($p in $pg.permissions) { $p.value = ($sent -contains $p.identifier) -and ($global:Cr.NotGranted -notcontains $p.identifier) } }
                return $role
            }
            throw "unexpected call: $method $Uri"
        }
    }

    AfterAll {
        Remove-Variable Cr -Scope Global -ErrorAction SilentlyContinue
        Remove-Item Function:\New-CrPermission, Function:\New-CrTemplate, Function:\New-CrHttpError -ErrorAction SilentlyContinue
    }

    BeforeAll {
        function script:Invoke-Script {
            param([hashtable]$Extra = @{})
            $params = @{ Server = 'https://example.sentinelone.net'; ApiToken = $global:Cr.Token; TemplateRoleId = '111'; SiteId = '5'; LogPath = $global:Cr.LogPath }
            foreach ($key in $Extra.Keys) { $params[$key] = $Extra[$key] }
            foreach ($key in @($params.Keys)) { if ($null -eq $params[$key]) { $params.Remove($key) } }
            $global:Cr.Output = & $script:ScriptPath @params *>&1
            return $LASTEXITCODE
        }
        function script:Get-Calls([string]$Pattern) {
            @($global:Cr.Calls | Where-Object { "$($_.Method) $($_.Uri)" -match $Pattern })
        }
        function script:ConvertFrom-Logfmt([string]$Line) {
            $h = [ordered]@{}
            foreach ($m in [regex]::Matches($Line, '(\w+)=("(?:[^"\\]|\\.)*"|\S*)')) {
                $v = $m.Groups[2].Value
                if ($v.StartsWith('"')) { $v = $v.Substring(1, $v.Length - 2) }
                $h[$m.Groups[1].Value] = $v
            }
            $h
        }
    }

    Context 'parameter validation' {
        It 'rejects a non-https server' {
            { Invoke-Script @{ Server = 'http://example.sentinelone.net' } } | Should -Throw
        }
        It 'requires a scope' {
            { Invoke-Script @{ SiteId = $null } } | Should -Throw '*exactly one*'
        }
        It 'rejects more than one scope' {
            { Invoke-Script @{ AccountId = '7' } } | Should -Throw '*exactly one*'
        }
        It 'rejects a non-numeric template role id' {
            { Invoke-Script @{ TemplateRoleId = 'abc' } } | Should -Throw
        }
        It 'rejects an empty role name' {
            { Invoke-Script @{ RoleName = '' } } | Should -Throw
        }
        It 'rejects MaxRetries above 10' {
            { Invoke-Script @{ MaxRetries = 11 } } | Should -Throw
        }
        It 'makes no API call when validation fails' {
            { Invoke-Script @{ SiteId = $null } } | Should -Throw
            $global:Cr.Calls.Count | Should -Be 0
        }
    }

    Context 'creating the role' {
        It 'creates a role with the needed permissions and their dependencies, in the requested scope' {
            Invoke-Script | Should -Be 0
            $post = (Get-Calls '^POST .*/rbac/role$')
            $post.Count | Should -Be 1
            $post[0].Body.data.name | Should -Be 'alert-storm-mssp'
            $post[0].Body.data.description | Should -Be 'Permissions required by alert-storm-mssp.ps1 to resolve alerts and threats.'
            # 101,103,104,105 (threats) + 201,202,203 (alerts) + 107 (103 depends on it); not 102, 106 or 301
            @($post[0].Body.data.permissionIds | Sort-Object) | Should -Be @('101', '103', '104', '105', '107', '201', '202', '203')
            @($post[0].Body.filter.siteIds) | Should -Be @('5')
        }
        It 'reads the template role in the same scope' {
            Invoke-Script @{ SiteId = $null; AccountId = '7' } | Should -Be 0
            (Get-Calls '^GET .*/rbac/role/111').Count | Should -Be 1
            (Get-Calls '^GET .*/rbac/role/111')[0].Uri | Should -Match 'accountIds=7'
            @((Get-Calls '^POST .*/rbac/role$')[0].Body.filter.accountIds) | Should -Be @('7')
        }
        It 'pulls in the permission a needed one depends on even though it is not itself needed' {
            Invoke-Script | Should -Be 0
            @((Get-Calls '^POST .*/rbac/role$')[0].Body.data.permissionIds) | Should -Contain '107'
            ($global:Cr.Output | Out-String) | Should -Match 'Mark Threat\s+dependency of Threats\.updateIncidentStatus'
        }
        It 'includes the View permissions that the update permissions depend on' {
            Invoke-Script | Should -Be 0
            $ids = @((Get-Calls '^POST .*/rbac/role$')[0].Body.data.permissionIds)
            $ids | Should -Contain '101'
            $ids | Should -Contain '201'
        }
        It 'leaves out unquarantine with -SkipUnquarantine' {
            Invoke-Script @{ SkipUnquarantine = $true } | Should -Be 0
            @((Get-Calls '^POST .*/rbac/role$')[0].Body.data.permissionIds) | Should -Not -Contain '105'
        }
        It 'also grants everything the template grants with -IncludeTemplatePermissions' {
            Invoke-Script @{ IncludeTemplatePermissions = $true } | Should -Be 0
            @((Get-Calls '^POST .*/rbac/role$')[0].Body.data.permissionIds | Sort-Object) | Should -Be @('101', '103', '104', '105', '106', '107', '201', '202', '203', '301')
        }
        It 'uses the given name and description' {
            Invoke-Script @{ RoleName = 'storm-role'; RoleDescription = 'hello there' } | Should -Be 0
            $b = (Get-Calls '^POST .*/rbac/role$')[0].Body
            $b.data.name | Should -Be 'storm-role'
            $b.data.description | Should -Be 'hello there'
        }
        It 'verifies the permissions on the created role and prints its id' {
            Invoke-Script | Should -Be 0
            (Get-Calls '^GET .*/rbac/role/999').Count | Should -Be 1
            $text = $global:Cr.Output | Out-String
            $text | Should -Match 'Created role .alert-storm-mssp. \(id 999\)'
            $text | Should -Match 'Verified: all 8 permissions'
        }
    }

    Context 'refusing to create' {
        It 'stops before creating when the template lacks a needed permission' {
            $global:Cr.Template.data.pages = @($global:Cr.Template.data.pages | Where-Object { $_.identifier -ne 'customAlerts' })
            Invoke-Script | Should -Be 1
            (Get-Calls '^POST ').Count | Should -Be 0
            ($global:Cr.Output | Out-String) | Should -Match "Custom Alerts\.view \(page 'customAlerts', type 'view'\)"
        }
        It 'stops when a dependency is missing from the template' {
            $global:Cr.Template.data.pages[0].permissions[2].dependsOn = @('101', '999999')
            Invoke-Script | Should -Be 1
            (Get-Calls '^POST ').Count | Should -Be 0
            ($global:Cr.Output | Out-String) | Should -Match 'depends on id 999999'
        }
        It 'does not create a role whose name already exists in the scope' {
            $global:Cr.Existing = @([pscustomobject]@{ id = '555'; name = 'alert-storm-mssp' })
            Invoke-Script | Should -Be 1
            (Get-Calls '^POST ').Count | Should -Be 0
            ($global:Cr.Output | Out-String) | Should -Match "already exists.*id 555"
        }
        It 'ignores a similarly named role' {
            $global:Cr.Existing = @([pscustomobject]@{ id = '555'; name = 'alert-storm-mssp-old' })
            Invoke-Script | Should -Be 0
            (Get-Calls '^POST ').Count | Should -Be 1
        }
        It 'creates nothing, and exits 0, when the prompt is declined' {
            $global:Cr.Answer = 'N'
            Invoke-Script | Should -Be 0
            (Get-Calls '^POST ').Count | Should -Be 0
            ($global:Cr.Output | Out-String) | Should -Match 'Nothing was created'
        }
        It 'asks exactly once' {
            Invoke-Script | Should -Be 0
            Should -Invoke Read-Host -Times 1 -Exactly
        }
    }

    Context 'failures' {
        It 'fails, naming the permission, when the created role does not have one of them' {
            $global:Cr.NotGranted = @('203')
            Invoke-Script | Should -Be 1
            ($global:Cr.Output | Out-String) | Should -Match 'not granted on it: STAR Rule Alerts / Update Analyst Verdict'
        }
        It 'shows the response body when the console rejects the create' {
            $global:Cr.PostError = '{"errors":[{"detail":"Role name already in use"}]}'
            Invoke-Script | Should -Be 1
            ($global:Cr.Output | Out-String) | Should -Match 'Role name already in use'
        }
        It 'retries a 429 on create, honoring Retry-After' {
            $global:Cr.RateLimit = @{ Remaining = 1; RetryAfter = 3 }
            Invoke-Script | Should -Be 0
            (Get-Calls '^POST ').Count | Should -Be 2
            Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq 3 }
        }
        It 'gives up on a persistent 429 and exits 1' {
            $global:Cr.RateLimit = @{ Remaining = 99; RetryAfter = 1 }
            Invoke-Script @{ MaxRetries = 2 } | Should -Be 1
            (Get-Calls '^POST ').Count | Should -Be 3
        }
    }

    Context 'logging' {
        It 'logs the run with a masked token, the plan, the created role and the exit code' {
            Invoke-Script | Should -Be 0
            $events = @(Get-Content -LiteralPath $global:Cr.LogPath | ForEach-Object { ConvertFrom-Logfmt $_ })
            foreach ($e in $events) { $e.run_id | Should -Match '^[0-9a-f]{12}$'; $e.ts | Should -Not -BeNullOrEmpty }
            @($events | Where-Object event -eq 'run_start')[0].token | Should -Be 'eyJraWQiOi*****Y4HWg8hF3g'
            @($events | Where-Object event -eq 'plan')[0].permissions | Should -Be '8'
            @($events | Where-Object event -eq 'role_created')[0].role_id | Should -Be '999'
            @($events | Where-Object event -eq 'run_end')[0].exit_code | Should -Be '0'
            (Get-Content -LiteralPath $global:Cr.LogPath -Raw) | Should -Not -Match 'x{20}'
        }
        It 'stops before any API call when the log file cannot be written' {
            $blocker = Join-Path $TestDrive 'iamafile'
            Set-Content -LiteralPath $blocker -Value 'x'
            { Invoke-Script @{ LogPath = (Join-Path $blocker 'run.log') } } | Should -Throw
            $global:Cr.Calls.Count | Should -Be 0
        }
    }
}
