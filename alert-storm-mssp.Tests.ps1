#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Runs the whole script with Invoke-RestMethod / Read-Host / Start-Sleep mocked. The fake API enforces the limits from docs/swagger_2.1.json, so a request the real API would reject fails here.

BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot 'alert-storm-mssp.ps1'
    $script:Sha1 = 'a' * 40
    $script:Sha256 = 'b' * 64
}

Describe 'alert-storm-mssp.ps1' {
    BeforeEach {
        # Test state lives in a global hashtable: $script: resolves differently inside mocks invoked from the script under test.
        $global:Asm = @{}
        $global:Asm.Calls = [System.Collections.Generic.List[object]]::new()
        $global:Asm.ThreatIds = [string[]]@()
        $global:Asm.AlertsRemaining = 0
        $global:Asm.FailPattern = $null     # regex on "METHOD uri"; matching calls throw, once per call
        $global:Asm.Answer = 'N'
        $global:Asm.Output = $null
        $global:Asm.LogPath = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '.log')
        $global:Asm.IgnoreStatusFilters = $false   # $true emulates a console that returns threats regardless of the status filters
        $global:Asm.ThreatStatus = @{}   # id -> @{ incident; mitigation } (default unresolved / not_mitigated)
        $global:Asm.ServerError = $null  # @{ Pattern; Fail = @(call numbers); Always } -> HTTP 500 on those calls (counted per Pattern)
        $global:Asm.MaxSize = $null      # @{ Page; Ids; Alerts } -> HTTP 500 when a request is bigger than the 'server' can handle
        $global:Asm.RateLimit = $null   # @{ Pattern; Remaining; RetryAfter } -> the next N matching calls answer HTTP 429
        $global:Asm.Token = ConvertTo-SecureString 'tok-123' -AsPlainText -Force
        $global:Asm.TempBefore = @(Get-ChildItem ([System.IO.Path]::GetTempPath()) -Filter 'tmp*.tmp' -ErrorAction SilentlyContinue).Count

        Mock Start-Sleep {}
        Mock Read-Host { $global:Asm.Answer }
        Mock Invoke-RestMethod {
            $method = "$Method".ToUpper()
            $global:Asm.Calls.Add([pscustomobject]@{
                Method  = $method
                Uri     = $Uri
                Headers = $Headers
                Body    = if ($Body) { $Body | ConvertFrom-Json -Depth 10 } else { $null }
            })
            if ($global:Asm.FailPattern -and "$method $Uri" -match $global:Asm.FailPattern) {
                throw 'simulated API failure'
            }

            $rl = $global:Asm.RateLimit
            if ($rl -and $rl.Remaining -gt 0 -and "$method $Uri" -match $rl.Pattern) {
                $rl.Remaining--
                $resp = [System.Net.Http.HttpResponseMessage]::new(429)
                if ($rl.RetryAfter) { $resp.Headers.Add('Retry-After', [string]$rl.RetryAfter) }
                $ex = [System.Exception]::new('429 Too Many Requests')
                $ex | Add-Member -NotePropertyName Response -NotePropertyValue $resp
                throw $ex
            }

            $se = $global:Asm.ServerError
            if ($se -and "$method $Uri" -match $se.Pattern) {
                $se.N++
                if ($se.Always -or @($se.Fail) -contains $se.N) { throw (New-Asm500Error) }
            }

            $path = ([uri]$Uri).AbsolutePath
            $query = [System.Web.HttpUtility]::ParseQueryString(([uri]$Uri).Query)
            $body = if ($Body) { $Body | ConvertFrom-Json -Depth 10 -AsHashtable } else { $null }

            switch -Regex ("$method $path") {
                '^GET /web/api/v2\.1/system/info$' {
                    # swagger: data.{release,version,build,patch,latestAgentVersion}
                    return [pscustomobject]@{ data = [pscustomobject]@{ build = '98'; latestAgentVersion = '22.3'; patch = ''; release = 'S-26.3.4'; version = '44' } }
                }
                '^GET /web/api/v2\.1/threats$' {
                    # swagger: limit max 1000; ids come back as data[].id
                    $limit = [int]$query['limit']
                    if ($limit -lt 1 -or $limit -gt 1000) { throw "limit $limit outside 1-1000" }
                    if ($global:Asm.MaxSize.Page -and $limit -gt $global:Asm.MaxSize.Page) { throw (New-Asm500Error) }
                    $offset = if ($query['cursor']) { [int]$query['cursor'] } else { 0 }
                    if ($Uri.Length -gt 8000) { throw "414 URI too long ($($Uri.Length) chars)" }
                    # ThreatsByHash (optional): hash -> ids, so a lookup only returns threats for the hashes it asked for
                    $all = if ($global:Asm.ThreatsByHash) { @($query['contentHashes'] -split ',' | ForEach-Object { $global:Asm.ThreatsByHash[$_] }) } else { $global:Asm.ThreatIds }
                    if (-not $global:Asm.IgnoreStatusFilters) {
                        $want = @($query['incidentStatuses'] -split ',' | Where-Object { $_ })
                        $nin = @($query['incidentStatusesNin'] -split ',' | Where-Object { $_ })
                        $all = @($all | Where-Object {
                                $st = $global:Asm.ThreatStatus[$_]
                                $incident = if ($st) { $st.incident } else { 'unresolved' }
                                (-not $want -or $want -contains $incident) -and ($nin -notcontains $incident)
                            })
                    }
                    $slice = @($all | Select-Object -Skip $offset -First $limit)
                    $next = if ($offset + $slice.Count -lt $all.Count) { [string]($offset + $slice.Count) } else { $null }
                    return [pscustomobject]@{
                        data       = @($slice | ForEach-Object {
                            $st = $global:Asm.ThreatStatus[$_]
                            [pscustomobject]@{ id = $_; threatInfo = [pscustomobject]@{
                                    threatId         = $_
                                    incidentStatus   = $(if ($st) { $st.incident } else { 'unresolved' })
                                    mitigationStatus = $(if ($st) { $st.mitigation } else { 'not_mitigated' })
                                } }
                        })
                        pagination = [pscustomobject]@{ nextCursor = $next; totalItems = $all.Count }
                    }
                }
                '^POST /web/api/v2\.1/threats/(incident|mitigate/un-quarantine)$' {
                    $ids = @($body.filter.ids)
                    if ($ids.Count -lt 1 -or $ids.Count -gt 5000) { throw "filter.ids count $($ids.Count) outside 1-5000" }
                    if ($global:Asm.MaxSize.Ids -and $ids.Count -gt $global:Asm.MaxSize.Ids) { throw (New-Asm500Error) }
                    return [pscustomobject]@{ data = [pscustomobject]@{ affected = $ids.Count } }
                }
                '^POST /web/api/v2\.1/cloud-detection/alerts/analyst-verdict$' {
                    if (-not $body.data.analystVerdict) { throw 'data.analystVerdict required' }
                    if ($global:Asm.MaxSize.Alerts -and [int]$body.filter.limit -gt $global:Asm.MaxSize.Alerts) { throw (New-Asm500Error) }
                    return [pscustomobject]@{ data = [pscustomobject]@{ affected = [math]::Min($global:Asm.AlertsRemaining, [int]$body.filter.limit) } }
                }
                '^POST /web/api/v2\.1/cloud-detection/alerts/incident$' {
                    # swagger: data holds only incidentStatus
                    if (@($body.data.Keys) -ne 'incidentStatus') { throw 'alerts/incident data must contain only incidentStatus' }
                    $n = [math]::Min($global:Asm.AlertsRemaining, [int]$body.filter.limit)
                    $global:Asm.AlertsRemaining -= $n
                    return [pscustomobject]@{ data = [pscustomobject]@{ affected = $n } }
                }
                default { throw "unexpected call: $method $Uri" }
            }
        }
    }

    AfterAll {
        Remove-Variable Asm -Scope Global -ErrorAction SilentlyContinue
        Remove-Item Function:\New-Asm500Error -ErrorAction SilentlyContinue
    }

    AfterEach {
        # the spool file must never be left behind
        @(Get-ChildItem ([System.IO.Path]::GetTempPath()) -Filter 'tmp*.tmp' -ErrorAction SilentlyContinue).Count |
            Should -BeLessOrEqual $global:Asm.TempBefore
    }

    BeforeAll {
        function global:New-Asm500Error {
            $resp = [System.Net.Http.HttpResponseMessage]::new(500)
            $ex = [System.Exception]::new('500 Internal Server Error')
            $ex | Add-Member -NotePropertyName Response -NotePropertyValue $resp
            return $ex
        }
        function script:Invoke-Script {
            param([hashtable]$Extra = @{})
            $params = @{ Server = 'https://example.sentinelone.net'; ApiToken = $global:Asm.Token; FileHash = $script:Sha1; LogPath = $global:Asm.LogPath }
            foreach ($key in $Extra.Keys) { $params[$key] = $Extra[$key] }
            $global:Asm.Output = & $script:ScriptPath @params *>&1
            return $LASTEXITCODE
        }
        # Parses a logfmt line into a hashtable; quoted values are unescaped.
        function script:ConvertFrom-Logfmt([string]$Line) {
            $h = [ordered]@{}
            foreach ($m in [regex]::Matches($Line, '(\w+)=("(?:[^"\\]|\\.)*"|\S*)')) {
                $v = $m.Groups[2].Value
                if ($v.StartsWith('"')) { $v = $v.Substring(1, $v.Length - 2) -replace '\\"', '"' -replace '\\\\', '\' }
                $h[$m.Groups[1].Value] = $v
            }
            $h
        }
        function script:Get-LogEvents([string]$Event) {
            # Callers wrap this in @() when they index it: a lone dictionary indexed with [0] returns its first value, not the event.
            Get-Content -LiteralPath $global:Asm.LogPath | ForEach-Object { ConvertFrom-Logfmt $_ } | Where-Object { -not $Event -or $_.event -eq $Event }
        }
        function script:Get-Calls([string]$Pattern) {
            @($global:Asm.Calls | Where-Object { "$($_.Method) $($_.Uri)" -match $Pattern })
        }
    }

    Context 'parameter validation' {
        It 'rejects a non-https server' {
            { Invoke-Script @{ Server = 'http://example.sentinelone.net' } } | Should -Throw
        }
        It 'rejects an MD5-length hash' {
            { Invoke-Script @{ FileHash = 'c' * 32 } } | Should -Throw
        }
        It 'rejects a non-hex hash' {
            { Invoke-Script @{ FileHash = 'z' * 40 } } | Should -Throw
        }
        It 'rejects an unknown threat verdict' {
            { Invoke-Script @{ ThreatAnalystVerdict = 'benign' } } | Should -Throw
        }
        It 'rejects an unknown alert verdict' {
            { Invoke-Script @{ AlertAnalystVerdict = 'benign' } } | Should -Throw
        }
        It 'rejects a batch delay over one hour' {
            { Invoke-Script @{ BatchDelaySeconds = 3601 } } | Should -Throw
        }
        It 'rejects a page size over 1000' {
            { Invoke-Script @{ ThreatsPageSize = 1001 } } | Should -Throw
        }
        It 'rejects a threat batch limit over 5000' {
            { Invoke-Script @{ ThreatsBatchLimit = 5001 } } | Should -Throw
        }
        It 'accepts SHA256' {
            Invoke-Script @{ FileHash = $script:Sha256 } | Should -Be 0
        }
        It 'makes no API call when validation fails' {
            { Invoke-Script @{ FileHash = 'nope' } } | Should -Throw
            $global:Asm.Calls.Count | Should -Be 0
        }
    }

    Context 'request basics' {
        It 'sends the plaintext token in the Authorization header' {
            $global:Asm.ThreatIds = [string[]]@('100000000000000001')
            Invoke-Script | Should -Be 0
            ($global:Asm.Calls | ForEach-Object { $_.Headers.Authorization } | Sort-Object -Unique) | Should -Be 'ApiToken tok-123'
        }
        It 'trims a trailing slash from the server' {
            $global:Asm.ThreatIds = [string[]]@('100000000000000001')
            Invoke-Script @{ Server = 'https://example.sentinelone.net/' } | Should -Be 0
            $global:Asm.Calls | ForEach-Object { $_.Uri | Should -Not -Match '\.net//' }
        }
        It 'sends verdicts in lowercase' {
            $global:Asm.ThreatIds = [string[]]@('100000000000000001')
            $global:Asm.AlertsRemaining = 1
            Invoke-Script @{ ThreatAnalystVerdict = 'TRUE_POSITIVE'; AlertAnalystVerdict = 'Suspicious' } | Should -Be 0
            (Get-Calls 'POST .*/threats/incident')[0].Body.data.analystVerdict | Should -Be 'true_positive'
            (Get-Calls 'POST .*/alerts/analyst-verdict')[0].Body.data.analystVerdict | Should -Be 'suspicious'
        }
    }

    Context 'console version' {
        It 'reads /system/info once and prints the release' {
            Invoke-Script | Should -Be 0
            (Get-Calls '^GET .*/system/info$').Count | Should -Be 1
            ($global:Asm.Output | Out-String) | Should -Match 'Console release: S-26\.3\.4'
        }
        It 'continues with a warning when /system/info fails' {
            $global:Asm.FailPattern = '/system/info'
            $global:Asm.ThreatIds = [string[]]@('100000000000000001')
            Invoke-Script | Should -Be 0
            ($global:Asm.Output | Out-String) | Should -Match 'Console release: unknown'
            (Get-Calls 'POST .*/threats/incident').Count | Should -Be 1
        }
    }

    Context 'threat lookup' {
        It 'filters the lookup by hash and excludes resolved threats, and uses the default page size' {
            $global:Asm.ThreatIds = [string[]]@('100000000000000001')
            Invoke-Script | Should -Be 0
            $get = (Get-Calls '^GET .*/threats\?')[0]
            $get.Uri | Should -Match 'limit=1000'
            $get.Uri | Should -Match "contentHashes=$($script:Sha1)"
            $get.Uri | Should -Match 'incidentStatusesNin=resolved'
            $get.Uri | Should -Not -Match 'incidentStatuses='
        }
        It 'follows the cursor across pages' {
            $global:Asm.ThreatIds = [string[]](1..25 | ForEach-Object { "1000000000000000$('{0:D2}' -f $_)" })
            Invoke-Script @{ ThreatsPageSize = 10; ThreatsBatchLimit = 100 } | Should -Be 0
            (Get-Calls '^GET .*/threats\?').Count | Should -Be 3
            $sent = @((Get-Calls 'POST .*/threats/incident') | ForEach-Object { $_.Body.filter.ids })
            $sent.Count | Should -Be 25
            ($sent | Sort-Object -Unique).Count | Should -Be 25
        }
    }

    Context 'resolved threats' {
        It 'leaves already-resolved threats out of the lookup and out of the resolve calls' {
            $ids = [string[]](1..1000 | ForEach-Object { "1000000000{0:D5}" -f $_ })
            $global:Asm.ThreatIds = $ids
            foreach ($id in $ids[0..699]) { $global:Asm.ThreatStatus[$id] = @{ incident = 'resolved'; mitigation = 'mitigated' } }
            Invoke-Script @{ ThreatsBatchLimit = 500 } | Should -Be 0
            $sent = @((Get-Calls 'POST .*/threats/incident') | ForEach-Object { $_.Body.filter.ids })
            $sent.Count | Should -Be 300
            ($sent | Where-Object { $global:Asm.ThreatStatus.ContainsKey($_) }).Count | Should -Be 0
            @(Get-LogEvents 'lookup_complete')[0].threats_found | Should -Be '300'
        }
    }

    Context 'threat resolve' {
        It 'sends only the ids as the incident filter, in chunks' {
            $global:Asm.ThreatIds = [string[]](1..25 | ForEach-Object { "1000000000000000$('{0:D2}' -f $_)" })
            Invoke-Script @{ ThreatsBatchLimit = 10 } | Should -Be 0
            $calls = Get-Calls 'POST .*/threats/incident'
            $calls.Count | Should -Be 3
            @($calls | ForEach-Object { @($_.Body.filter.ids).Count }) | Should -Be @(10, 10, 5)
            foreach ($c in $calls) {
                @($c.Body.filter.PSObject.Properties.Name) | Should -Be @('ids')
                $c.Body.data.incidentStatus | Should -Be 'resolved'
                $c.Body.data.analystVerdict | Should -Be 'false_positive'
            }
        }
        It 'pauses between chunks but not after the last' {
            $global:Asm.ThreatIds = [string[]](1..25 | ForEach-Object { "1000000000000000$('{0:D2}' -f $_)" })
            $global:Asm.AlertsRemaining = 0
            Invoke-Script @{ ThreatsBatchLimit = 10; BatchDelaySeconds = 7 } | Should -Be 0
            Should -Invoke Start-Sleep -Times 2 -ParameterFilter { $Seconds -eq 7 }
        }
        It 'prompts exactly once per run' {
            $global:Asm.ThreatIds = [string[]](1..25 | ForEach-Object { "1000000000000000$('{0:D2}' -f $_)" })
            Invoke-Script @{ ThreatsBatchLimit = 10 } | Should -Be 0
            Should -Invoke Read-Host -Times 1 -Exactly
        }
    }

    Context 'unquarantine' {
        It "does not send unquarantine when the answer is N" {
            $global:Asm.ThreatIds = [string[]]@('100000000000000001')
            Invoke-Script | Should -Be 0
            (Get-Calls 'un-quarantine').Count | Should -Be 0
        }
        It 'unquarantines each chunk, with only ids, before resolving it' {
            $global:Asm.Answer = 'Y'
            $global:Asm.ThreatIds = [string[]](1..25 | ForEach-Object { "1000000000000000$('{0:D2}' -f $_)" })
            Invoke-Script @{ ThreatsBatchLimit = 10 } | Should -Be 0
            $threatPosts = @($global:Asm.Calls | Where-Object { $_.Method -eq 'POST' -and $_.Uri -match '/threats/' })
            @($threatPosts | ForEach-Object { if ($_.Uri -match 'un-quarantine') { 'U' } else { 'R' } }) -join '' | Should -Be 'URURUR'
            foreach ($c in ($threatPosts | Where-Object { $_.Uri -match 'un-quarantine' })) {
                @($c.Body.filter.PSObject.Properties.Name) | Should -Be @('ids')
            }
        }
        It 'skips resolving a chunk whose unquarantine failed, and exits 1' {
            $global:Asm.Answer = 'Y'
            $global:Asm.FailPattern = 'POST .*un-quarantine'
            $global:Asm.ThreatIds = [string[]](1..5 | ForEach-Object { "10000000000000000$_" })
            Invoke-Script | Should -Be 1
            (Get-Calls 'POST .*/threats/incident').Count | Should -Be 0
        }
    }

    Context 'failures' {
        It 'continues past a failed resolve chunk and exits 1' {
            $global:Asm.ThreatIds = [string[]](1..25 | ForEach-Object { "1000000000000000$('{0:D2}' -f $_)" })
            $global:Asm.FailPattern = 'POST .*/threats/incident'
            Invoke-Script @{ ThreatsBatchLimit = 10 } | Should -Be 1
            (Get-Calls 'POST .*/threats/incident').Count | Should -Be 3
        }
        It 'still runs the alerts step when the lookup fails, and exits 1' {
            $global:Asm.FailPattern = '^GET .*/threats\?'
            $global:Asm.AlertsRemaining = 3
            Invoke-Script | Should -Be 1
            (Get-Calls 'POST .*/alerts/incident').Count | Should -Be 1
            (Get-Calls 'POST .*/threats/').Count | Should -Be 0
        }
    }

    Context 'error output' {
        It 'prints a failed chunk as one [!] line, without a Write-Error call-site block' {
            $global:Asm.ThreatIds = [string[]]@('100000000000001')
            $global:Asm.FailPattern = 'POST .*/threats/incident'
            Invoke-Script | Should -Be 1
            $text = $global:Asm.Output | Out-String
            $text | Should -Match '\[!\] Chunk 1: error resolving threat incidents: simulated API failure'
            $text | Should -Not -Match 'Write-Error'
            $text | Should -Not -Match '(?m)^Line \|'
        }
        It 'prints a failed lookup as one [!] line' {
            $global:Asm.FailPattern = '^GET .*/threats\?'
            Invoke-Script | Should -Be 1
            ($global:Asm.Output | Out-String) | Should -Match '\[!\] Threat lookup failed: simulated API failure'
        }
    }

    Context 'nothing matched' {
        It 'skips the prompt and threat calls, still tries alerts, and exits 0' {
            Invoke-Script | Should -Be 0
            Should -Invoke Read-Host -Times 0 -Exactly
            (Get-Calls 'POST .*/threats/').Count | Should -Be 0
            (Get-Calls 'POST .*/alerts/incident').Count | Should -Be 1
        }
    }

    Context 'alerts' {
        It 'sets the verdict before resolving, with the same filter, per batch' {
            $global:Asm.AlertsRemaining = 5
            Invoke-Script @{ AlertsBatchLimit = 2 } | Should -Be 0
            $alertCalls = @($global:Asm.Calls | Where-Object { $_.Uri -match '/alerts/' })
            @($alertCalls | ForEach-Object { if ($_.Uri -match 'analyst-verdict') { 'V' } else { 'I' } }) -join '' | Should -Be 'VIVIVI'
            $alertCalls[0].Body.filter.incidentStatus | Should -Be 'UNRESOLVED'
            $alertCalls[0].Body.filter.sourceProcessFileHashSha1__contains | Should -Be $script:Sha1
            ($alertCalls[0].Body.filter | ConvertTo-Json -Compress) | Should -Be ($alertCalls[1].Body.filter | ConvertTo-Json -Compress)
        }
        It 'uses the SHA256 filter key for a SHA256 hash' {
            $global:Asm.AlertsRemaining = 1
            Invoke-Script @{ FileHash = $script:Sha256 } | Should -Be 0
            (Get-Calls 'POST .*/alerts/incident')[0].Body.filter.sourceProcessFileHashSha256__contains | Should -Be $script:Sha256
        }
        It 'runs alerts even when only alerts match' {
            $global:Asm.AlertsRemaining = 4
            Invoke-Script | Should -Be 0
            $global:Asm.AlertsRemaining | Should -Be 0
        }
    }

    Context 'rate limiting (HTTP 429)' {
        BeforeEach {
            $global:Asm.ThreatIds = [string[]]@('100000000000000001')
        }
        It 'retries a 429 on the lookup and completes' {
            $global:Asm.RateLimit = @{ Pattern = '^GET .*/threats\?'; Remaining = 2 }
            Invoke-Script | Should -Be 0
            (Get-Calls '^GET .*/threats\?').Count | Should -Be 3
            (Get-Calls 'POST .*/threats/incident').Count | Should -Be 1
        }
        It 'waits for the Retry-After header' {
            $global:Asm.RateLimit = @{ Pattern = '^GET .*/threats\?'; Remaining = 1; RetryAfter = 3 }
            Invoke-Script | Should -Be 0
            Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq 3 }
        }
        It 'backs off exponentially when there is no Retry-After' {
            $global:Asm.RateLimit = @{ Pattern = '^GET .*/threats\?'; Remaining = 3 }
            Invoke-Script | Should -Be 0
            foreach ($n in 2, 4, 8) {
                Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq $n }
            }
        }
        It 'caps a very long Retry-After at 300 seconds' {
            $global:Asm.RateLimit = @{ Pattern = '^GET .*/threats\?'; Remaining = 1; RetryAfter = 9999 }
            Invoke-Script | Should -Be 0
            Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq 300 }
        }
        It 'retries a 429 on the resolve call' {
            $global:Asm.RateLimit = @{ Pattern = 'POST .*/threats/incident'; Remaining = 1 }
            Invoke-Script | Should -Be 0
            (Get-Calls 'POST .*/threats/incident').Count | Should -Be 2
        }
        It 'retries a 429 on the unquarantine call' {
            $global:Asm.Answer = 'Y'
            $global:Asm.RateLimit = @{ Pattern = 'POST .*un-quarantine'; Remaining = 1 }
            Invoke-Script | Should -Be 0
            (Get-Calls 'POST .*un-quarantine').Count | Should -Be 2
            (Get-Calls 'POST .*/threats/incident').Count | Should -Be 1
        }
        It 'retries a 429 on the alert verdict and incident calls' {
            $global:Asm.AlertsRemaining = 2
            $global:Asm.RateLimit = @{ Pattern = 'POST .*/alerts/'; Remaining = 2 }
            Invoke-Script | Should -Be 0
            $global:Asm.AlertsRemaining | Should -Be 0
        }
        It 'retries a 429 on /system/info' {
            $global:Asm.RateLimit = @{ Pattern = '/system/info'; Remaining = 1 }
            Invoke-Script | Should -Be 0
            ($global:Asm.Output | Out-String) | Should -Match 'Console release: S-26\.3\.4'
        }
        It 'gives up after MaxRetries, fails the lookup, and still runs alerts' {
            $global:Asm.RateLimit = @{ Pattern = '^GET .*/threats\?'; Remaining = 99 }
            Invoke-Script @{ MaxRetries = 2 } | Should -Be 1
            (Get-Calls '^GET .*/threats\?').Count | Should -Be 3
            (Get-Calls 'POST .*/threats/').Count | Should -Be 0
            (Get-Calls 'POST .*/alerts/incident').Count | Should -Be 1
        }
        It 'does not retry when MaxRetries is 0' {
            $global:Asm.RateLimit = @{ Pattern = '^GET .*/threats\?'; Remaining = 1 }
            Invoke-Script @{ MaxRetries = 0 } | Should -Be 1
            (Get-Calls '^GET .*/threats\?').Count | Should -Be 1
        }
        It 'does not retry non-429 errors' {
            $global:Asm.FailPattern = '^GET .*/threats\?'
            Invoke-Script | Should -Be 1
            (Get-Calls '^GET .*/threats\?').Count | Should -Be 1
        }
        It 'rejects MaxRetries above 10' {
            { Invoke-Script @{ MaxRetries = 11 } } | Should -Throw
        }
        It 'spaces lookup page requests at least 150 ms apart' {
            $global:Asm.ThreatIds = [string[]](1..25 | ForEach-Object { "1000000000000000$('{0:D2}' -f $_)" })
            Invoke-Script @{ ThreatsPageSize = 10 } | Should -Be 0
            (Get-Calls '^GET .*/threats\?').Count | Should -Be 3
            Should -Invoke Start-Sleep -Times 2 -Exactly -ParameterFilter { $Milliseconds -gt 0 -and $Milliseconds -le 150 }
        }
    }

    Context 'multiple hashes' {
        BeforeEach {
            $global:Asm.A1 = 'a' * 40
            $global:Asm.A2 = 'c' * 40
            $global:Asm.B1 = 'b' * 64
            $global:Asm.ThreatsByHash = @{
                $global:Asm.A1 = [string[]](1..12 | ForEach-Object { "1000000000000001$('{0:D2}' -f $_)" })
                $global:Asm.A2 = [string[]](1..9 | ForEach-Object { "1000000000000002$('{0:D2}' -f $_)" })
                $global:Asm.B1 = [string[]](1..4 | ForEach-Object { "1000000000000003$('{0:D2}' -f $_)" })
            }
        }
        It 'looks up every hash in one request and resolves all threats as one batch' {
            Invoke-Script @{ FileHash = @($global:Asm.A1, $global:Asm.A2, $global:Asm.B1); ThreatsBatchLimit = 10 } | Should -Be 0
            $gets = Get-Calls '^GET .*/threats\?'
            $gets.Count | Should -Be 1
            foreach ($h in $global:Asm.A1, $global:Asm.A2, $global:Asm.B1) { $gets[0].Uri | Should -Match $h }
            # 12 + 9 + 4 = 25 ids resolved in chunks of 10, not one call set per hash
            $calls = Get-Calls 'POST .*/threats/incident'
            @($calls | ForEach-Object { @($_.Body.filter.ids).Count }) | Should -Be @(10, 10, 5)
            @($calls | ForEach-Object { $_.Body.filter.ids }) | Sort-Object -Unique | Should -HaveCount 25
        }
        It 'prompts once for all hashes, and unquarantines every chunk from that one answer' {
            $global:Asm.Answer = 'Y'
            Invoke-Script @{ FileHash = @($global:Asm.A1, $global:Asm.A2, $global:Asm.B1); ThreatsBatchLimit = 10 } | Should -Be 0
            Should -Invoke Read-Host -Times 1 -Exactly
            (Get-Calls 'POST .*un-quarantine').Count | Should -Be 3
        }
        It 'sends each hash type to the alerts endpoints once, with every hash of that type' {
            $global:Asm.AlertsRemaining = 2
            Invoke-Script @{ FileHash = @($global:Asm.A1, $global:Asm.A2, $global:Asm.B1) } | Should -Be 0
            $alertCalls = @($global:Asm.Calls | Where-Object { $_.Uri -match '/alerts/' })
            $alertCalls.Count | Should -Be 4   # verdict + incident for SHA1, verdict + incident for SHA256
            $sha1 = $alertCalls[0].Body.filter
            @($sha1.sourceProcessFileHashSha1__contains) | Should -Be @($global:Asm.A1, $global:Asm.A2)
            $sha1.PSObject.Properties.Name | Should -Not -Contain 'sourceProcessFileHashSha256__contains'
            $sha256 = $alertCalls[2].Body.filter
            @($sha256.sourceProcessFileHashSha256__contains) | Should -Be @($global:Asm.B1)
            $sha256.PSObject.Properties.Name | Should -Not -Contain 'sourceProcessFileHashSha1__contains'
        }
        It 'makes no SHA256 alert call when only SHA1 hashes are given' {
            Invoke-Script @{ FileHash = @($global:Asm.A1, $global:Asm.A2) } | Should -Be 0
            (Get-Calls 'POST .*/alerts/incident').Count | Should -Be 1
        }
        It 'ignores duplicates, including ones that differ only by case' {
            Invoke-Script @{ FileHash = @($global:Asm.A1, $global:Asm.A1.ToUpper(), $global:Asm.A1) } | Should -Be 0
            ([regex]::Matches((Get-Calls '^GET .*/threats\?')[0].Uri, $global:Asm.A1)).Count | Should -Be 1
            @((Get-Calls 'POST .*/threats/incident')[0].Body.filter.ids).Count | Should -Be 12
        }
        It 'rejects one comma-joined string (what pwsh -File delivers), with no API calls' {
            { Invoke-Script @{ FileHash = "$($global:Asm.A1),$($global:Asm.B1)" } } | Should -Throw
            $global:Asm.Calls.Count | Should -Be 0
        }
        It 'rejects the whole run, with no API calls, if any one hash is invalid' {
            { Invoke-Script @{ FileHash = @($global:Asm.A1, 'not-a-hash') } } | Should -Throw
            $global:Asm.Calls.Count | Should -Be 0
        }
        It 'rejects an empty hash list' {
            { Invoke-Script @{ FileHash = ' ' } } | Should -Throw
            $global:Asm.Calls.Count | Should -Be 0
        }
        It 'splits a very large hash list across lookup requests that fit in a URL, still as one batch with one prompt' {
            $many = [string[]](1..150 | ForEach-Object { ('{0:x}' -f $_).PadLeft(64, 'd') })
            $global:Asm.ThreatsByHash = @{}
            foreach ($h in $many) { $global:Asm.ThreatsByHash[$h] = [string[]]@("2$($h.Substring(60))") }
            Invoke-Script @{ FileHash = $many } | Should -Be 0     # the mock throws 414 above 8000 chars
            $gets = Get-Calls '^GET .*/threats\?'
            $gets.Count | Should -BeGreaterThan 1
            ($gets | ForEach-Object { $_.Uri.Length } | Measure-Object -Maximum).Maximum | Should -BeLessThan 4000
            $ids = @((Get-Calls 'POST .*/threats/incident') | ForEach-Object { $_.Body.filter.ids })
            $ids.Count | Should -Be 150
            Should -Invoke Read-Host -Times 1 -Exactly
        }
        It 'summarizes all hashes together' {
            Invoke-Script @{ FileHash = @($global:Asm.A1, $global:Asm.B1) } | Should -Be 0
            ($global:Asm.Output | Out-String) | Should -Match '2 hash\(es\)'
        }
    }

    Context 'server errors (HTTP 500)' {
        BeforeEach {
            $global:Asm.Ids = [string[]](1..1000 | ForEach-Object { "1000000000000{0:D4}" -f $_ })
            $global:Asm.ThreatIds = $global:Asm.Ids
        }
        It 'retries a too-large resolve chunk once at the same size, then 100 smaller each time, and resolves every id exactly once' {
            $global:Asm.MaxSize = @{ Ids = 250 }
            Invoke-Script @{ ThreatsBatchLimit = 500 } | Should -Be 0
            $calls = Get-Calls 'POST .*/threats/incident'
            # 500 is rejected and retried once at 500, then 400 and 300 are rejected, then 200 is accepted and kept for the rest of the step
            @($calls | ForEach-Object { @($_.Body.filter.ids).Count }) | Should -Be @(500, 500, 400, 300, 200, 200, 200, 200, 200)
            $sent = @($calls | Where-Object { @($_.Body.filter.ids).Count -le 250 } | ForEach-Object { $_.Body.filter.ids })
            $sent.Count | Should -Be 1000
            ($sent | Sort-Object -Unique).Count | Should -Be 1000
        }
        It 'does not drop ids: the retried chunk starts with the same ids' {
            $global:Asm.MaxSize = @{ Ids = 250 }
            Invoke-Script @{ ThreatsBatchLimit = 500 } | Should -Be 0
            $calls = Get-Calls 'POST .*/threats/incident'
            $firstAccepted = @($calls | Where-Object { @($_.Body.filter.ids).Count -le 250 })[0]
            @($firstAccepted.Body.filter.ids)[0] | Should -Be $global:Asm.Ids[0]
        }
        It 'never reduces below 1' {
            $global:Asm.ThreatIds = [string[]]@('100000000000001', '100000000000002', '100000000000003')
            $global:Asm.MaxSize = @{ Ids = 1 }
            Invoke-Script @{ ThreatsBatchLimit = 150 } | Should -Be 0
            @((Get-Calls 'POST .*/threats/incident') | ForEach-Object { @($_.Body.filter.ids).Count }) | Should -Be @(3, 3, 3, 1, 1, 1)
        }
        It 'retries a one-off 500 at the same size without reducing it' {
            $global:Asm.ServerError = @{ Pattern = 'POST .*/threats/incident'; Fail = @(1); N = 0 }
            Invoke-Script @{ ThreatsBatchLimit = 500 } | Should -Be 0
            @((Get-Calls 'POST .*/threats/incident') | ForEach-Object { @($_.Body.filter.ids).Count }) | Should -Be @(500, 500, 500)
            @(Get-LogEvents 'batch_size_reduced').Count | Should -Be 0
            $same = @(Get-LogEvents 'retry_same_size')
            $same.Count | Should -Be 1
            $same[0].operation | Should -Be 'threat_resolve'
            $same[0].batch_size | Should -Be '500'
        }
        It 'retries a one-off 500 on the lookup at the same page size' {
            $global:Asm.ServerError = @{ Pattern = '^GET .*/threats\?'; Fail = @(1); N = 0 }
            Invoke-Script | Should -Be 0
            @((Get-Calls '^GET .*/threats\?') | ForEach-Object { [regex]::Match($_.Uri, 'limit=(\d+)').Groups[1].Value }) | Should -Be @('1000', '1000')
            @(Get-LogEvents 'batch_size_reduced').Count | Should -Be 0
        }
        It 'retries a one-off 500 on alerts at the same limit' {
            $global:Asm.ThreatIds = [string[]]@()
            $global:Asm.AlertsRemaining = 2
            $global:Asm.ServerError = @{ Pattern = 'POST .*/alerts/analyst-verdict'; Fail = @(1); N = 0 }
            Invoke-Script | Should -Be 0
            @((Get-Calls 'POST .*/alerts/analyst-verdict') | ForEach-Object { $_.Body.filter.limit }) | Should -Be @(500, 500)
            @(Get-LogEvents 'batch_size_reduced').Count | Should -Be 0
        }
        It 'only keeps the size on the first retry of a streak, not on every size' {
            $global:Asm.MaxSize = @{ Ids = 250 }
            Invoke-Script @{ ThreatsBatchLimit = 500 } | Should -Be 0
            @(Get-LogEvents 'retry_same_size').Count | Should -Be 1
            @(Get-LogEvents 'batch_size_reduced').Count | Should -Be 3
        }
        It 'resets the retry count after a success' {
            # incident calls 1,2 fail, 3 succeeds (retry count resets), then 4,5 fail and 6 succeeds. MaxRetries=2 would be exceeded without a reset.
            $global:Asm.ServerError = @{ Pattern = 'POST .*/threats/incident'; Fail = @(1, 2, 4, 5); N = 0 }
            Invoke-Script @{ ThreatsBatchLimit = 500; MaxRetries = 2 } | Should -Be 0
            $sent = @((Get-Calls 'POST .*/threats/incident') | ForEach-Object { $_.Body.filter.ids })
            ($sent | Sort-Object -Unique).Count | Should -Be 1000
        }
        It 'stops after MaxRetries consecutive 500s, reports the unresolved ids, and still runs alerts' {
            $global:Asm.ServerError = @{ Pattern = 'POST .*/threats/incident'; Always = $true; N = 0 }
            $global:Asm.AlertsRemaining = 1
            Invoke-Script @{ ThreatsBatchLimit = 500; MaxRetries = 2 } | Should -Be 1
            (Get-Calls 'POST .*/threats/incident').Count | Should -Be 3
            ($global:Asm.Output | Out-String) | Should -Match 'Threat ids NOT resolved: 1000'
            (Get-Calls 'POST .*/alerts/incident').Count | Should -Be 1
        }
        It 'does not retry a 500 when MaxRetries is 0' {
            $global:Asm.ServerError = @{ Pattern = 'POST .*/threats/incident'; Always = $true; N = 0 }
            Invoke-Script @{ MaxRetries = 0 } | Should -Be 1
            (Get-Calls 'POST .*/threats/incident').Count | Should -Be 1
        }
        It 'does not shrink the chunk on non-500 errors' {
            $global:Asm.FailPattern = 'POST .*/threats/incident'
            Invoke-Script @{ ThreatsBatchLimit = 500 } | Should -Be 1
            @((Get-Calls 'POST .*/threats/incident') | ForEach-Object { @($_.Body.filter.ids).Count }) | Should -Be @(500, 500)
        }
        It 'does not repeat unquarantine when only the resolve call hit a 500' {
            $global:Asm.Answer = 'Y'
            $global:Asm.ThreatIds = [string[]]@('100000000000001', '100000000000002', '100000000000003')
            $global:Asm.ServerError = @{ Pattern = 'POST .*/threats/incident'; Fail = @(1); N = 0 }
            Invoke-Script | Should -Be 0
            (Get-Calls 'POST .*un-quarantine').Count | Should -Be 1
            (Get-Calls 'POST .*/threats/incident').Count | Should -Be 2
        }
        It 'repeats unquarantine on the retry when the unquarantine call itself hit a 500' {
            $global:Asm.Answer = 'Y'
            $global:Asm.ThreatIds = [string[]]@('100000000000001', '100000000000002', '100000000000003')
            $global:Asm.ServerError = @{ Pattern = 'POST .*un-quarantine'; Fail = @(1); N = 0 }
            Invoke-Script | Should -Be 0
            (Get-Calls 'POST .*un-quarantine').Count | Should -Be 2
            (Get-Calls 'POST .*/threats/incident').Count | Should -Be 1
        }
        It 'retries the same lookup page with a smaller page size, without skipping ids' {
            $global:Asm.ThreatIds = [string[]](1..1500 | ForEach-Object { "1000000000{0:D5}" -f $_ })
            $global:Asm.MaxSize = @{ Page = 700 }
            Invoke-Script | Should -Be 0
            $limits = @((Get-Calls '^GET .*/threats\?') | ForEach-Object { [regex]::Match($_.Uri, 'limit=(\d+)').Groups[1].Value })
            $limits | Should -Be @('1000', '1000', '900', '800', '700', '700', '700')
            $sent = @((Get-Calls 'POST .*/threats/incident') | ForEach-Object { $_.Body.filter.ids })
            $sent.Count | Should -Be 1500
            ($sent | Sort-Object -Unique).Count | Should -Be 1500
        }
        It 'fails the lookup after MaxRetries 500s, and still runs alerts' {
            $global:Asm.ServerError = @{ Pattern = '^GET .*/threats\?'; Always = $true; N = 0 }
            $global:Asm.AlertsRemaining = 1
            Invoke-Script @{ MaxRetries = 2 } | Should -Be 1
            (Get-Calls '^GET .*/threats\?').Count | Should -Be 3
            (Get-Calls 'POST .*/alerts/incident').Count | Should -Be 1
        }
        It 'retries alerts with a smaller limit and resolves all of them' {
            $global:Asm.ThreatIds = [string[]]@()
            $global:Asm.AlertsRemaining = 600
            $global:Asm.MaxSize = @{ Alerts = 250 }
            Invoke-Script @{ AlertsBatchLimit = 500 } | Should -Be 0
            $global:Asm.AlertsRemaining | Should -Be 0
            $limits = @((Get-Calls 'POST .*/alerts/analyst-verdict') | ForEach-Object { $_.Body.filter.limit })
            $limits[0..3] | Should -Be @(500, 500, 400, 300)
        }
        It 'gives up on alerts after MaxRetries 500s and exits 1' {
            $global:Asm.ThreatIds = [string[]]@()
            $global:Asm.ServerError = @{ Pattern = 'POST .*/alerts/'; Always = $true; N = 0 }
            Invoke-Script @{ MaxRetries = 1 } | Should -Be 1
        }
    }

    Context 'logging' {
        BeforeEach {
            $global:Asm.ThreatIds = [string[]](1..1000 | ForEach-Object { "1000000000{0:D5}" -f $_ })
        }
        It 'writes parseable logfmt: every line has ts, level, run_id and event' {
            Invoke-Script @{ ThreatsBatchLimit = 500 } | Should -Be 0
            $lines = @(Get-Content -LiteralPath $global:Asm.LogPath)
            $lines.Count | Should -BeGreaterThan 5
            foreach ($l in $lines) {
                $e = ConvertFrom-Logfmt $l
                $e.ts | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$'
                $e.level | Should -BeIn 'info', 'warn', 'error'
                $e.run_id | Should -Match '^[0-9a-f]{12}$'
                $e.event | Should -Not -BeNullOrEmpty
            }
        }
        It 'appends across runs, each with its own run_id' {
            Invoke-Script | Should -Be 0
            $first = @(Get-Content -LiteralPath $global:Asm.LogPath).Count
            Invoke-Script | Should -Be 0
            @(Get-Content -LiteralPath $global:Asm.LogPath).Count | Should -BeGreaterThan $first
            (Get-LogEvents 'run_start' | ForEach-Object { $_.run_id } | Sort-Object -Unique).Count | Should -Be 2
        }
        It 'logs every API attempt with operation, requested batch size, outcome, duration and item count' {
            Invoke-Script @{ ThreatsBatchLimit = 500 } | Should -Be 0
            $resolves = @(Get-LogEvents 'api_attempt' | Where-Object { $_.operation -eq 'threat_resolve' })
            $resolves.Count | Should -Be 2
            foreach ($r in $resolves) {
                $r.batch_size | Should -Be '500'
                $r.outcome | Should -Be 'ok'
                $r.attempt | Should -Be '1'
                $r.affected | Should -Be '500'
                $r.endpoint | Should -Be '/web/api/v2.1/threats/incident'
                [int]$r.duration_ms | Should -BeGreaterOrEqual 0
            }
            $lookup = @(Get-LogEvents 'api_attempt' | Where-Object { $_.operation -eq 'threat_lookup' })
            $lookup[0].batch_size | Should -Be '1000'
            $lookup[0].returned | Should -Be '1000'
        }
        It 'logs each 500 with its batch size, plus the reductions, so success rate per size can be computed' {
            $global:Asm.MaxSize = @{ Ids = 250 }
            Invoke-Script @{ ThreatsBatchLimit = 500 } | Should -Be 0
            $resolves = @(Get-LogEvents 'api_attempt' | Where-Object { $_.operation -eq 'threat_resolve' })
            @($resolves | ForEach-Object { "$($_.batch_size):$($_.outcome)" }) | Should -Be @('500:server_error', '500:server_error', '400:server_error', '300:server_error', '200:ok', '200:ok', '200:ok', '200:ok', '200:ok')
            @($resolves | Where-Object { $_.outcome -eq 'server_error' } | ForEach-Object { $_.http_status } | Sort-Object -Unique) | Should -Be '500'
            @($resolves | ForEach-Object { $_.size_retry }) | Should -Be @('0', '1', '2', '3', '4', '0', '0', '0', '0')
            $reductions = @(Get-LogEvents 'batch_size_reduced')
            @($reductions | ForEach-Object { "$($_.from)>$($_.to)" }) | Should -Be @('500>400', '400>300', '300>200')
        }
        It 'logs a 429 as rate_limited with an increasing attempt number' {
            $global:Asm.RateLimit = @{ Pattern = '^GET .*/threats\?'; Remaining = 2 }
            Invoke-Script | Should -Be 0
            $lookup = @(Get-LogEvents 'api_attempt' | Where-Object { $_.operation -eq 'threat_lookup' })
            @($lookup | ForEach-Object { "$($_.attempt):$($_.outcome)" }) | Should -Be @('1:rate_limited', '2:rate_limited', '3:ok')
            $lookup[0].http_status | Should -Be '429'
        }
        It 'logs retries_exhausted and an error run_end when the retry limit is hit' {
            $global:Asm.ServerError = @{ Pattern = 'POST .*/threats/incident'; Always = $true; N = 0 }
            Invoke-Script @{ ThreatsBatchLimit = 500; MaxRetries = 1 } | Should -Be 1
            $ex = @(Get-LogEvents 'retries_exhausted')
            $ex.Count | Should -Be 1
            $ex[0].level | Should -Be 'error'
            $ex[0].unprocessed_ids | Should -Be '1000'
            $end = @(Get-LogEvents 'run_end')[0]
            $end.level | Should -Be 'error'
            $end.exit_code | Should -Be '1'
            $end.threats_unprocessed | Should -Be '1000'
        }
        It 'quotes values that contain spaces, and keeps the error text' {
            $global:Asm.FailPattern = 'POST .*/threats/incident'
            Invoke-Script @{ ThreatsBatchLimit = 500 } | Should -Be 1
            $err = Get-LogEvents 'api_attempt' | Where-Object { $_.outcome -eq 'error' } | Select-Object -First 1
            $err.level | Should -Be 'error'
            $err.error | Should -Be 'simulated API failure'
        }
        It 'logs run_start with the parameters, full hashes and a masked token, and run_end with the summary' {
            Invoke-Script @{ ThreatsBatchLimit = 500 } | Should -Be 0
            $start = @(Get-LogEvents 'run_start')[0]
            $start.server | Should -Be 'example.sentinelone.net'
            $start.hashes | Should -Be $script:Sha1
            $start.hash_count | Should -Be '1'
            $start.threats_batch_limit | Should -Be '500'
            $start.max_retries | Should -Be '5'
            @(Get-LogEvents 'console_release')[0].release | Should -Be 'S-26.3.4'
            @(Get-LogEvents 'lookup_complete')[0].threats_found | Should -Be '1000'
            $end = @(Get-LogEvents 'run_end')[0]
            $end.exit_code | Should -Be '0'
            $end.threats_resolved | Should -Be '1000'
        }
        It 'masks a long token as first10*****last10 and never logs the full token' {
            $long = 'eyJraWQiOi' + ('x' * 200) + 'Y4HWg8hF3g'
            $global:Asm.Token = ConvertTo-SecureString $long -AsPlainText -Force
            Invoke-Script | Should -Be 0
            @(Get-LogEvents 'run_start')[0].token | Should -Be 'eyJraWQiOi*****Y4HWg8hF3g'
            (Get-Content -LiteralPath $global:Asm.LogPath -Raw) | Should -Not -Match 'x{20}'
        }
        It 'fully masks a short token' {
            Invoke-Script | Should -Be 0
            @(Get-LogEvents 'run_start')[0].token | Should -Be '*****'
            (Get-Content -LiteralPath $global:Asm.LogPath -Raw) | Should -Not -Match 'tok-123'
        }
        It 'logs the incident and mitigation status mix of each lookup page, and the API total' {
            $global:Asm.IgnoreStatusFilters = $true   # a console that returns resolved threats anyway: the log must show them
            foreach ($id in $global:Asm.ThreatIds[0..299]) { $global:Asm.ThreatStatus[$id] = @{ incident = 'resolved'; mitigation = 'mitigated' } }
            Invoke-Script @{ ThreatsPageSize = 500; ThreatsBatchLimit = 5000 } | Should -Be 0
            $pages = @(Get-LogEvents 'lookup_page')
            $pages.Count | Should -Be 2
            $pages[0].returned | Should -Be '500'
            $pages[0].total_items | Should -Be '1000'
            $pages[0].incident_resolved | Should -Be '300'
            $pages[0].incident_unresolved | Should -Be '200'
            $pages[0].incident_in_progress | Should -Be '0'
            $pages[0].mitigation_mitigated | Should -Be '300'
            $pages[0].mitigation_not_mitigated | Should -Be '200'
            $pages[1].incident_unresolved | Should -Be '500'
            $pages[1].incident_resolved | Should -Be '0'
            $done = @(Get-LogEvents 'lookup_complete')[0]
            $done.threats_found | Should -Be '1000'
            $done.api_total_items | Should -Be '1000'     # first page only, not summed over every page
            $done.incident_unresolved | Should -Be '700'
            $done.incident_resolved | Should -Be '300'
            $done.mitigation_mitigated | Should -Be '300'
            $done.mitigation_not_mitigated | Should -Be '700'
        }
        It 'logs a status the API returns that we do not know, instead of dropping it' {
            $global:Asm.IgnoreStatusFilters = $true
            $global:Asm.ThreatStatus[$global:Asm.ThreatIds[0]] = @{ incident = 'weird_status'; mitigation = 'quantum' }
            Invoke-Script | Should -Be 0
            $done = @(Get-LogEvents 'lookup_complete')[0]
            $done.incident_weird_status | Should -Be '1'
            $done.mitigation_quantum | Should -Be '1'
        }
        It 'logs no URLs or query strings, only the host and endpoint paths' {
            Invoke-Script | Should -Be 0
            $raw = Get-Content -LiteralPath $global:Asm.LogPath -Raw
            $raw | Should -Not -Match 'https?://'
            $raw | Should -Not -Match 'contentHashes='
            $raw | Should -Not -Match 'cursor='
        }
        It 'creates the log folder if it does not exist' {
            $global:Asm.LogPath = Join-Path $TestDrive 'nested/dir/run.log'
            Invoke-Script | Should -Be 0
            Test-Path $global:Asm.LogPath | Should -BeTrue
        }
        It 'stops before any API call when the log file cannot be written' {
            $blocker = Join-Path $TestDrive 'iamafile'
            Set-Content -LiteralPath $blocker -Value 'x'
            $global:Asm.LogPath = Join-Path $blocker 'run.log'
            { Invoke-Script } | Should -Throw
            $global:Asm.Calls.Count | Should -Be 0
        }
    }
}
