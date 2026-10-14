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
                    $offset = if ($query['cursor']) { [int]$query['cursor'] } else { 0 }
                    if ($Uri.Length -gt 8000) { throw "414 URI too long ($($Uri.Length) chars)" }
                    # ThreatsByHash (optional): hash -> ids, so a lookup only returns threats for the hashes it asked for
                    $all = if ($global:Asm.ThreatsByHash) { @($query['contentHashes'] -split ',' | ForEach-Object { $global:Asm.ThreatsByHash[$_] }) } else { $global:Asm.ThreatIds }
                    $slice = @($all | Select-Object -Skip $offset -First $limit)
                    $next = if ($offset + $slice.Count -lt $all.Count) { [string]($offset + $slice.Count) } else { $null }
                    return [pscustomobject]@{
                        data       = @($slice | ForEach-Object { [pscustomobject]@{ id = $_; threatInfo = [pscustomobject]@{ threatId = $_ } } })
                        pagination = [pscustomobject]@{ nextCursor = $next; totalItems = $all.Count }
                    }
                }
                '^POST /web/api/v2\.1/threats/(incident|mitigate/un-quarantine)$' {
                    $ids = @($body.filter.ids)
                    if ($ids.Count -lt 1 -or $ids.Count -gt 5000) { throw "filter.ids count $($ids.Count) outside 1-5000" }
                    return [pscustomobject]@{ data = [pscustomobject]@{ affected = $ids.Count } }
                }
                '^POST /web/api/v2\.1/cloud-detection/alerts/analyst-verdict$' {
                    if (-not $body.data.analystVerdict) { throw 'data.analystVerdict required' }
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

    AfterAll { Remove-Variable Asm -Scope Global -ErrorAction SilentlyContinue }

    AfterEach {
        # the spool file must never be left behind
        @(Get-ChildItem ([System.IO.Path]::GetTempPath()) -Filter 'tmp*.tmp' -ErrorAction SilentlyContinue).Count |
            Should -BeLessOrEqual $global:Asm.TempBefore
    }

    BeforeAll {
        function script:Invoke-Script {
            param([hashtable]$Extra = @{})
            $params = @{ Server = 'https://example.sentinelone.net'; ApiToken = $global:Asm.Token; FileHash = $script:Sha1 }
            foreach ($key in $Extra.Keys) { $params[$key] = $Extra[$key] }
            $global:Asm.Output = & $script:ScriptPath @params *>&1
            return $LASTEXITCODE
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
        It 'filters the lookup by hash and unresolved status, and uses the default page size' {
            $global:Asm.ThreatIds = [string[]]@('100000000000000001')
            Invoke-Script | Should -Be 0
            $get = (Get-Calls '^GET .*/threats\?')[0]
            $get.Uri | Should -Match 'limit=1000'
            $get.Uri | Should -Match "contentHashes=$($script:Sha1)"
            $get.Uri | Should -Match 'incidentStatuses=unresolved'
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
}
