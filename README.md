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

Tests: `Invoke-Pester ./alert-storm-mssp.Tests.ps1` (Pester 5.5+).

<img width="719" height="190" alt="image" src="https://github.com/user-attachments/assets/11e5997d-32b4-4fee-9b75-e2ffe8f7242b" />
