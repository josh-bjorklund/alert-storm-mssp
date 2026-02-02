# alert-storm-mssp
The MSSP version of alert storm, no site IDs needed. This will clear all alerts for a given console, within the scope of the API token. 

PowerShell script to clear and resolve an alert storm in the SentinelOne console.

In the script itself change the console URL to fit your environment. 

At run time, provide your API key, and the hash value of the false positive or desired threat to begin resolving both threats and alerts to include both the scenarios of a false positive threats, such as a VT reputation hit, and alerts, such as someone accidentally adding a hash to a block list or STAR rule.

By default the threat and analyst verdict is false positive, but this can be changed to any value you'd like. You will also be prompted to have the option to unquarantine files if desired. 

USAGE: .\alert-storm-mssp.ps1 > Follow prompts

<img width="719" height="190" alt="image" src="https://github.com/user-attachments/assets/11e5997d-32b4-4fee-9b75-e2ffe8f7242b" />
