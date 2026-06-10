param()
$ErrorActionPreference = 'Continue'
Write-Host "Removing all duplicate NNNIDS firewall block rules..."

$output = netsh advfirewall firewall show rule name=all
$ips = @{}
$name = ""
foreach ($line in $output) {
    $t = $line.Trim()
    if ($t -match "^Rule Name:\s+NNNIDS_Block_(.+)$") {
        $name = $Matches[1].Trim()
    }
    if (($name -ne "") -and ($t -match "^RemoteIP:\s+([0-9.]+)")) {
        $ip = $Matches[1]
        $ips[$ip] = 1
        $name = ""
    }
}

Write-Host "Found $($ips.Count) unique blocked IPs"

foreach ($ip in $ips.Keys) {
    $rn = "NNNIDS_Block_" + $ip
    netsh advfirewall firewall delete rule name=$rn | Out-Null
    Write-Host "Deleted all rules for $ip"
    netsh advfirewall firewall add rule name=$rn dir=in action=block remoteip=$ip protocol=any enable=yes | Out-Null
    Write-Host "Re-added single rule for $ip"
}

$check = netsh advfirewall firewall show rule name=all | Select-String "NNNIDS_Block"
Write-Host "DONE. Total NNNIDS rules: $($check.Count)"
