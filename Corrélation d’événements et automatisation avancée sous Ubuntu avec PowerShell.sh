############################################################
# EXERCICE 1 : Corrélation SSH + Syslog
############################################################

$sshFails = Get-Content /var/log/auth.log |
Select-String "Failed password"

$sysErrors = Get-Content /var/log/syslog |
Select-String "error"

if($sshFails.Count -gt 10 -and $sysErrors.Count -gt 20){
    Write-Host "ALERTE : activité suspecte corrélée"
}


############################################################
# EXERCICE 2 : Détection burst connexions
############################################################

$connections = netstat -tunap 2>$null |
Select-String "ESTABLISHED"

$grouped = $connections |
ForEach-Object {
    ($_ -split "\s+")[-2]
} |
Group-Object

$grouped | Where-Object {$_.Count -gt 20}


############################################################
# EXERCICE 3 : Score de risque IP
############################################################

$ips = Get-Content /var/log/auth.log |
Select-String "Failed password" |
ForEach-Object {
    ($_ -split "from ")[1].Split(" ")[0]
}

$ips | Group-Object | ForEach-Object {

    $risk = $_.Count * 10

    [PSCustomObject]@{
        IP = $_.Name
        Attempts = $_.Count
        RiskScore = $risk
    }
}


############################################################
# EXERCICE 4 : Blocage automatique intelligent
############################################################

$threats = @(
    @{IP="192.168.1.10"; Risk=95},
    @{IP="10.0.0.22"; Risk=70}
)

foreach($t in $threats){

    if($t.Risk -gt 90){
        sudo iptables -A INPUT -s $t.IP -j DROP
    }
    elseif($t.Risk -gt 60){
        sudo iptables -A INPUT -s $t.IP -j REJECT
    }
}


############################################################
# EXERCICE 5 : Dashboard temps réel SOC
############################################################

while($true){

    Clear-Host

    $cpu = top -bn1 | Select-String "Cpu"
    $ram = free -h | Select-String "Mem"
    $fails = (Get-Content /var/log/auth.log |
        Select-String "Failed password").Count

    Write-Host "====== SOC DASHBOARD ======"
    Write-Host $cpu
    Write-Host $ram
    Write-Host "Failed SSH: $fails"

    Start-Sleep -Seconds 5
}


############################################################
# EXERCICE 6 : Corrélation multi-fichiers
############################################################

$auth = Get-Content /var/log/auth.log
$sys = Get-Content /var/log/syslog
$kern = Get-Content /var/log/kern.log

if(
    ($auth | Select-String "Failed").Count -gt 5 -and
    ($sys | Select-String "error").Count -gt 5 -and
    ($kern | Select-String "denied").Count -gt 3
){
    Write-Host "ALERTE MULTI-LOG"
}


############################################################
# EXERCICE 7 : Détection brute force distribuée
############################################################

$events = Get-Content /var/log/auth.log |
Select-String "Failed password"

$ips = $events |
ForEach-Object {
    ($_ -split "from ")[1].Split(" ")[0]
}

if(($ips | Group-Object).Count -gt 20){
    Write-Host "Brute force distribué détecté"
}


############################################################
# EXERCICE 8 : Baseline comportementale
############################################################

$baselineCPU = 20

$currentCPU = (
top -bn1 |
Select-String "Cpu"
).ToString()

Write-Host "Comparer baseline avec activité réelle"


############################################################
# EXERCICE 9 : Watchdog services critiques
############################################################

$services = @("postgresql","ssh")

foreach($svc in $services){

    $status = systemctl is-active $svc

    if($status -ne "active"){
        Write-Host "$svc DOWN"
        sudo systemctl restart $svc
    }
}


############################################################
# EXERCICE 10 : Surveillance intégrité fichiers
############################################################

$critical = @(
"/etc/passwd",
"/etc/shadow"
)

foreach($file in $critical){

    Get-FileHash $file
}


############################################################
# EXERCICE 11 : Export incidents JSON
############################################################

$incident = @{
    Time = Get-Date
    Type = "Recon Scan"
    Severity = "HIGH"
}

$incident | ConvertTo-Json |
Out-File incident.json


############################################################
# EXERCICE 12 : API réputation IP
############################################################

$ip = "8.8.8.8"

Invoke-RestMethod `
-Uri "https://ipinfo.io/$ip/json"


############################################################
# EXERCICE 13 : Heatmap console
############################################################

1..24 | ForEach-Object {

    $count = Get-Random -Minimum 1 -Maximum 50

    Write-Host "$_ h : " ("#" * $count)
}


############################################################
# EXERCICE 14 : Détection scan horizontal
############################################################

$logs = @(
"192.168.1.10 -> 10.0.0.1",
"192.168.1.10 -> 10.0.0.2",
"192.168.1.10 -> 10.0.0.3"
)

$logs | Group-Object


############################################################
# EXERCICE 15 : Mini moteur SIEM
############################################################

while($true){

    $fails = (Get-Content /var/log/auth.log |
        Select-String "Failed password").Count

    $errors = (Get-Content /var/log/syslog |
        Select-String "error").Count

    $score = ($fails * 5) + ($errors * 2)

    if($score -gt 50){
        Write-Host "SEVERITY HIGH"
    }
    elseif($score -gt 20){
        Write-Host "SEVERITY MEDIUM"
    }
    else{
        Write-Host "NORMAL"
    }

    Start-Sleep -Seconds 10
}


############################################################
# EXERCICE 16 : Génération rapport SOC CSV
############################################################

$data = [PSCustomObject]@{
    Date = Get-Date
    Alerts = 12
    Critical = 2
    BlockedIPs = 8
}

$data | Export-Csv soc_report.csv -NoTypeInformation


############################################################
# EXERCICE 17 : Détection anomalies trafic
############################################################

$traffic = Get-Random -Minimum 100 -Maximum 5000

if($traffic -gt 4000){
    Write-Host "Anomalie trafic"
}


############################################################
# EXERCICE 18 : Rotation automatique incidents
############################################################

Get-ChildItem ./incidents |
Where-Object {$_.Length -gt 50KB} |
Remove-Item


############################################################
# EXERCICE 19 : Quarantaine logique
############################################################

$badIP = "192.168.1.66"

sudo iptables -A INPUT -s $badIP -j DROP


############################################################
# EXERCICE 20 : DEFCON dynamique
############################################################

$risk = Get-Random -Minimum 1 -Maximum 100

switch ($risk){
    {$_ -gt 80} {Write-Host "DEFCON 1"}
    {$_ -gt 60} {Write-Host "DEFCON 2"}
    {$_ -gt 40} {Write-Host "DEFCON 3"}
    default {Write-Host "DEFCON 5"}
}