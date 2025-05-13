Import-Module "..\_modules\NukeDefender\NukeDefender.psm1"

#Requires -RunAsAdministrator

param($DOMAIN)
param($DOMAINDNS)
param($LDAPROOT)
param($PCNAME)
param($SUBNET)

function Set-IPAddress {
    param (
        [int]$SUBNET  # Exemple : 10 pour 192.168.10.250
    )
    # Get info: adapter, IP, gateway
    $NetAdapter = Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -ExpandProperty NetConnectionID
    $IPAddress = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetAdapter | Select-Object -ExpandProperty IPAddress

    # Vérifie si l'adresse IP actuelle est une adresse APIPA
    $IPByte = $IPAddress.Split(".")
    if ($IPByte[0] -eq "169" -and $IPByte[1] -eq "254") {
        Write-Host "`n [ ERROR ] - $IPAddress is a Link-Local address, Please check the VM network settings. `n`n"
        exit
    } else {
        # Construit l'adresse IP statique à partir du sous-réseau fourni
        $DNS = "192.168.$SUBNET.250"
        $StaticIP = "192.168.$SUBNET.10"

        netsh interface ipv4 set address name="$NetAdapter" static $StaticIP 255.255.255.0
        Set-DnsClientServerAddress -InterfaceAlias $NetAdapter -ServerAddresses ($DNS, "1.1.1.1")
    }
}

function Invoke-LabSetup { 
    if ($env:COMPUTERNAME -ne $PCNAME) { 
        Write-Host("`n [++] First run detected. Modifying network config...")

        Nuke-Defender
        Set-IPAddress -SUBNET $SUBNET
        Rename-Computer -NewName $PCNAME -Restart

    } elseif ($env:COMPUTERNAME -eq $PCNAME -and $env:USERDNSDOMAIN -ne $DOMAINDNS) {
        write-host ("`n [++] Joining domain and reboot...")
        
        Nuke-Defender
        $password = "R00tR00t" | ConvertTo-SecureString -asPlainText -Force
        $username = "$DOMAIN\Administrator" 
        $credential = New-Object System.Management.Automation.PSCredential($username,$password)
        if (Test-Connection -ComputerName $DOMAINDNS -Count 5 -Quiet) { 
            Add-Computer -DomainName $DOMAIN -Credential $credential  | Out-Null
            Start-Sleep 5
            restart-computer
        } else {
            Write-Error ("`n [ ERROR ] Can't reach the Domain Controller, Please check network connectivity or DNS Settings... Shutdown in 5 seconds")
            Start-Sleep 5
        }

    } else {
        $group = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("VQB0AGkAbABpAHMAYQB0AGUAdQByAHMAIABkAHUAIABCAHUAcgBlAGEAdQAgAOAAIABkAGkAcwB0AGEAbgBjAGUA"))
        Add-LocalGroupMember -Group $group -Member '$($DOMAIN)\Domain Admins'
        Add-LocalGroupMember -Group $group -Member '$($DOMAIN)\IT'
        Add-LocalGroupMember -Group 'Administrators' -Member '$($DOMAIN)\IT'
    }
} 
