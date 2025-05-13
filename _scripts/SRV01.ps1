Import-Module "..\_modules\NukeDefender\NukeDefender.psm1"

#Requires -RunAsAdministrator

param($DOMAIN)
param($DOMAINDNS)
param($LDAPROOT)
param($PCNAME)
param($SUBNET)

function Set-IPAddress {
    param (
        [int]$SUBNET  # Example : 10 for 192.168.10.250
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
        $StaticIP = "192.168.$SUBNET.200"

        netsh interface ipv4 set address name="$NetAdapter" static $StaticIP 255.255.255.0
        Set-DnsClientServerAddress -InterfaceAlias $NetAdapter -ServerAddresses ($DNS, "1.1.1.1")
    }
}

function Invoke-LabSetup { 
    if ($env:COMPUTERNAME -ne $PCNAME) { 
        Write-Host("`n [++] First run detected. Modifying network config...")

        # Deactivate Windows Update
        Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
        Set-Service wuauserv -StartupType Disabled
        Stop-Service bits -Force -ErrorAction SilentlyContinue
        Set-Service bits -StartupType Disabled
        Stop-Service dosvc -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dosvc" -Name "Start" -Value 4
        takeown /f "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /a /r > $null 2>&1
        icacls "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /grant administrators:F /t > $null 2>&1
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1

        Set-IPAddress -SUBNET $SUBNET
        Rename-Computer -NewName $PCNAME -Restart

    } elseif ($env:COMPUTERNAME -eq $PCNAME -and $env:USERDNSDOMAIN -ne $DOMAINDNS) {
        write-host ("`n [++] Joining domain and reboot...")

        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False | Out-Null
        
        $password = "R00tR00t" | ConvertTo-SecureString -asPlainText -Force
        $username = "$DOMAIN\Administrator" 
        $credential = New-Object System.Management.Automation.PSCredential($username,$password)
        #Verif ping du domaine avant lancement de la connection
        if (Test-Connection -ComputerName $DOMAINDNS -Count 5 -Quiet) { 
            Add-Computer -DomainName $DOMAIN -Credential $credential  | Out-Null
            Start-Sleep 5
            restart-computer
        } else {
            Write-Error ("`n [ ERROR ] Can't reach the Domain Controller, Please check network connectivity or DNS Settings... Shutdown in 5 seconds")
            Start-Sleep 5
        }

    } else { 
        # Create credentials file
        Write-Host ("`n [++] Final configuration...")
        
        $username = '$DOMAIN\mlaurens'
        $password = ConvertTo-SecureString '!0Nevagrup0!' -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $password
        $credential | Export-CliXml -Path "C:\secure_credentials.xml"
        
        # Create the PowerShell script to perform LLMNR trigger
        $scriptContent = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("dwBoAGkAbABlACAAKAAkAHQAcgB1AGUAKQAgAHsACgAgACAAJABjAHIAZQBkAGUAbgB0AGkAYQBsACAAPQAgAEkAbQBwAG8AcgB0AC0AQwBsAGkAWABtAGwAIAAtAFAAYQB0AGgAIAAiAEMAOgBcAHMAZQBjAHUAcgBlAF8AYwByAGUAZABlAG4AdABpAGEAbABzAC4AeABtAGwAIgAKACAAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAALQBGAGkAbABlAFAAYQB0AGgAIAAiAHAAbwB3AGUAcgBzAGgAZQBsAGwALgBlAHgAZQAiACAALQBBAHIAZwB1AG0AZQBuAHQATABpAHMAdAAgACIALQBDAG8AbQBtAGEAbgBkACAAbABzACAAXABcAFMAUQBMADAAMQBcAEMAJAAiACAALQBDAHIAZQBkAGUAbgB0AGkAYQBsACAAJABjAHIAZQBkAGUAbgB0AGkAYQBsAAoAIAAgAFMAdABhAHIAdAAtAFMAbABlAGUAcAAgAC0AUwBlAGMAbwBuAGQAcwAgADEAMgAwAAoAfQA="))
        $group = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("VQB0AGkAbABpAHMAYQB0AGUAdQByAHMAIABkAHUAIABCAHUAcgBlAGEAdQAgAOAAIABkAGkAcwB0AGEAbgBjAGUA"))
        
        $scriptPath = "C:\llmnr_trigger.ps1"
        $scriptContent | Set-Content -Path $scriptPath
        
        # Add the script to the Run registry key for startup
        if (-not (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run")) {
            New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Force
        }

        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "LLMNR_Trigger_Script" -Value "powershell.exe -ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`"" 
        New-LocalUser -Name srvadmin -Password (ConvertTo-SecureString "Super-Password-4-Admin" -AsPlainText -Force)
        Add-LocalGroupMember -Group $group -Member '$($DOMAIN)\Domain Admins'
        Add-LocalGroupMember -Group $group -Member '$($DOMAINDNS)\IT'
        Add-LocalGroupMember -Group 'Administrators' -Member '$($DOMAINDNS)\IT'
    }     
} 