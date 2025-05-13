Import-Module "..\_modules\Nuke-Defender.psm1"

#Requires -RunAsAdministrator

param($DOMAIN)
param($DOMAINDNS)
param($LDAPROOT)
param($PCNAME)

function Invoke-LabSetup { 
    if ($env:COMPUTERNAME -ne $PCNAME) { 
        write-host ("`n Changement des paramètres IP et du nom et reboot...")

        Nuke-Defender
        $NetAdapter=Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
        $IPAddress=Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetAdapter | Select-Object -ExpandProperty IPAddress
        $IPByte = $IPAddress.Split(".")
        $DNS = ($IPByte[0]+"."+$IPByte[1]+"."+$IPByte[2]+".250")
        Set-DnsClientServerAddress -InterfaceAlias $NetAdapter -ServerAddresses ("$DNS","1.1.1.1")
        Disable-NetAdapterPowerManagement -Name "$NetAdapter"
        netsh interface ipv6 set dnsservers "$NetAdapter" dhcp

        Rename-Computer -NewName $PCNAME -Restart
    } elseif ($env:COMPUTERNAME -eq $PCNAME -and $env:USERDNSDOMAIN -ne $DOMAINDNS) {
        write-host ("`n Ajout au domaine et reboot...")
        
        Nuke-Defender
        $password = "R00tR00t" | ConvertTo-SecureString -asPlainText -Force
        $username = "$DOMAIN\Administrateur" 
        $credential = New-Object System.Management.Automation.PSCredential($username,$password)
        #Verif ping du domaine avant lancement de la connection
        if (Test-Connection -ComputerName $DOMAINDNS -Count 5 -Quiet) { 
            Add-Computer -DomainName $DOMAIN -Credential $credential  | Out-Null
            Start-Sleep 5
            restart-computer
        } else {
            Write-Error "Erreur Impossible de Ping l'AD Vérfier la connectivité ou le DNS... Arrêt dans 5sec !"
            Start-Sleep 5
        }
    } else {
        $group = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("VQB0AGkAbABpAHMAYQB0AGUAdQByAHMAIABkAHUAIABCAHUAcgBlAGEAdQAgAOAAIABkAGkAcwB0AGEAbgBjAGUA"))
        Add-LocalGroupMember -Group $group -Member '$($DOMAIN)\Admins du domaine'
        Add-LocalGroupMember -Group $group -Member '$($DOMAIN)\IT'
        Add-LocalGroupMember -Group Administrateurs -Member '$($DOMAIN)\IT'
    }
} 
