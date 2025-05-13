Import-Module "..\_modules\Nuke-Defender.psm1"

#Requires -RunAsAdministrator

param($DOMAIN)
param($DOMAINDNS)
param($LDAPROOT)
param($PCNAME)

function Set-IPAddress {
    # Get info: adapter, IP, gateway
    $NetAdapter=Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
    $IPAddress=Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetAdapter | Select-Object -ExpandProperty IPAddress
    $Gateway=((Get-NetIPConfiguration -InterfaceAlias $NetAdapter).IPv4DefaultGateway).NextHop
    $IPByte = $IPAddress.Split(".")

    # Check IP and set static
    if ($IPByte[0] -eq "169" -And $IPByte[1] -eq "254") {
        Write-Host("`n [ ERROR ] - $IPaddress is a Link-Local address, Please check the VM network settings. `n`n")
        exit
    } else {
        $StaticIP = ($IPByte[0]+"."+$IPByte[1]+"."+$IPByte[2]+".250")
        netsh interface ipv4 set address name="$NetAdapter" static $StaticIP 255.255.255.0 $Gateway
        Set-DnsClientServerAddress -InterfaceAlias $NetAdapter -ServerAddresses ("127.0.0.1","1.1.1.1")
    }
}

function Get-QoL{
    write-host("`n [++] QoL - Dark Mode")
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f > $null
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f > $null

    write-host("`n [++] QoL - Session Locking and deactivate standy")
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveTimeOut" /t REG_DWORD /d "0" /f > $null 
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_DWORD /d "0" /f > $null
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_DWORD /d "0" /f > $null

    Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask | Out-Null
}

function Add-User{
    param([Parameter()][string]$forename,[Parameter()][string]$name,[Parameter()][string]$sam,[Parameter()][string]$ou,[Parameter()][string]$passwd)
    
    $mdp = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($passwd))
    New-ADUser -Name "$forename $name" -GivenName "$forename" -Surname "$name" -SamAccountName "$sam" -UserPrincipalName "$sam@$DOMAINDNS" -Path "OU=$ou,$LDAPROOT" -AccountPassword (ConvertTo-SecureString $passwd -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
}

function Add-ADDS {
    Write-host("`n [++] Install Active Directory Domain Services (ADDS)")
    Install-windowsfeature -name AD-Domain-Services -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null

    Write-host("`n [++] Importing Module Active Directory")
    Import-Module ActiveDirectory -WarningAction SilentlyContinue | Out-Null
    
    Write-host("`n [++] Installing domain $DOMAINDNS")
    Install-ADDSForest -SkipPreChecks -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "WinThreshold" -DomainName $DOMAINDNS -DomainNetbiosName $DOMAIN -ForestMode "WinThreshold" -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false -SysvolPath "C:\Windows\SYSVOL" -Force:$true -SafeModeAdministratorPassword (Convertto-SecureString -AsPlainText "R00tR00t" -Force) -WarningAction SilentlyContinue | Out-Null
}

function Add-ADCS {
    Write-Host("`n [++] Install AD Certificate Services")
    Add-WindowsFeature -Name AD-Certificate -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
  
    write-host("`n [++] Install ADCS Certificate Authority")
    Add-WindowsFeature -Name Adcs-Cert-Authority -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null

    write-host("`n [++] Configuring Active Directory Certificate Authority")
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 2048 -HashAlgorithmName SHA1 -ValidityPeriod Years -ValidityPeriodUnits 99 -WarningAction SilentlyContinue -Force | Out-Null

    write-host("`n [++] Install Remote System Administration Tools (RSAT)")
    Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -WarningAction SilentlyContinue | Out-Null
    Add-WindowsFeature RSAT-ADCS,RSAT-ADCS-mgmt -WarningAction SilentlyContinue | Out-Null
    Add-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature
}

function Add-Users-to-Domain {
    # Groupes, OUs, utilisateurs
    New-ADGroup -name "HR" -GroupScope Global
    New-ADGroup -name "Management" -GroupScope Global
    New-ADGroup -name "Consultants" -GroupScope Global
    New-ADGroup -name "Sales" -GroupScope Global
    New-ADGroup -name "IT" -GroupScope Global
    New-ADGroup -name "Backup" -GroupScope Global

    New-ADOrganizationalUnit -Name "Groups" -Path $LDAPROOT
    New-ADOrganizationalUnit -Name "HR" -Path $LDAPROOT
    New-ADOrganizationalUnit -Name "Management" -Path $LDAPROOT
    New-ADOrganizationalUnit -Name "Consultants" -Path $LDAPROOT
    New-ADOrganizationalUnit -Name "Sales" -Path $LDAPROOT
    New-ADOrganizationalUnit -Name "IT" -Path $LDAPROOT
    New-ADOrganizationalUnit -Name "SVC" -Path $LDAPROOT

    foreach ($g in Get-ADGroup -Filter *){ 
        Get-ADGroup $g | Move-ADObject -targetpath "OU=Groups,$LDAPROOT" -ErrorAction SilentlyContinue | Out-Null
    }

    # Management
    Add-User -forename "Richard" -name "Cuvillier" -sam "rcuvillier" -ou "management" -passwd "TgBlAHYAYQBzAGUAYwAxADIAMwA="
    Add-User -forename "Basile" -name "Delacroix" -sam "bdelacroix" -ou "management" -passwd "QQB6AGUAcgB0AHkAIwAxADUA"
    Add-User -forename "Martine" -name "Baudet" -sam "mbaudet" -ou "management" -passwd "NgA3AEQAMQBmAEQAJQAlAGsAOAByADgA"
    Add-User -forename "Ludovic" -name "Michaux" -sam "lmichaux" -ou "management" -passwd "TgBlAHYAYQBzAGUAYwAyADAAMgA0AA=="
    Add-ADGroupMember -Identity "Management" -Members rcuvillier,bdelacroix,mbaudet,lmichaux

    # HR
    Add-User -forename "Louise" -name "Chappuis" -sam "lchappuis" -ou "hr" -passwd "QQB6AGUAcgB0AHkAMQAyADMA"
    Add-User -forename "Sarah" -name "Meyer" -sam "smeyer" -ou "hr" -passwd "TgBlAHYAYQBzAGUAYwAyADAAMgA0ACEA"
    Add-User -forename "Fabrice" -name "Girault" -sam "fgirault" -ou "hr" -passwd "QQB6AGUAcgB0AHkAMgAwADIANAA="
    Add-ADGroupMember -Identity "HR" -Members lchappuis,smeyer,fgirault

    # Consultants
    Add-User -forename "Henri" -name "Walter" -sam "hwalter" -ou "consultants" -passwd "VwBvAGQAZQBuAHMAZQBjACoAOQA4AA=="
    Add-User -forename "Bertrand" -name "Dubois" -sam "bdubois" -ou "consultants" -passwd "SwBpAEwAbABFAHIANQAhAA=="
    Add-User -forename "Didier" -name "Leroux" -sam "dleroux" -ou "consultants" -passwd "TgBlAHYAYQAqADkAOAAyAA=="
    Add-User -forename "Pascal" -name "Mesny" -sam "pmesny" -ou "consultants" -passwd "dwBzADkAcABBACYAbABnADcATgAzADIA"
    Add-User -forename "Lydia" -name "Beaumont" -sam "lbeaumont" -ou "consultants" -passwd "VAAwAGsAaQAwAEgAMAB0ADMAbAA="
    Add-User -forename "Alexia" -name "Chabert" -sam "achabert" -ou "consultants" -passwd "UABPAGkAdQAqACYAOAA3AF4AJQA="
    Add-User -forename "Dylan" -name "Brassard" -sam "dbrassard" -ou "consultants" -passwd "SwBzAGQAaQAzADQAMgA2AEMAJgB2AGUA"
    Add-User -forename "Lara" -name "Fournier" -sam "lfournier" -ou "consultants" -passwd "OAA3AGMAYgB6AHUAdgBzAEYAMAAyACYA"
    Add-User -forename "Hugo" -name "Dupuy" -sam "hdupuy" -ou "consultants" -passwd "WAAyAHcAXgB2AFkANAAzADIARQBvAFAA"
    Add-User -forename "Pierre" -name "Sylvestre" -sam "psylvestre" -ou "consultants" -passwd "UABhAHMAcwB3AG8AcgBkADEAMgAzACEA"
    Add-ADGroupMember -Identity "Consultants" -Members hwalter,bdubois,dleroux,pmesny,lbeaumont,achabert,dbrassard,lfournier,hdupuy,psylvestre

    # sales
    Add-User -forename "Olivier" -name "Bossuet" -sam "obossuet" -ou "sales" -passwd "YgB4AEwAIQBAADIATQBlADEATQA4AHUA"
    Add-User -forename "Jessica" -name "Plantier" -sam "jplantier" -ou "sales" -passwd "TgAzAHYANABnAHIAMAB1AHAA"
    Add-User -forename "Jade" -name "Schneider" -sam "jschneider" -ou "sales" -passwd "VAB6AGoAMAA0ADQAWgBlAFYAJgBZAHUA"
    Add-User -forename "Laetitia" -name "Portier" -sam "lportier" -ou "sales" -passwd "QQB6AGUAcgB0AHkAMgAwADIANAA="
    Add-User -forename "Cyrille" -name "Toutain" -sam "ctoutain" -ou "sales" -passwd "cQBzAGcANQA2ADQAUwBGADIALQAkAA=="
    Add-ADGroupMember -Identity "Sales" -Members obossuet,jplantier,jschneider,lportier,ctoutain

    # Comptes IT et comptes IT admins du domaine
    Add-User -forename "Sylvain" -name "Cormier" -sam "scormier" -ou "it" -passwd "egBMADAAVAAxAE4AIQA0AEEAQQBZAHIA"
    Add-User -forename "Admin" -name "Sylvain Cormier" -sam "adm-scormier" -ou "it" -passwd "egBMADAAVAAxAE4AIQA0AEEAQQBZAHIA"
    Add-User -forename "Maxime" -name "Laurens" -sam "mlaurens" -ou "it" -passwd "IQAwAE4AZQB2AGEAZwByAHUAcAAwACEA"
    Add-User -forename "Admin" -name "Maxime Laurens" -sam "adm-mlaurens" -ou "it" -passwd "UwB1AHAAZQByAC0AUABhAHMAcwB3AG8AcgBkAC0ANAAtAEEAZABtAGkAbgA="
    
    Add-ADGroupMember -Identity "IT" -Members scormier,mlaurens
    Add-ADGroupMember -Identity "Domain Admins" -Members adm-scormier,adm-mlaurens

    # Quelques comptes désactivés
    New-ADUser -Name "Arnaud Trottier" -GivenName "Arnaud" -Surname "Trottier" -SamAccountName "atrottier" -Description "Désactivé le 14/06/2023" -UserPrincipalName "atrottier@$DOMAINDNS" -Path "OU=sales,$LDAPROOT" -AccountPassword (ConvertTo-SecureString "Hello123" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Out-Null
    New-ADUser -Name "Guillaume Brazier" -GivenName "Guillaume" -Surname "Brazier" -SamAccountName "gbrazier" -Description "Désactivé le 25/08/2023" -UserPrincipalName "gbrazier@$DOMAINDNS" -Path "OU=consultants,$LDAPROOT" -AccountPassword (ConvertTo-SecureString "Summer2024" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Out-Null

    # Comptes de service et SPN
    New-ADUser -Name "svc-sql" -GivenName "svc" -Surname "sql" -SamAccountName "svc-sql" -Description "Compte de service SQL" -UserPrincipalName "svc-sql@$DOMAINDNS" -Path "OU=SVC,$LDAPROOT" -AccountPassword (ConvertTo-SecureString "sql0v3-u" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount -PassThru  | Out-Null
    New-ADUser -Name "svc-backup" -GivenName "svc" -Surname "backup" -SamAccountName "svc-backup" -Description "Compte de service backup. Mdp: B4ckup-S3rv1c3" -UserPrincipalName "svc-backup@$DOMAINDNS" -Path "OU=SVC,$LDAPROOT" -AccountPassword (ConvertTo-SecureString "B4ckup-S3rv1c3" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Out-Null
    New-ADUser -Name "svc-legacy" -GivenName "svc" -Surname "legacy" -SamAccountName "svc-legacy" -Description "Compte de service pour app legacy" -UserPrincipalName "svc-legacy@$DOMAINDNS" -Path "OU=SVC,$LDAPROOT" -AccountPassword (ConvertTo-SecureString "Killthislegacy!" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
    Add-ADGroupMember -Identity "Backup" -Members svc-backup

    setspn -A $PCNAME/svc-sql.$DOMAINDNS:`60111 $DOMAIN\svc-sql > $null
    setspn -A svc-sql/$DOMAINDNS $DOMAIN\svc-sql > $null
    setspn -A DomainController/svc-sql.$DOMAINDNS:`60111 $DOMAIN\svc-sql > $null

    Get-ADUser -Identity "svc-legacy" | Set-ADAccountControl -DoesNotRequirePreAuth:$true

    # Share
    mkdir C:\Share
    New-SmbShare -Name "Share" -Path "C:\Share" -ChangeAccess "Utilisators" -FullAccess "Everyone" -WarningAction SilentlyContinue | Out-Null

    # For Passback attack
    Copy-Item -Path "_tools\LdapAdminPortable.zip" Destination "C:\Share\LdapAdminPortable.zip"

    # Creating and configuring Custom GPO
    Write-Host("`n  [++] Creating Custom GPO")
    New-GPO -Name "CustomGPO"

    # Setting registry values using the Custom GPO
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SYSTEM\CurrentControlSet\Services\FDResPub" -ValueName "DependOnService" -Type MultiString -Value "RpcSs\0http\0fpdhost\0LanmanWorkstation"  # Configures service dependencies for FDResPub
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ValueName "sc_fdredpub" -Type MultiString -Value "sc config fdrespub depend= RpcSs/http/fdphost/LanmanWorkstation"  # Adds FDResPub service configuration to startup
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\System\CurrentControlSet\Control\Terminal Server" -ValueName "fDenyTSConnections" -Value 0 -Type Dword | Out-Null  # Enables Remote Desktop connections
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ValueName "UserAuthentication" -Value 0 -Type Dword | Out-Null  # Enables Remote Desktop connections
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableLUA" -Value 0 -Type Dword | Out-Null  # Disables User Account Control (UAC)
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" -ValueName "LocalAccountTokenFilterPolicy" -Value 1 -Type Dword | Out-Null  # Allows full remote access for local accounts
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" -ValueName "AlwaysInstallElevated" -Value 1 -Type Dword | Out-Null  # Allows elevated privileges for MSI installations
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoUpdate" -Value 1 -Type Dword | Out-Null  # Disables automatic Windows updates
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" -ValueName "DisabledComponents" -Value 0x20 -Type Dword  # Prefer IPv4 over IPv6

    New-GPLink -Name "CustomGPO" -Target $LDAP -LinkEnabled Yes -Enforced Yes
    
    # GPP password
    New-Item "\\$PCNAME\sysvol\$DOMAINDNS\Policies\Groups.xml" -ItemType File -Value ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("PAA/AHgAbQBsACAAdgBlAHIAcwBpAG8AbgA9ACIAMQAuADAAIgAgAGUAbgBjAG8AZABpAG4AZwA9ACIAdQB0AGYALQA4ACIAIAA/AD4ADQAKADwARwByAG8AdQBwAHMAIABjAGwAcwBpAGQAPQAiAHsAZQAxADgAYgBkADMAMABiAC0AYwA3AGIAZAAtAGMAOQA5AGYALQA3ADgAYgBiAC0AMgAwADYAYgA0ADMANABkADAAYgAwADgAfQAiAD4ADQAKAAkAPABVAHMAZQByACAAYwBsAHMAaQBkAD0AIgB7AEQARgA1AEYAMQA4ADUANQAtADUAMQBFADUALQA0AGQAMgA0AC0AOABCADEAQQAtAEQAOQBCAEQARQA5ADgAQgBBADEARAAxAH0AIgAgAG4AYQBtAGUAPQAiAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAIAAoAGIAdQBpAGwAdAAtAGkAbgApACIAIABpAG0AYQBnAGUAPQAiADIAIgAgAGMAaABhAG4AZwBlAGQAPQAiADIAMAAxADUALQAwADIALQAxADgAIAAwADEAOgA1ADMAOgAwADEAIgAgAHUAaQBkAD0AIgB7AEQANQBGAEUANwAzADUAMgAtADgAMQBFADEALQA0ADIAQQAyAC0AQgA3AEQAQQAtADEAMQA4ADQAMAAyAEIARQA0AEMAMwAzAH0AIgA+AA0ACgAJAAkAPABQAHIAbwBwAGUAcgB0AGkAZQBzACAAYQBjAHQAaQBvAG4APQAiAFUAIgAgAG4AZQB3AE4AYQBtAGUAPQAiACIAIABmAHUAbABsAE4AYQBtAGUAPQAiACIAIABkAGUAcwBjAHIAaQBwAHQAaQBvAG4APQAiACIAIABjAHAAYQBzAHMAdwBvAHIAZAA9ACIAUgBJADEAMwAzAEIAMgBXAGwAMgBDAGkASQAwAEMAYQB1ADEARAB0AHIAdABUAGUAMwB3AGQARgB3AHoAQwBpAFcAQgA1AFAAUwBBAHgAWABNAEQAcwB0AGMAaABKAHQAMwBiAEwAMABVAGkAZQAwAEIAYQBaAC8ANwByAGQAUQBqAHUAZwBUAG8AbgBGADMAWgBXAEEASwBhADEAaQBSAHYAZAA0AEoARwBRACIAIABjAGgAYQBuAGcAZQBMAG8AZwBvAG4APQAiADAAIgAgAG4AbwBDAGgAYQBuAGcAZQA9ACIAMAAiACAAbgBlAHYAZQByAEUAeABwAGkAcgBlAHMAPQAiADAAIgAgAGEAYwBjAHQARABpAHMAYQBiAGwAZQBkAD0AIgAwACIAIABzAHUAYgBBAHUAdABoAG8AbgB0AHkAPQAiAFIASQBEAF8AQQBEAE0ASQBOACIAIAB1AHMAZQByAE4AYQBtAGUAPQAiAGkAbgBzAHQAYQBsAGwAcABjACIALwA+AA0ACgAJADwALwBVAHMAZQByAD4ADQAKADwALwBHAHIAbwB1AHAAcwA+AA==")))
}

function Invoke-LabSetup{
    if ($env:COMPUTERNAME -ne $PCNAME ) {
        Write-Host("`n  [++] First run detected. Modifying network config...")
        Set-IPAddress
        Write-Host("`n  [++] Removing MS Defender...")
        Nuke-Defender
        Write-Host("`n  [++] Modifying QoL")
        Get-QoL
        Write-Host("`n  [--] The server will be renamed and restarted")
        Start-Sleep -Seconds 5
        Rename-Computer -NewName $PCNAME -Restart

    } elseif ($env:USERDNSDOMAIN -ne $DOMAIN) {
        Write-Host("`n  [++] Second run detected, Installing roles...")
        Add-ADDS

    } elseif ($env:COMPUTERNAME -eq $PCNAME -and $env:USERDNSDOMAIN -eq $DOMAIN) {
        $exists = $false
        try {
            $user = Get-ADUser -Identity "svc-sql" -ErrorAction Stop
            $exists = $true
            Write-Host("Everything is installed")
        } catch {
            $exists = $false
        } if (-not $exists) {
            Write-Host("`n  [++] Third run detected. Adding AD CS and Users...")
            Add-ADCS
            Add-Users-to-Domain
        }
    }
}