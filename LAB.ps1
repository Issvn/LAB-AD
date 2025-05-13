# ============================
# Role Mapping
# ============================
$roles = @{
    '1' = 'DC01'
    '2' = 'SRV01'
    '3' = 'PC01'
}

# Check if running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "⚠️ This script must be run as Administrator. Please restart PowerShell with elevated privileges."
    exit
}

# ============================
# Functions
# ============================
function Convert-ToLDAPRoot {
    param ([string]$domainDns)
    return ($domainDns.ToLower().Split('.') | ForEach-Object { "DC=$_" }) -join ','
}

function Prompt-ForDomain {
    while ($true) {
        $input = Read-Host "`nEnter the domain name (e.g., lab.int)"
        if ($input -match '^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$') {
            return $input
        } else {
            Write-Host "❌ Invalid format. Please enter a domain like 'example.local' or 'corp.internal'."
        }
    }
}

function Invoke-CloudSetup {
    param (
        [string]$Role,
        [string]$Domain,
        [string]$DomainDns,
        [string]$LdapRoot
    )
    $scriptUrl = "https://raw.githubusercontent.com/Issvn/LAB-AD/main/_scripts/$Role.ps1"
    $tempScript = "$env:TEMP\$Role.ps1"

    try {
        Write-Host "`nDownloading script from GitHub..."
        Invoke-WebRequest -Uri $scriptUrl -OutFile $tempScript -ErrorAction Stop
        Write-Host "Running script..."
        & $tempScript -PCNAME $Role -DOMAIN $Domain -DOMAINDNS $DomainDns -LDAPROOT $LdapRoot
        Invoke-LabSetup
    } catch {
        Write-Error "Error during script download or execution: $_"
    }
}

function Invoke-LocalSetup {
    param (
        [string]$Role,
        [string]$Domain,
        [string]$DomainDns,
        [string]$LdapRoot
    )
    $localScript = "_scripts/$Role.ps1"
    if (Test-Path $localScript) {
        Write-Host "`nRunning local script..."
        & $localScript -PCNAME $Role -DOMAIN $Domain -DOMAINDNS $DomainDns -LDAPROOT $LdapRoot
        Invoke-LabSetup
    } else {
        Write-Error "Local script '$localScript' not found."
    }
}

# ============================
# User Input
# ============================
$a = (Read-Host "Execution type:`n 1. Cloud (from GitHub)`n 2. Local (requires local repo)").Trim().ToLower()
$s = (Read-Host "`nSelect role to install:`n 1. Domain Controller (DC01)`n 2. Server (SRV01)`n 3. Client (PC01)`nEnter your choice").Trim()

if ($roles.ContainsKey($s)) {
    $selectedRole = $roles[$s]

    # Ask for domain name only if DC is selected
    if ($selectedRole -eq 'DC01') {
        $domainDns = Prompt-ForDomain
        $domain = $domainDns.Split('.')[0].ToUpper()
        $ldapRoot = Convert-ToLDAPRoot -domainDns $domainDns
    } else {
        # Default values for non-DC roles
        $domain = "LAB"
        $domainDns = "LAB.INT"
        $ldapRoot = Convert-ToLDAPRoot -domainDns $domainDns
    }

    switch ($a) {
        '1' { Invoke-CloudSetup -Role $selectedRole -Domain $domain -DomainDns $domainDns -LdapRoot $ldapRoot }
        'cloud' { Invoke-CloudSetup -Role $selectedRole -Domain $domain -DomainDns $domainDns -LdapRoot $ldapRoot }
        '2' { Invoke-LocalSetup -Role $selectedRole -Domain $domain -DomainDns $domainDns -LdapRoot $ldapRoot }
        'local' { Invoke-LocalSetup -Role $selectedRole -Domain $domain -DomainDns $domainDns -LdapRoot $ldapRoot }
        default { Write-Host "`nInvalid execution type." }
    }
} else {
    Write-Host "`nInvalid role selection."
}