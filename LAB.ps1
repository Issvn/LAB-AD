# NETBIOS Domain Name
$DOMAIN=NEVASEC
# Domain Name TLD
$DOMAINDNS=NEVASEC.LOCAL
# LDAP Root DN
$LDAPROOT="DC=nevasec,DC=local"

$a = Read-Host "Execution type: `n 1. Cloud (from github.com)`n 2. Local (need to download the repo)"

$c = @{ '1' = 'DC01'; '2' = 'SRV01'; '3' = 'PC01' }; 
$s = Read-Host "`nRole to install:`n 1. Domain Controller (DC01)`n 2. Server (SRV01)`n 3. Client (PC01)`nEnter your choice"; 

if ($a -eq '1' -or $a -eq 'Cloud') {
    if ($c.ContainsKey($s)) { 
        (iwr -useb ("https://github.com/Issvn/LAB-AD/tree/main/_scripts/" + $c[$s] + ".ps1") -PCNAME=$c[$s] -DOMAIN=$DOMAIN -DOMAINDNS=$DOMAINDNS -LDAPROOT=$LDAPROOT); 
        Invoke-LabSetup
    } else { 
        Write-Host "Invalid Choice`n"
    }
} elseif ($a -eq '2' -or $a -eq 'Local') {
    if ($c.ContainsKey($s)) { 
        (iex ("_scripts/" + $c[$s] + ".ps1") -PCNAME=$($c[$s]) -DOMAIN=$DOMAIN -DOMAINDNS=$DOMAINDNS -LDAPROOT=$LDAPROOT);
        Invoke-LabSetup
    } else { 
        Write-Host "Invalid Choice`n"
    }
} else { 
    Write-Host "Invalid Choice`n"
}