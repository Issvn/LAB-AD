# NETBIOS Domain Name
$DOMAIN=NEVASEC
# Domain Name TLD
$DOMAINDNS=NEVASEC.LOCAL
# LDAP Root DN
$LDAPROOT="DC=nevasec,DC=local"

$c = @{ '1' = 'DC01'; '2' = 'SRV01'; '3' = 'PC01' }; 
$s = Read-Host "Role to install:`n 1. Domain Controller (DC01)`n 2. Server (SRV01)`n 3. Client (PC01)`nEnter your choice"; 

if ($c.ContainsKey($s)) { 
    (iwr -useb ("https://github.com/Issvn/LAB-AD/tree/main/_scripts/" + $c[$s] + ".ps1") -PCNAME=$c[$s] -DOMAIN=$DOMAIN -DOMAINDNS=$DOMAINDNS -LDAPROOT=$LDAPROOT); 
    Invoke-LabSetup
} else { 
    Write-Host "Invalid Choice"
}