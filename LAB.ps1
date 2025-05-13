$DOMAIN=NEVASEC
$DOMAINDNS=NEVASEC.LOCAL
$LDAPROOT="DC=nevasec,DC=local"

$c = @{ '1' = 'DC01'; '2' = 'SRV01'; '3' = 'PC01' }; 
$s = Read-Host "Machine à installer:`n1. Contrôleur de domaine (DC01)`n2. Serveur (SRV01)`n3. Client (PC01)`nEntrez votre choix (1/2/3):"; 

if ($c.ContainsKey($s)) { 
    (iex ("_scripts\" + $c[$s] + ".ps1") -PCNAME $c[$s] -DOMAIN=$DOMAIN -DOMAINDNS=$DOMAINDNS -LDAPROOT=$LDAPROOT); 
    Invoke-LabSetup
} else { 
    Write-Host "Choix invalide."
}