# Requires PowerView (Get-DomainObjectAcl, ConvertFrom-SID)
# Enumerates interesting ACLs, resolves both ObjectSID and Trustee SID

param(
    [Parameter(Mandatory=$true)]
    [string]$Domain
)

function Resolve-SID {
    param([Parameter(Mandatory)][object]$SidLike)

    $sidString = $null
    try {
        switch ($SidLike.GetType().FullName) {
            "System.String" { if ($SidLike -match '^S-\d-\d+(-\d+)+$') { $sidString = $SidLike } }
            "System.Byte[]" { $sidString = (New-Object System.Security.Principal.SecurityIdentifier($SidLike, 0)).Value }
            "System.Security.Principal.SecurityIdentifier" { $sidString = $SidLike.Value }
            default { try { $sidString = [string]$SidLike } catch {} }
        }
    } catch {}

    $name = $null
    if ($sidString) {
        try {
            $name = ConvertFrom-SID -ObjectSID $sidString -Domain $Domain -ErrorAction Stop
        } catch {
            try { $name = (New-Object System.Security.Principal.SecurityIdentifier($sidString)).Translate([System.Security.Principal.NTAccount]).Value }
            catch { $name = $null }
        }
    }
    [pscustomobject]@{ SidString = $sidString; Name = $name }
}

function Get-RightsColor {
    param([string]$Rights)
    if ($Rights -match 'GenericAll|WriteOwner|WriteDacl') { return 'Red' }
    if ($Rights -match 'GenericWrite|WriteProperty')      { return 'Yellow' }
    return 'Green'
}

function Write-AclHit {
    param([pscustomobject]$R)

    $rightsColor = Get-RightsColor -Rights $R.Rights
    $trustee     = if ($R.TrusteeName) { $R.TrusteeName } else { $R.TrusteeSID }
    $target      = if ($R.ObjectName)  { $R.ObjectName }  else { $R.ObjectSID }
    $inheritCol  = if ($R.Inherited) { 'DarkGray' } else { 'White' }

    Write-Host "[RIGHTS] " -NoNewline -ForegroundColor DarkGray
    Write-Host $R.Rights -NoNewline -ForegroundColor $rightsColor
    Write-Host "  [TRUSTEE] " -NoNewline -ForegroundColor DarkGray
    Write-Host $trustee -NoNewline -ForegroundColor Cyan
    Write-Host "  [TARGET] " -NoNewline -ForegroundColor DarkGray
    Write-Host $target -NoNewline -ForegroundColor Magenta
    Write-Host "  [INHERITED] " -NoNewline -ForegroundColor DarkGray
    Write-Host $R.Inherited -ForegroundColor $inheritCol
}

$DomainSid = Get-DomainSid $Domain

$Results = Get-DomainObjectAcl -Domain $Domain -ResolveGUIDs -Identity * -ErrorAction SilentlyContinue |
Where-Object {
    ($_."ActiveDirectoryRights" -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner') -and
    ($_."AceType" -eq 'AccessAllowed') -and
    ($_."SecurityIdentifier" -match '^S-1-5-.*-[1-9]\d{3,}$') -and
    ($_."SecurityIdentifier" -notmatch $DomainSid)
} | ForEach-Object {
    $trustee = Resolve-SID -SidLike $_.SecurityIdentifier
    $obj     = Resolve-SID -SidLike $_.ObjectSID

    [pscustomobject]@{
        Rights      = $_.ActiveDirectoryRights
        TrusteeSID  = $trustee.SidString
        TrusteeName = $trustee.Name
        ObjectSID   = $obj.SidString
        ObjectName  = $obj.Name
        Inherited   = $_.IsInherited
        ObjectDN    = $_.ObjectDN
    }
} | Sort-Object ObjectName, TrusteeName

foreach ($r in $Results) { Write-AclHit -R $r }

# Optional export
# $Results | Export-Csv -NoTypeInformation -Encoding UTF8 -Path .\interesting_acls_resolved.csv
