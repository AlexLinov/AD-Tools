<#  
  Enable SAN override + Disable SID extension for AD CS  
  Works for: “PolicyModules\CertificateAuthority_MicrosoftDefault.Policy”   
#>

param(
    [Parameter(Mandatory=$true)]
    [string] $CAConfigString,

    [Parameter(Mandatory=$false)]
    [switch] $VerifyOnly
)

function Write-Log {
    param([string] $Msg)
    Write-Host "$(Get-Date -Format u) - $Msg"
}

# Instantiate COM object
$Admin = New-Object -ComObject CertificateAuthority.Admin

if ($VerifyOnly) {
    Write-Log "=== Verification Mode ==="
    try {
        $editFlags = $Admin.GetConfigEntry($CAConfigString, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags")
        Write-Log "Current EditFlags: 0x{0:X}" -f $editFlags
        $disableList = $Admin.GetConfigEntry($CAConfigString, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "DisableExtensionList")
        Write-Log "Current DisableExtensionList: $disableList"
    }
    catch {
        Write-Log "ERROR reading config entries: $_"
    }
    return
}

Write-Log "Reading current EditFlags..."
$currentEdit = $Admin.GetConfigEntry($CAConfigString, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags")
Write-Log "Current EditFlags value: 0x{0:X}" -f $currentEdit

$flag_SAN = 0x00040000
$newEdit = $currentEdit -bor $flag_SAN
Write-Log "Setting EditFlags to 0x{0:X} (adding EDITF_ATTRIBUTESUBJECTALTNAME2)" -f $newEdit
$Admin.SetConfigEntry($CAConfigString, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags", $newEdit)

Write-Log "Setting DisableExtensionList to omit SID extension (OID: 1.3.6.1.4.1.311.25.2)..."
$Admin.SetConfigEntry($CAConfigString, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "DisableExtensionList", "1.3.6.1.4.1.311.25.2")

Write-Log "Restarting CA service..."
Restart-Service certsvc -Force

Write-Log "=== Completed. Please reconnect to apply COM interface changes if working remotely. ==="
