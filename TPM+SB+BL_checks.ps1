# ================================================
# FULL SYSTEM SECURITY AUDIT - PowerShell 7.5.4
# TPM SpecVersion (like tpm.msc), Secure Boot, BitLocker
# Multi-drive aware, clean outputs, auto-save audit
# ================================================

# --- Create timestamp for file output ---
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ScriptFolder = Split-Path -Parent $MyInvocation.MyCommand.Path
$AuditFile = Join-Path $ScriptFolder "WindowsSecurityAudit_$timestamp.txt"

# --- TPM Info ---
try {
    $TpmCim = Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm
    if ($TpmCim -and $TpmCim.SpecVersion) {

        $specStrings = $TpmCim.SpecVersion | ForEach-Object { $_.ToString() } | Where-Object { $_ -ne '' }
        if ($specStrings.Count -ge 2) {
            $SpecVer = "$($specStrings[0]).$($specStrings[1])"
        } elseif ($specStrings.Count -eq 1) {
            $SpecVer = "$($specStrings[0]).0"
        } else {
            $SpecVer = 'N/A'
        }

        $TpmInfo = [PSCustomObject]@{
            TPMPresent   = $true
            TPMReady     = $TpmCim.IsEnabled_InitialValue
            TPMOwned     = $TpmCim.IsOwned_InitialValue
            SpecVersion  = $SpecVer
        }
    } else {
        $TpmInfo = [PSCustomObject]@{
            TPMPresent   = $false
            TPMReady     = $false
            TPMOwned     = $false
            SpecVersion  = 'N/A'
        }
    }
} catch {
    $TpmInfo = [PSCustomObject]@{
        TPMPresent   = $false
        TPMReady     = $false
        TPMOwned     = $false
        SpecVersion  = 'N/A'
    }
}

# --- Secure Boot Info ---
try {
    $SecureBoot = Confirm-SecureBootUEFI
    $UEFIMode = (Get-CimInstance Win32_ComputerSystem).BootupState
    $SecureBootInfo = [PSCustomObject]@{
        SecureBootEnabled = if ($SecureBoot) { $true } else { $false }
        BootMode          = if ($UEFIMode -match "UEFI") { "UEFI" } else { "Legacy/BIOS" }
    }
} catch {
    $SecureBootInfo = [PSCustomObject]@{
        SecureBootEnabled = $false
        BootMode          = 'Unknown'
    }
}

# --- BitLocker Info ---
$Drives = Get-CimInstance Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3}
$BitLockerInfo = foreach ($disk in $Drives) {
    try {
        $bl = Get-BitLockerVolume -MountPoint $disk.DeviceID -ErrorAction SilentlyContinue
        if ($bl) {
            $KeyProtectors = ($bl.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ', '
            [PSCustomObject]@{
                DriveLetter         = $disk.DeviceID
                TPMPresent          = $TpmInfo.TPMPresent
                TPMReady            = $TpmInfo.TPMReady
                TPMOwned            = $TpmInfo.TPMOwned
                SpecVersion         = $TpmInfo.SpecVersion
                SecureBootEnabled   = $SecureBootInfo.SecureBootEnabled
                BootMode            = $SecureBootInfo.BootMode
                ProtectionStatus    = switch ($bl.ProtectionStatus) {0{"Disabled"}1{"Unknown"}2{"On"}Default{"N/A"}}
                LockStatus          = switch ($bl.LockStatus) {0{"Unlocked"}1{"Locked"}Default{"N/A"}}
                EncryptionMethod    = if ($bl.EncryptionMethod) { $bl.EncryptionMethod } else {"N/A"}
                PercentageEncrypted = if ($bl.EncryptionPercentage -ne $null) { [math]::Round($bl.EncryptionPercentage) } else {"N/A"}
                KeyProtectorTypes   = if ($KeyProtectors) { $KeyProtectors } else {"N/A"}
                AutoUnlock          = if ($bl.AutoUnlockEnabled -ne $null) { $bl.AutoUnlockEnabled } else {"N/A"}
            }
        } else {
            [PSCustomObject]@{
                DriveLetter         = $disk.DeviceID
                TPMPresent          = $TpmInfo.TPMPresent
                TPMReady            = $TpmInfo.TPMReady
                TPMOwned            = $TpmInfo.TPMOwned
                SpecVersion         = $TpmInfo.SpecVersion
                SecureBootEnabled   = $SecureBootInfo.SecureBootEnabled
                BootMode            = $SecureBootInfo.BootMode
                ProtectionStatus    = "Disabled"
                LockStatus          = "N/A"
                EncryptionMethod    = "N/A"
                PercentageEncrypted = "N/A"
                KeyProtectorTypes   = "N/A"
                AutoUnlock          = "N/A"
            }
        }
    } catch {
        [PSCustomObject]@{
            DriveLetter         = $disk.DeviceID
            TPMPresent          = $TpmInfo.TPMPresent
            TPMReady            = $TpmInfo.TPMReady
            TPMOwned            = $TpmInfo.TPMOwned
            SpecVersion         = $TpmInfo.SpecVersion
            SecureBootEnabled   = $SecureBootInfo.SecureBootEnabled
            BootMode            = $SecureBootInfo.BootMode
            ProtectionStatus    = "Error"
            LockStatus          = "Error"
            EncryptionMethod    = "Error"
            PercentageEncrypted = "Error"
            KeyProtectorTypes   = "Error"
            AutoUnlock          = "Error"
        }
    }
}

# --- Define column widths and header ---
$headerFmt = "{0,-6} {1,-8} {2,-8} {3,-8} {4,-10} {5,-8} {6,-12} {7,-12} {8,-10} {9,-15} {10,-8} {11,-20} {12,-10}"
$header = $headerFmt -f "Drive","TPMPres","TPMReady","TPMOwn","SpecVer","SB","BootMode","BLStatus","Lock","EncryptMethod","PctEnc","KeyProtectors","AutoUnlock"

# --- Console Output with Colors ---
Write-Host "`n=== TPM / Secure Boot / BitLocker Info ===" -ForegroundColor Green
Write-Host $header -ForegroundColor Green
Write-Host ("-" * 140) -ForegroundColor Green

foreach ($d in $BitLockerInfo) {
    $line = $headerFmt -f `
        $d.DriveLetter, 
        $d.TPMPresent, 
        $d.TPMReady, 
        $d.TPMOwned, 
        $d.SpecVersion, 
        $d.SecureBootEnabled, 
        $d.BootMode, 
        $d.ProtectionStatus, 
        $d.LockStatus, 
        $d.EncryptionMethod, 
        $d.PercentageEncrypted, 
        $d.KeyProtectorTypes, 
        $d.AutoUnlock
    Write-Host $line
}

# --- Save same formatted table to text file ---
$tableLines = @($header, "-"*140)
foreach ($d in $BitLockerInfo) {
    $tableLines += $headerFmt -f `
        $d.DriveLetter, 
        $d.TPMPresent, 
        $d.TPMReady, 
        $d.TPMOwned, 
        $d.SpecVersion, 
        $d.SecureBootEnabled, 
        $d.BootMode, 
        $d.ProtectionStatus, 
        $d.LockStatus, 
        $d.EncryptionMethod, 
        $d.PercentageEncrypted, 
        $d.KeyProtectorTypes, 
        $d.AutoUnlock
}
$tableLines | Out-File -FilePath $AuditFile -Encoding UTF8

Write-Host "`nAudit saved to $AuditFile" -ForegroundColor Cyan

# --- Quick Summary Placeholder ---
<# 
Write-Host "`n=== Quick Audit Summary ==="
foreach ($d in $BitLockerInfo) {
    $line = "Drive: $($d.DriveLetter) | TPM: $($d.TPMPresent)/$($d.TPMReady)/$($d.TPMOwned)/$($d.SpecVersion) | SecureBoot: $($d.SecureBootEnabled) | BL: $($d.ProtectionStatus)/$($d.LockStatus)/$($d.PercentageEncrypted)%/$($d.EncryptionMethod)/$($d.KeyProtectorTypes)"
    Write-Host $line
}
# Placeholder: Uncomment for multi-device audits, use Invoke-Command for remote collection
#>
