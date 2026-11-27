@{
    RootModule        = 'PcGuardian.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '6f1d2a54-3b7e-4c1a-9d52-7a0c5e8b9f13'
    Author            = 'pc-guardian contributors'
    Description       = 'Read-only Windows security audit with baseline diffing. Orchestrates Microsoft Defender; not an antivirus engine.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-GuardianRun', 'Set-GuardianVirusTotalKey', 'Install-GuardianScanner', 'Get-GuardianSafeItem', 'Add-GuardianSafeItem', 'Remove-GuardianSafeItem', 'Get-GuardianScannerStatus', 'Get-GuardianSetting', 'Set-GuardianSetting', 'Get-GuardianDailyScan', 'Add-GuardianDevFolder', 'Remove-GuardianDevFolder', 'Get-GuardianUpdateInfo', 'Save-GuardianUpdate', 'Add-GuardianIgnoredFile', 'Get-GuardianIgnoredFile', 'Remove-GuardianIgnoredFile', 'Install-GuardianPhoneTools', 'Get-GuardianPhoneStatus', 'Invoke-GuardianPhoneCheck')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{ PSData = @{ Tags = @('security', 'audit', 'defender', 'windows'); LicenseUri = '' } }
}
