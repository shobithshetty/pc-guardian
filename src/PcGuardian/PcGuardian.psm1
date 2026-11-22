Set-StrictMode -Version Latest

$script:ModuleRoot = $PSScriptRoot
# Progress reporting for the app. Off unless Invoke-GuardianRun -Progress turns it on.
$script:ProgressEnabled = $false
$script:PhaseIndex = 0
$script:PhaseTotal = 0

$publicFiles  = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public')  -Filter '*.ps1' -ErrorAction SilentlyContinue)
$privateFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -ErrorAction SilentlyContinue)

foreach ($file in @($privateFiles) + @($publicFiles)) {
    . $file.FullName
}

Export-ModuleMember -Function $publicFiles.BaseName
