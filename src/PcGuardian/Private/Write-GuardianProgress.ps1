function Write-GuardianProgress {
    <#
    .SYNOPSIS
        Emits one machine-readable progress line, only when the app asked for progress (-Progress).
    .DESCRIPTION
        Lines look like  PCG|<type>|<value>  and are read by the Windows app as they arrive.
        Types: phase (n|total|name), file (current item), count (items done), percent (0-100 within the current
        step, only when the amount of work is known), found (one finding as JSON).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('phase', 'file', 'count', 'percent', 'found')][string]$Type,
        [Parameter(Mandatory)][string[]]$Value
    )
    if ($script:ProgressEnabled) {
        # Keep each event on one line: a path or JSON must not contain a line break.
        $text = ($Value -join '|') -replace '[\r\n]+', ' '
        Write-Host ('PCG|{0}|{1}' -f $Type, $text)
    }
}

function Start-GuardianPhase {
    <#
    .SYNOPSIS
        Marks the start of the next numbered step of a run ("Step 3 of 6").
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    $script:PhaseIndex++
    Write-GuardianProgress -Type phase -Value @($script:PhaseIndex, $script:PhaseTotal, $Name)
}

function Write-GuardianFound {
    <#
    .SYNOPSIS
        Tells the app about a finding the moment it is found, before the scan finishes.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Finding)
    $o = [pscustomobject]@{
        Kind = 'Scan'; Severity = (Get-FindingSeverity -Finding $Finding)
        Category = $Finding.Category; Key = $Finding.Key; Detail = $Finding.Detail }
    Write-GuardianProgress -Type found -Value (ConvertTo-Json -InputObject $o -Compress)
}
