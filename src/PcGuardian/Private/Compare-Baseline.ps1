function Compare-Baseline {
    <#
    .SYNOPSIS
        Diffs a current snapshot against a baseline by Category + Key.
    .OUTPUTS
        Object with .New and .Removed arrays of findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Baseline,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Current
    )
    $baseKeys = @{}
    foreach ($b in $Baseline) { $baseKeys["$($b.Category)|$($b.Key)"] = $true }
    $curKeys = @{}
    foreach ($c in $Current) { $curKeys["$($c.Category)|$($c.Key)"] = $true }

    [pscustomobject]@{
        New     = @($Current  | Where-Object { -not $baseKeys.ContainsKey("$($_.Category)|$($_.Key)") })
        Removed = @($Baseline | Where-Object { -not $curKeys.ContainsKey("$($_.Category)|$($_.Key)") })
    }
}
