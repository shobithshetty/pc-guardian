function New-Finding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Key,
        [string]$Detail = ''
    )
    [pscustomobject]@{ Category = $Category; Key = $Key; Detail = $Detail }
}
