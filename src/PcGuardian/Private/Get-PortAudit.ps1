function Get-PortAudit {
    [CmdletBinding()]
    param()
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' } |
        ForEach-Object {
            $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            [pscustomobject]@{ Port = $_.LocalPort; Process = $proc; Addr = $_.LocalAddress }
        } |
        Sort-Object Port, Process -Unique |
        ForEach-Object {
            New-Finding -Category 'Port' -Key "Port:$($_.Port):$($_.Process)" -Detail "Listening on $($_.Addr) ($($_.Process))"
        }
}
