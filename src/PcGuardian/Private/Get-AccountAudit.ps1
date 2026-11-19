function Get-AccountAudit {
    [CmdletBinding()]
    param()
    Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | ForEach-Object {
        New-Finding -Category 'Account' -Key "Admin:$($_.Name)" -Detail "$($_.ObjectClass) in Administrators"
    }
    Get-LocalUser -ErrorAction SilentlyContinue | Where-Object Enabled | ForEach-Object {
        New-Finding -Category 'Account' -Key "User:$($_.Name)" -Detail 'Enabled local user'
    }
}
