function ConvertFrom-JsonDictionary {
    <#
    .SYNOPSIS
        Parses JSON into dictionaries on both Windows PowerShell 5.1 and PowerShell 7.
    .DESCRIPTION
        ConvertFrom-Json cannot read the empty-string key every modern package-lock.json contains (PowerShell 7
        refuses it; 5.1 has no -AsHashtable). PowerShell 7 uses -AsHashtable; 5.1 uses JavaScriptSerializer.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text)

    if ($PSVersionTable.PSVersion.Major -ge 7) { return ($Text | ConvertFrom-Json -AsHashtable) }
    Add-Type -AssemblyName System.Web.Extensions
    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $serializer.MaxJsonLength = [int]::MaxValue
    $serializer.RecursionLimit = 1000
    $serializer.DeserializeObject($Text)
}

function Test-DictionaryKey {
    <#
    .SYNOPSIS
        $true when a dictionary (Hashtable or the Dictionary that Windows PowerShell 5.1 returns) has the key.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Dictionary, [Parameter(Mandatory)][string]$Key)
    @($Dictionary.Keys) -contains $Key
}

function ConvertFrom-PackageLock {
    <#
    .SYNOPSIS
        Reads npm's package-lock.json (v1, v2 and v3) into a flat list of packages.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $json = ConvertFrom-JsonDictionary -Text (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop)
    if ($json -isnot [System.Collections.IDictionary]) { return }
    $seen = @{}
    function Add-Pkg($name, $version) {
        if (-not $name -or -not $version) { return }
        $k = "$name@$version"
        if (-not $seen[$k]) { $seen[$k] = $true; [pscustomobject]@{ Ecosystem = 'npm'; Name = "$name"; Version = "$version"; Source = $Path } }
    }
    function Add-NestedDependency($deps) {
        if ($deps -isnot [System.Collections.IDictionary]) { return }
        foreach ($name in @($deps.Keys)) {
            $entry = $deps[$name]
            if ($entry -isnot [System.Collections.IDictionary]) { continue }
            if ((Test-DictionaryKey $entry 'version')) { Add-Pkg $name $entry['version'] }
            if ((Test-DictionaryKey $entry 'dependencies')) { Add-NestedDependency $entry['dependencies'] }
        }
    }

    if ((Test-DictionaryKey $json 'packages') -and $json['packages'] -is [System.Collections.IDictionary]) {
        foreach ($key in @($json['packages'].Keys)) {
            if ($key -eq '') { continue }                                         # the project itself
            $entry = $json['packages'][$key]
            if ($entry -isnot [System.Collections.IDictionary]) { continue }
            if ((Test-DictionaryKey $entry 'link') -and $entry['link']) { continue }
            $name = if ((Test-DictionaryKey $entry 'name')) { $entry['name'] } else { ($key -split 'node_modules/')[-1] }
            $ver  = if ((Test-DictionaryKey $entry 'version')) { $entry['version'] } else { $null }
            Add-Pkg $name $ver
        }
    }
    elseif ((Test-DictionaryKey $json 'dependencies')) {
        Add-NestedDependency $json['dependencies']
    }
}

function ConvertFrom-RequirementsTxt {
    <#
    .SYNOPSIS
        Reads pinned packages (name==version) from a pip requirements file. Unpinned lines are skipped.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    foreach ($line in (Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        $t = ($line -replace '\s#.*$', '').Trim()
        if ($t -match '^(?<n>[A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*==\s*(?<v>[A-Za-z0-9._+!-]+)') {
            [pscustomobject]@{ Ecosystem = 'PyPI'; Name = $Matches.n; Version = $Matches.v; Source = $Path }
        }
    }
}

function Find-PackageManifest {
    <#
    .SYNOPSIS
        Finds package-lock.json and requirements.txt files in code folders (skipping dependency and build folders).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Roots, [int]$MaxDepth = 4, [int]$MaxFiles = 200)

    $skip = 'node_modules', '.git', 'venv', '.venv', '__pycache__', 'bin', 'obj', 'dist', 'build', 'AppData', 'site-packages'
    $found = 0
    foreach ($root in $Roots) {
        $queue = New-Object System.Collections.Generic.Queue[object]
        $queue.Enqueue(@{ Path = $root; Depth = 0 })
        while ($queue.Count -gt 0 -and $found -lt $MaxFiles) {
            $cur = $queue.Dequeue()
            foreach ($entry in (Get-ChildItem -LiteralPath $cur.Path -Force -ErrorAction SilentlyContinue)) {
                if ($entry.PSIsContainer) {
                    if ($cur.Depth -lt $MaxDepth -and $entry.Name -notin $skip -and -not ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                        $queue.Enqueue(@{ Path = $entry.FullName; Depth = $cur.Depth + 1 })
                    }
                }
                elseif ($entry.Name -in 'package-lock.json', 'requirements.txt') {
                    $found++; $entry.FullName
                }
            }
        }
    }
}

function Invoke-OsvQuery {
    <#
    .SYNOPSIS
        Asks osv.dev which of the given packages have known advisories. Sends only package name, ecosystem and version.
    .OUTPUTS
        One result per input package, in order: an object with a Vulns list of advisory ids.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Packages, [int]$BatchSize = 500)

    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    for ($i = 0; $i -lt $Packages.Count; $i += $BatchSize) {
        $chunk = @($Packages[$i..([Math]::Min($i + $BatchSize, $Packages.Count) - 1)])
        $body = @{ queries = @($chunk | ForEach-Object { @{ package = @{ name = $_.Name; ecosystem = $_.Ecosystem }; version = $_.Version } }) }
        $resp = Invoke-RestMethod -Uri 'https://api.osv.dev/v1/querybatch' -Method Post -ContentType 'application/json' `
            -Body ($body | ConvertTo-Json -Depth 6 -Compress) -TimeoutSec 60 -UserAgent 'pc-guardian'
        $results = @($resp.results)
        for ($j = 0; $j -lt $chunk.Count; $j++) {
            $ids = @()
            if ($j -lt $results.Count -and $results[$j] -and $results[$j].PSObject.Properties['vulns']) { $ids = @($results[$j].vulns | ForEach-Object { $_.id }) }
            [pscustomobject]@{ Vulns = $ids }
        }
    }
}

function ConvertFrom-OsvResult {
    <#
    .SYNOPSIS
        Turns packages plus their OSV results into findings: known-malicious packages one by one (Alert),
        ordinary vulnerabilities summarised once per project file (Info).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Packages, [Parameter(Mandatory)][object[]]$Results)

    $vulnBySource = @{}
    for ($i = 0; $i -lt $Packages.Count; $i++) {
        $p = $Packages[$i]
        $ids = @($Results[$i].Vulns)
        if ($ids.Count -eq 0) { continue }
        $mal = @($ids | Where-Object { $_ -like 'MAL-*' })
        if ($mal.Count -gt 0) {
            New-Finding -Category 'Package' -Key "Package:Malicious:$($p.Ecosystem):$($p.Name)@$($p.Version)" `
                -Detail "Known malicious package ($($mal -join ', ')) in $($p.Source). Remove it and rotate any secrets on this machine."
        }
        else {
            if (-not $vulnBySource[$p.Source]) { $vulnBySource[$p.Source] = New-Object System.Collections.Generic.List[string] }
            $vulnBySource[$p.Source].Add("$($p.Name)@$($p.Version)")
        }
    }
    foreach ($src in $vulnBySource.Keys) {
        $list = $vulnBySource[$src]
        $example = ($list | Select-Object -First 3) -join ', '
        New-Finding -Category 'Package' -Key "Package:Vulnerable:$src" -Detail "$($list.Count) package(s) with known vulnerabilities, for example $example"
    }
}

function Get-PackageRiskAudit {
    <#
    .SYNOPSIS
        Checks the packages your code projects depend on against OSV, including its list of known-malicious packages.
    .DESCRIPTION
        Opt-in and needs the network. Sends only package names, ecosystems and versions (public information) to
        api.osv.dev. Reads package-lock.json and pinned requirements.txt files in your code folders.
    #>
    [CmdletBinding()]
    param([string[]]$Roots, [int]$MaxPackages = 5000)

    if (-not $Roots) { $Roots = @(Get-DevFolderRoot) }
    if ($Roots.Count -eq 0) {
        return New-Finding -Category 'Scanner' -Key 'Package:NoFolders' -Detail 'No code folders were found to check. Set PCGUARDIAN_DEV_ROOTS to a semicolon-separated list of folders.'
    }
    Write-GuardianProgress -Type file -Value 'Looking for package lock files'
    $packages = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($file in (Find-PackageManifest -Roots $Roots)) {
        Write-GuardianProgress -Type file -Value $file
        $list = try {
            if ($file -like '*package-lock.json') { ConvertFrom-PackageLock -Path $file } else { ConvertFrom-RequirementsTxt -Path $file }
        } catch { @() }
        foreach ($pkg in $list) {
            $k = "$($pkg.Ecosystem)|$($pkg.Name)|$($pkg.Version)|$($pkg.Source)"
            if (-not $seen[$k] -and $packages.Count -lt $MaxPackages) { $seen[$k] = $true; $packages.Add($pkg) }
        }
    }
    if ($packages.Count -eq 0) { return }

    Write-GuardianProgress -Type file -Value "Checking $($packages.Count) packages against osv.dev"
    try { $results = @(Invoke-OsvQuery -Packages $packages.ToArray()) }
    catch { return New-Finding -Category 'Scanner' -Key 'Package:LookupFailed' -Detail "Could not reach osv.dev: $($_.Exception.Message)" }
    ConvertFrom-OsvResult -Packages $packages.ToArray() -Results $results
}
