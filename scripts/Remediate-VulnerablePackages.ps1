<#
.SYNOPSIS
    Idempotently remediates known-vulnerable NuGet packages in a .NET repository.

.DESCRIPTION
    Many .NET repos fail CI/CodeQL because NuGet's built-in security audit (NuGetAudit)
    is configured to treat advisories as errors (NU1901-NU1904), and a direct or
    transitive package has a known vulnerability. Because `dotnet restore` fails,
    downstream steps (build, test, CodeQL autobuild) fail too - even though there is
    no real code-security finding, just a blocked restore.

    This script fixes the CLASS of problem, not one instance:
      1. Discovers the solution/projects and whether Central Package Management
         (CPM, via Directory.Packages.props) is in use.
      2. Runs `dotnet restore` (and, as a supplementary/cross-check source,
         `dotnet list package --vulnerable --include-transitive --format json`)
         to enumerate every vulnerable package, its resolved version, and the
         GitHub Security Advisory (GHSA) backing it. Restore output is parsed
         directly because when NU190x is promoted to an ERROR, restore fails
         for the affected project(s) and `dotnet list package --vulnerable`
         cannot report on them (no project.assets.json) - so the authoritative
         signal in that case is the restore/build diagnostic text itself.
      3. For each vulnerable package, queries the public GitHub Advisory
         Database API (https://api.github.com/advisories/{GHSA_ID}) to find the
         nearest published version that clears every applicable advisory for
         the resolved version's line (e.g. 2.0.0 on the "2.x" line -> the first
         patched 2.x release, not an unrelated major bump).
      4. Applies the minimal fix:
           - DIRECT reference, non-CPM  -> bump <PackageReference Version=".."/>
             in that project's .csproj.
           - DIRECT reference, CPM      -> bump <PackageVersion Version=".."/>
             in Directory.Packages.props.
           - TRANSITIVE-only, non-CPM   -> add a new pinned
             <PackageReference Include="Id" Version="patched" /> to the
             consuming project(s) to force the safe version.
           - TRANSITIVE-only, CPM       -> add/update the
             <PackageVersion Include="Id" Version="patched" /> entry in
             Directory.Packages.props AND add a version-less
             <PackageReference Include="Id" /> to the consuming project(s).
             (Verified empirically: a CPM PackageVersion entry alone does NOT
             change resolution for a package that is not already referenced by
             that project - the bare PackageReference is required too.)
      5. Re-runs restore + build to confirm the fix actually clears the
         advisories and the solution still compiles.
      6. Prints a summary of every change (package, project/props file,
         old -> new version, advisory ids, direct/transitive).

    The script is idempotent: running it again on an already-clean repo is a
    no-op (exit 0), and re-running it after a partial fix will not duplicate
    XML nodes - existing PackageReference/PackageVersion entries are updated
    in place rather than re-added.

    HARD CONSTRAINTS (never violated by this script):
      - Never disables or relaxes NuGetAudit, NuGetAuditMode, NuGetAuditLevel,
        WarningsNotAsErrors, or TreatWarningsAsErrors.
      - Never deletes, skips, or disables tests.
      - Never edits any file outside of .csproj / Directory.Packages.props
        version metadata.

.PARAMETER RepoPath
    Path to the repository/working directory to remediate. Defaults to the
    current working directory.

.PARAMETER WhatIf
    Dry-run. Detects and reports what would change, including planned
    old -> new versions and advisory ids, but performs no file writes and does
    not attempt the post-fix restore/build verification (since nothing was
    written, there is nothing new to verify).

.PARAMETER Configuration
    Build configuration used for the verification build. Defaults to
    'Release' (this is what CI typically uses, and is where audit-as-error
    failures are most commonly hit).

.EXAMPLE
    ./Remediate-VulnerablePackages.ps1 -RepoPath C:\repos\TrainLoop

.EXAMPLE
    ./Remediate-VulnerablePackages.ps1 -WhatIf

.NOTES
    Exit codes:
      0 - No vulnerable packages found (no-op), OR all vulnerable packages
          were remediated and the post-fix restore + build succeeded.
      1 - One or more vulnerable packages could not be fully remediated
          (e.g. no patched version exists yet for the resolved version's
          line), or the post-fix build/restore verification failed. Details
          are printed to stderr/host describing exactly what is blocking.
      2 - Restore failed for reasons unrelated to the vulnerable-package
          audit pattern (the script deliberately refuses to "fix" unrelated
          build breaks - see printed diagnostic for the real error).
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$RepoPath = (Get-Location).Path,
    [string]$Configuration = 'Release'
)

# -WhatIf is supplied automatically by SupportsShouldProcess (a common
# parameter) and populates $WhatIfPreference - no separate [switch]$WhatIf
# parameter is declared here (PowerShell forbids redefining a common
# parameter). Every file write in this script is gated behind
# $PSCmdlet.ShouldProcess(), which respects -WhatIf natively.
$IsDryRun = [bool]$WhatIfPreference

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --------------------------------------------------------------------------
# Small utilities
# --------------------------------------------------------------------------

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host "=== $Title ===" -ForegroundColor Cyan
}

function Write-Info    { param([string]$Message) Write-Host "  $Message" }
function Write-Warn    { param([string]$Message) Write-Host "  WARNING: $Message" -ForegroundColor Yellow }
function Write-ErrLine { param([string]$Message) Write-Host "  ERROR: $Message" -ForegroundColor Red }
function Write-Ok      { param([string]$Message) Write-Host "  OK: $Message" -ForegroundColor Green }

# NuGet/SemVer-ish version comparison. Handles up to 4 numeric parts plus an
# optional -prerelease suffix, which covers the overwhelming majority of
# NuGet package versions (including GHSA advisory range endpoints).
function ConvertTo-VersionParts {
    param([Parameter(Mandatory)][string]$Version)
    $core = $Version
    $pre = $null
    if ($Version -match '^(?<core>[0-9]+(\.[0-9]+){0,3})(-(?<pre>.+))?$') {
        $core = $Matches['core']
        $pre = $Matches['pre']
    }
    $parts = @($core -split '\.' | ForEach-Object { [int]$_ })
    while ($parts.Count -lt 4) { $parts += 0 }
    [PSCustomObject]@{ Parts = $parts; Pre = $pre }
}

function Compare-NuGetVersion {
    param([Parameter(Mandatory)][string]$VersionA, [Parameter(Mandatory)][string]$VersionB)
    $a = ConvertTo-VersionParts $VersionA
    $b = ConvertTo-VersionParts $VersionB
    for ($i = 0; $i -lt 4; $i++) {
        if ($a.Parts[$i] -ne $b.Parts[$i]) { return [Math]::Sign($a.Parts[$i] - $b.Parts[$i]) }
    }
    if (-not $a.Pre -and -not $b.Pre) { return 0 }
    if (-not $a.Pre) { return 1 }   # release > prerelease
    if (-not $b.Pre) { return -1 }
    return [string]::Compare($a.Pre, $b.Pre, [StringComparison]::OrdinalIgnoreCase)
}

# Evaluates a GitHub Advisory `vulnerable_version_range` expression, e.g.
# ">= 2.0.0-preview11, <= 2.7.4" or "< 4.0.0", against a concrete version.
function Test-VersionInRange {
    param([Parameter(Mandatory)][string]$Version, [Parameter(Mandatory)][string]$RangeExpr)
    $clauses = $RangeExpr -split ','
    foreach ($clause in $clauses) {
        $c = $clause.Trim()
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        if ($c -notmatch '^(?<op>>=|<=|>|<|=)\s*(?<ver>\S+)$') { continue }
        $op = $Matches['op']; $ver = $Matches['ver']
        $cmp = Compare-NuGetVersion -VersionA $Version -VersionB $ver
        switch ($op) {
            '>=' { if ($cmp -lt 0) { return $false } }
            '<=' { if ($cmp -gt 0) { return $false } }
            '>'  { if ($cmp -le 0) { return $false } }
            '<'  { if ($cmp -ge 0) { return $false } }
            '='  { if ($cmp -ne 0) { return $false } }
        }
    }
    return $true
}

# --------------------------------------------------------------------------
# GitHub Advisory lookup (generic - never hardcodes a package/version)
# --------------------------------------------------------------------------

$script:AdvisoryCache = @{}

function Get-GithubAdvisory {
    param([Parameter(Mandatory)][string]$GhsaId)
    if ($script:AdvisoryCache.ContainsKey($GhsaId)) { return $script:AdvisoryCache[$GhsaId] }

    $result = $null
    if (Get-Command gh -ErrorAction SilentlyContinue) {
        try {
            $json = & gh api "advisories/$GhsaId" 2>$null
            if ($LASTEXITCODE -eq 0 -and $json) { $result = ($json -join "`n") | ConvertFrom-Json }
        } catch { $result = $null }
    }
    if (-not $result) {
        try {
            $headers = @{ 'User-Agent' = 'Remediate-VulnerablePackages.ps1'; 'Accept' = 'application/vnd.github+json' }
            if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $($env:GITHUB_TOKEN)" }
            $result = Invoke-RestMethod -Uri "https://api.github.com/advisories/$GhsaId" -Headers $headers -ErrorAction Stop
        } catch { $result = $null }
    }
    $script:AdvisoryCache[$GhsaId] = $result
    return $result
}

function Get-GhsaIdFromUrl {
    param([string]$Url)
    if ($Url -match '(GHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4})') { return $Matches[1] }
    return $null
}

# Given a package id, its currently-resolved (vulnerable) version, and one or
# more advisory URLs affecting it, returns the minimal version that clears
# every applicable advisory - or a set of blockers if that isn't possible.
function Resolve-PatchedVersion {
    param(
        [Parameter(Mandatory)][string]$PackageId,
        [Parameter(Mandatory)][string]$ResolvedVersion,
        [Parameter(Mandatory)][string[]]$AdvisoryUrls
    )
    $best = $null
    $blockers = @()
    foreach ($url in ($AdvisoryUrls | Sort-Object -Unique)) {
        $ghsa = Get-GhsaIdFromUrl -Url $url
        if (-not $ghsa) { $blockers += "Could not parse advisory id from URL: $url"; continue }

        $advisory = Get-GithubAdvisory -GhsaId $ghsa
        if (-not $advisory) { $blockers += "$ghsa (advisory lookup failed - network/rate-limit?)"; continue }

        $pkgVulns = @($advisory.vulnerabilities | Where-Object {
            $_.package.ecosystem -eq 'nuget' -and $_.package.name -ieq $PackageId
        })
        if ($pkgVulns.Count -eq 0) {
            # Advisory doesn't (or no longer) apply to this exact package id; skip.
            continue
        }

        $applicable = @($pkgVulns | Where-Object { Test-VersionInRange -Version $ResolvedVersion -RangeExpr $_.vulnerable_version_range })
        if ($applicable.Count -eq 0) {
            # Resolved version isn't actually in the vulnerable range per the
            # advisory data (e.g. metadata mismatch) - nothing to do for this URL.
            continue
        }

        foreach ($m in $applicable) {
            if (-not $m.first_patched_version) {
                $blockers += "$ghsa (no patched version published yet for this range: $($m.vulnerable_version_range))"
                continue
            }
            if (-not $best -or (Compare-NuGetVersion -VersionA $m.first_patched_version -VersionB $best) -gt 0) {
                $best = $m.first_patched_version
            }
        }
    }

    [PSCustomObject]@{
        PackageId      = $PackageId
        PatchedVersion = $best
        Blockers       = $blockers
    }
}

# --------------------------------------------------------------------------
# Repo discovery
# --------------------------------------------------------------------------

function Find-AllProjects {
    param([Parameter(Mandatory)][string]$RepoPath)
    return @(Get-ChildItem -Path $RepoPath -Filter '*.csproj' -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
}

# Returns an array of dotnet restore/build/list "targets": either a single
# .slnx, a single .sln, or - when neither exists at the repo root - every
# discovered .csproj individually (so multi-project repos without a solution
# file are still fully covered; `dotnet restore <directory>` is not valid
# MSBuild usage, so a directory is never handed to dotnet as a positional
# argument).
function Find-RestoreTargets {
    param([Parameter(Mandatory)][string]$RepoPath)
    $slnx = @(Get-ChildItem -Path $RepoPath -Filter '*.slnx' -File -ErrorAction SilentlyContinue)
    if ($slnx.Count -ge 1) { return @($slnx[0].FullName) }
    $sln = @(Get-ChildItem -Path $RepoPath -Filter '*.sln' -File -ErrorAction SilentlyContinue)
    if ($sln.Count -ge 1) { return @($sln[0].FullName) }
    $projects = @(Find-AllProjects -RepoPath $RepoPath)
    if ($projects.Count -ge 1) { return $projects }
    return @()
}

function Find-CentralPackageManagementFile {
    param([Parameter(Mandatory)][string]$RepoPath)
    $props = @(Get-ChildItem -Path $RepoPath -Filter 'Directory.Packages.props' -File -Recurse -ErrorAction SilentlyContinue)
    if ($props.Count -ge 1) {
        # Prefer the one closest to the repo root.
        return ($props | Sort-Object { $_.FullName.Length } | Select-Object -First 1).FullName
    }
    return $null
}

# --------------------------------------------------------------------------
# dotnet invocation helpers
# --------------------------------------------------------------------------

function Invoke-DotnetCommand {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'dotnet'
    foreach ($a in $Arguments) { $psi.ArgumentList.Add($a) }
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    [PSCustomObject]@{
        ExitCode = $proc.ExitCode
        StdOut   = $stdout
        StdErr   = $stderr
        Combined = "$stdout`n$stderr"
    }
}

# Runs a dotnet command once per target (a single .slnx/.sln, or one call
# per discovered .csproj when there's no solution file) and merges the
# results: Combined/StdOut text is concatenated (so downstream regex/JSON
# parsing sees everything), and ExitCode is the first non-zero code
# encountered (0 only if every invocation succeeded).
function Invoke-DotnetCommandOverTargets {
    param([Parameter(Mandatory)][string[]]$Targets, [Parameter(Mandatory)][string[]]$BaseArguments)
    if ($Targets.Count -eq 0) {
        throw "No project, solution, or .csproj files were found under '$RepoPath'."
    }
    $combined = New-Object System.Text.StringBuilder
    $stdOutAll = New-Object System.Text.StringBuilder
    $exitCode = 0
    foreach ($t in $Targets) {
        $rest = if ($BaseArguments.Count -gt 1) { $BaseArguments[1..($BaseArguments.Count - 1)] } else { @() }
        $argList = @($BaseArguments[0], $t) + $rest
        Write-Info "Running: dotnet $($argList -join ' ')"
        $r = Invoke-DotnetCommand -Arguments $argList
        [void]$combined.AppendLine($r.Combined)
        [void]$stdOutAll.AppendLine($r.StdOut)
        if ($r.ExitCode -ne 0 -and $exitCode -eq 0) { $exitCode = $r.ExitCode }
    }
    [PSCustomObject]@{
        ExitCode = $exitCode
        StdOut   = $stdOutAll.ToString()
        Combined = $combined.ToString()
    }
}

function Invoke-Restore {
    param([Parameter(Mandatory)][string[]]$Targets)
    return Invoke-DotnetCommandOverTargets -Targets $Targets -BaseArguments @('restore')
}

function Invoke-BuildVerification {
    param([Parameter(Mandatory)][string[]]$Targets, [string]$Configuration)
    return Invoke-DotnetCommandOverTargets -Targets $Targets -BaseArguments @('build', '--configuration', $Configuration, '--no-restore')
}

# --------------------------------------------------------------------------
# Vulnerable-package discovery
# --------------------------------------------------------------------------

# NU1901 = low, NU1902 = moderate, NU1903 = high, NU1904 = critical.
# Matches both plain warnings (audit=warn) and "Warning As Error" promotions
# (audit=error), on both Windows (drive-letter paths) and Linux runners - the
# " : " (space-colon-space) MSBuild diagnostic delimiter is what's anchored
# on, not the path shape itself.
$script:VulnLineRegex = '(?m)^\s*(?<proj>.+?)\s:\s(?<level>warning|error)\s(?<code>NU190[1-4]):\s(?:Warning As Error:\s)?Package\s''(?<pkg>[^'']+)''\s(?<ver>\S+)\shas a known (?<sev>\w+) severity vulnerability,\s*(?<url>\S+)'

function Get-VulnerabilitiesFromDiagnosticText {
    param([Parameter(Mandatory)][string]$Text)
    $found = New-Object System.Collections.Generic.List[object]
    foreach ($m in [regex]::Matches($Text, $script:VulnLineRegex)) {
        $found.Add([PSCustomObject]@{
            ProjectPath  = $m.Groups['proj'].Value.Trim()
            PackageId    = $m.Groups['pkg'].Value
            ResolvedVer  = $m.Groups['ver'].Value
            Severity     = $m.Groups['sev'].Value
            AdvisoryUrl  = $m.Groups['url'].Value
            Source       = 'restore-diagnostic'
        })
    }
    return $found
}

function Get-VulnerabilitiesFromListCommandSingleTarget {
    param([Parameter(Mandatory)][string]$Target)
    $args = @('list', $Target, 'package', '--vulnerable', '--include-transitive', '--format', 'json')
    Write-Info "Running: dotnet $($args -join ' ')"
    $result = Invoke-DotnetCommand -Arguments $args

    $found = New-Object System.Collections.Generic.List[object]
    $parsed = $null
    try { $parsed = $result.StdOut | ConvertFrom-Json -ErrorAction Stop } catch { $parsed = $null }

    if ($parsed -and $parsed.PSObject.Properties.Name -contains 'projects') {
        foreach ($proj in $parsed.projects) {
            if (-not ($proj.PSObject.Properties.Name -contains 'frameworks')) { continue }
            foreach ($fw in $proj.frameworks) {
                $topLevelList = if ($fw.PSObject.Properties.Name -contains 'topLevelPackages') { $fw.topLevelPackages } else { @() }
                $transitiveList = if ($fw.PSObject.Properties.Name -contains 'transitivePackages') { $fw.transitivePackages } else { @() }
                foreach ($top in @($topLevelList)) {
                    if (-not $top) { continue }
                    $topVulns = if ($top.PSObject.Properties.Name -contains 'vulnerabilities') { $top.vulnerabilities } else { @() }
                    foreach ($v in @($topVulns)) {
                        $found.Add([PSCustomObject]@{
                            ProjectPath = $proj.path
                            PackageId   = $top.id
                            ResolvedVer = $top.resolvedVersion
                            Severity    = $v.severity
                            AdvisoryUrl = $v.advisoryurl
                            Source      = 'list-package-direct'
                            IsDirect    = $true
                        })
                    }
                }
                foreach ($trans in @($transitiveList)) {
                    if (-not $trans) { continue }
                    $transVulns = if ($trans.PSObject.Properties.Name -contains 'vulnerabilities') { $trans.vulnerabilities } else { @() }
                    foreach ($v in @($transVulns)) {
                        $found.Add([PSCustomObject]@{
                            ProjectPath = $proj.path
                            PackageId   = $trans.id
                            ResolvedVer = $trans.resolvedVersion
                            Severity    = $v.severity
                            AdvisoryUrl = $v.advisoryurl
                            Source      = 'list-package-transitive'
                            IsDirect    = $false
                        })
                    }
                }
            }
        }
        return $found
    }

    # Fallback: format json unsupported (older SDK) or restore was broken -
    # try to parse the human-readable table as a last resort.
    $textRegex = '(?m)^\s*>\s(?<pkg>\S+)\s+(?:\S+\s+)?(?<resolved>\S+)\s+(?<sev>Low|Moderate|High|Critical)\s+(?<url>\S+)\s*$'
    foreach ($m in [regex]::Matches($result.StdOut, $textRegex)) {
        $found.Add([PSCustomObject]@{
            ProjectPath = $null
            PackageId   = $m.Groups['pkg'].Value
            ResolvedVer = $m.Groups['resolved'].Value
            Severity    = $m.Groups['sev'].Value
            AdvisoryUrl = $m.Groups['url'].Value
            Source      = 'list-package-text-fallback'
        })
    }
    return $found
}

# Each target gets its own `dotnet list package --vulnerable --format json`
# invocation and is parsed as its own independent JSON document (concatenated
# JSON text from multiple invocations is not itself valid JSON, so - unlike
# restore/build - this cannot reuse the generic multi-target text-merge
# helper).
function Get-VulnerabilitiesFromListCommand {
    param([Parameter(Mandatory)][string[]]$Targets)
    $found = New-Object System.Collections.Generic.List[object]
    foreach ($t in $Targets) {
        foreach ($item in (Get-VulnerabilitiesFromListCommandSingleTarget -Target $t)) { $found.Add($item) }
    }
    return $found
}

function Get-PackageRefXPath {
    param([Parameter(Mandatory)][string]$ElementName, [Parameter(Mandatory)][string]$PackageId)
    $lower = $PackageId.ToLowerInvariant()
    return "//$ElementName[translate(@Include,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='$lower']"
}

function Test-DirectReference {
    param([Parameter(Mandatory)][string]$ProjectPath, [Parameter(Mandatory)][string]$PackageId)
    if (-not (Test-Path $ProjectPath)) { return $false }
    $xml = Get-CsprojXmlDoc -Path $ProjectPath
    $node = $xml.SelectSingleNode((Get-PackageRefXPath -ElementName 'PackageReference' -PackageId $PackageId))
    return $null -ne $node
}

# --------------------------------------------------------------------------
# Remediation (file edits)
#
# All XML is loaded with PreserveWhitespace=true and saved without an XML
# declaration and without re-indenting, so that edits show up as minimal,
# reviewable diffs (attribute-only changes for version bumps; a single
# cleanly-indented new line for added PackageReference/PackageVersion
# entries) rather than reformatting the whole file. The original file's
# UTF-8 BOM presence/absence is preserved either way, again to keep diffs
# limited to the actual content change.
# --------------------------------------------------------------------------

$script:Changes = New-Object System.Collections.Generic.List[object]

function Test-FileHasUtf8Bom {
    param([Parameter(Mandatory)][string]$Path)
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $buffer = New-Object byte[] 3
        $read = $stream.Read($buffer, 0, 3)
        return ($read -eq 3 -and $buffer[0] -eq 0xEF -and $buffer[1] -eq 0xBB -and $buffer[2] -eq 0xBF)
    } finally { $stream.Dispose() }
}

function Get-CsprojXmlDoc {
    param([Parameter(Mandatory)][string]$Path)
    $doc = New-Object System.Xml.XmlDocument
    $doc.PreserveWhitespace = $true
    $doc.Load($Path)
    return $doc
}

function Save-XmlPreservingFormat {
    param([Parameter(Mandatory)][System.Xml.XmlDocument]$Xml, [Parameter(Mandatory)][string]$Path)
    $hadBom = Test-FileHasUtf8Bom -Path $Path
    $encoding = New-Object System.Text.UTF8Encoding($hadBom)
    $settings = [System.Xml.XmlWriterSettings]::new()
    $settings.Indent = $false
    $settings.OmitXmlDeclaration = $true
    $settings.NewLineChars = "`n"
    $settings.Encoding = $encoding
    $streamWriter = New-Object System.IO.StreamWriter($Path, $false, $encoding)
    try {
        $xmlWriter = [System.Xml.XmlWriter]::Create($streamWriter, $settings)
        try { $Xml.Save($xmlWriter) } finally { $xmlWriter.Dispose() }
    } finally {
        $streamWriter.Dispose()
    }
}

# Inserts $NewChild into $Parent, copying the indentation whitespace used by
# $Parent's existing element children (falling back to a sane default for an
# empty item group), and preserves the whitespace that precedes the parent's
# closing tag rather than appending after it.
function Add-XmlElementIndented {
    param(
        [Parameter(Mandatory)][System.Xml.XmlElement]$Parent,
        [Parameter(Mandatory)][System.Xml.XmlElement]$NewChild
    )
    $doc = $Parent.OwnerDocument
    $existingElementChildren = @($Parent.ChildNodes | Where-Object { $_ -is [System.Xml.XmlElement] })
    $indent = "`n    "
    if ($existingElementChildren.Count -gt 0) {
        $firstChild = $existingElementChildren[0]
        if ($firstChild.PreviousSibling -and $firstChild.PreviousSibling.NodeType -eq [System.Xml.XmlNodeType]::Whitespace) {
            $indent = $firstChild.PreviousSibling.Value
        }
    }
    $lastNode = $Parent.LastChild
    if ($lastNode -and $lastNode.NodeType -eq [System.Xml.XmlNodeType]::Whitespace) {
        $Parent.InsertBefore($NewChild, $lastNode) | Out-Null
        $Parent.InsertBefore($doc.CreateWhitespace($indent), $NewChild) | Out-Null
    } else {
        $Parent.AppendChild($doc.CreateWhitespace($indent)) | Out-Null
        $Parent.AppendChild($NewChild) | Out-Null
    }
}

# Creates a brand-new top-level ItemGroup (only needed when a project/props
# file has no existing ItemGroup containing the relevant element type) and
# wires it into the document root with matching indentation.
function Add-XmlTopLevelItemGroup {
    param([Parameter(Mandatory)][System.Xml.XmlDocument]$Doc)
    $root = $Doc.DocumentElement
    $existingElementChildren = @($root.ChildNodes | Where-Object { $_ -is [System.Xml.XmlElement] })
    $indent = "`n  "
    if ($existingElementChildren.Count -gt 0) {
        $firstChild = $existingElementChildren[0]
        if ($firstChild.PreviousSibling -and $firstChild.PreviousSibling.NodeType -eq [System.Xml.XmlNodeType]::Whitespace) {
            $indent = $firstChild.PreviousSibling.Value
        }
    }
    $itemGroup = $Doc.CreateElement('ItemGroup')
    $lastNode = $root.LastChild
    if ($lastNode -and $lastNode.NodeType -eq [System.Xml.XmlNodeType]::Whitespace) {
        $root.InsertBefore($itemGroup, $lastNode) | Out-Null
        $root.InsertBefore($Doc.CreateWhitespace($indent), $itemGroup) | Out-Null
    } else {
        $root.AppendChild($Doc.CreateWhitespace($indent)) | Out-Null
        $root.AppendChild($itemGroup) | Out-Null
    }
    return $itemGroup
}

function Set-DirectPackageReferenceVersion {
    param([Parameter(Mandatory)][string]$ProjectPath, [Parameter(Mandatory)][string]$PackageId, [Parameter(Mandatory)][string]$NewVersion)
    $xml = Get-CsprojXmlDoc -Path $ProjectPath
    $node = $xml.SelectSingleNode((Get-PackageRefXPath -ElementName 'PackageReference' -PackageId $PackageId))
    if (-not $node) { throw "Set-DirectPackageReferenceVersion: '$PackageId' not found as a direct PackageReference in $ProjectPath" }
    $oldVersion = $node.GetAttribute('Version')
    if ($oldVersion -eq $NewVersion) { return $false }
    if (-not $PSCmdlet.ShouldProcess($ProjectPath, "Bump PackageReference $PackageId $oldVersion -> $NewVersion")) { return $false }
    $node.SetAttribute('Version', $NewVersion)
    Save-XmlPreservingFormat -Xml $xml -Path $ProjectPath
    return $true
}

function Set-CpmPackageVersion {
    param([Parameter(Mandatory)][string]$PropsPath, [Parameter(Mandatory)][string]$PackageId, [Parameter(Mandatory)][string]$NewVersion)
    $xml = Get-CsprojXmlDoc -Path $PropsPath
    $node = $xml.SelectSingleNode((Get-PackageRefXPath -ElementName 'PackageVersion' -PackageId $PackageId))
    if ($node) {
        $oldVersion = $node.GetAttribute('Version')
        if ($oldVersion -eq $NewVersion) { return $false }
        if (-not $PSCmdlet.ShouldProcess($PropsPath, "Bump PackageVersion $PackageId $oldVersion -> $NewVersion")) { return $false }
        $node.SetAttribute('Version', $NewVersion)
    } else {
        if (-not $PSCmdlet.ShouldProcess($PropsPath, "Add PackageVersion $PackageId $NewVersion (security pin)")) { return $false }
        $itemGroup = $xml.SelectSingleNode('//ItemGroup[PackageVersion]')
        if (-not $itemGroup) { $itemGroup = Add-XmlTopLevelItemGroup -Doc $xml }
        $newNode = $xml.CreateElement('PackageVersion')
        $newNode.SetAttribute('Include', $PackageId)
        $newNode.SetAttribute('Version', $NewVersion)
        Add-XmlElementIndented -Parent $itemGroup -NewChild $newNode
    }
    Save-XmlPreservingFormat -Xml $xml -Path $PropsPath
    return $true
}

function Add-TransitivePackagePin {
    param([Parameter(Mandatory)][string]$ProjectPath, [Parameter(Mandatory)][string]$PackageId, [Parameter(Mandatory)][string]$NewVersion, [Parameter(Mandatory)][bool]$IsCpm)
    $xml = Get-CsprojXmlDoc -Path $ProjectPath
    $existing = $xml.SelectSingleNode((Get-PackageRefXPath -ElementName 'PackageReference' -PackageId $PackageId))
    if ($existing) {
        # Already a direct reference (maybe added by a previous run, or by
        # another advisory affecting the same package) - just make sure the
        # version is correct for the non-CPM case; CPM references carry no
        # Version attribute by design.
        if (-not $IsCpm) {
            $old = $existing.GetAttribute('Version')
            if ($old -eq $NewVersion) { return $false }
            if (-not $PSCmdlet.ShouldProcess($ProjectPath, "Bump pinned PackageReference $PackageId $old -> $NewVersion")) { return $false }
            $existing.SetAttribute('Version', $NewVersion)
            Save-XmlPreservingFormat -Xml $xml -Path $ProjectPath
            return $true
        }
        return $false
    }

    $desc = if ($IsCpm) { "Add version-less PackageReference $PackageId (CPM security pin, patched via Directory.Packages.props)" }
            else { "Add pinned PackageReference $PackageId $NewVersion (security pin for transitive dependency)" }
    if (-not $PSCmdlet.ShouldProcess($ProjectPath, $desc)) { return $false }

    $itemGroup = $xml.SelectSingleNode('//ItemGroup[PackageReference]')
    if (-not $itemGroup) { $itemGroup = Add-XmlTopLevelItemGroup -Doc $xml }
    $newNode = $xml.CreateElement('PackageReference')
    $newNode.SetAttribute('Include', $PackageId)
    if (-not $IsCpm) { $newNode.SetAttribute('Version', $NewVersion) }
    Add-XmlElementIndented -Parent $itemGroup -NewChild $newNode
    Save-XmlPreservingFormat -Xml $xml -Path $ProjectPath
    return $true
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

$RepoPath = (Resolve-Path -Path $RepoPath).Path
Write-Section "Remediate-VulnerablePackages"
Write-Info "RepoPath       : $RepoPath"
Write-Info "Mode           : $(if ($IsDryRun) { 'WhatIf (dry-run, no writes)' } else { 'Live' })"
Write-Info "Configuration  : $Configuration"

$targets = @(Find-RestoreTargets -RepoPath $RepoPath)
$cpmPropsPath = Find-CentralPackageManagementFile -RepoPath $RepoPath
$isCpm = [bool]$cpmPropsPath
if ($targets.Count -eq 0) {
    Write-ErrLine "No .slnx, .sln, or .csproj files were found under '$RepoPath'."
    exit 2
}
Write-Info "Restore target(s): $($targets -join ', ')"
Write-Info "CPM in use        : $isCpm$(if ($isCpm) { " ($cpmPropsPath)" })"

Write-Section "Restore (initial)"
$restoreResult = Invoke-Restore -Targets $targets
Write-Info "dotnet restore exit code: $($restoreResult.ExitCode)"

$diagnosticVulns = Get-VulnerabilitiesFromDiagnosticText -Text $restoreResult.Combined
$listVulns = Get-VulnerabilitiesFromListCommand -Targets $targets

# Merge both sources, de-duplicating on (ProjectPath, PackageId, ResolvedVer).
$allVulns = New-Object System.Collections.Generic.List[object]
$seenKeys = New-Object System.Collections.Generic.HashSet[string]
foreach ($v in @($diagnosticVulns) + @($listVulns)) {
    if (-not $v) { continue }
    $key = "$($v.ProjectPath)|$($v.PackageId)|$($v.ResolvedVer)"
    if ($seenKeys.Add($key)) { $allVulns.Add($v) }
}

if ($allVulns.Count -eq 0) {
    if ($restoreResult.ExitCode -ne 0) {
        Write-Section "Restore failed - NOT the vulnerable-package pattern"
        Write-ErrLine "dotnet restore failed, but no NU1901-NU1904 advisories were found in the output."
        Write-ErrLine "This script only remediates NuGet-audit vulnerable-package failures; it will not"
        Write-ErrLine "guess at, or attempt to fix, unrelated build/restore errors. Raw output follows:"
        Write-Host $restoreResult.Combined
        exit 2
    }
    Write-Section "No vulnerable packages found"
    Write-Ok "Repository is already clean. Nothing to do."
    exit 0
}

Write-Section "Vulnerable packages detected"
$byPackage = $allVulns | Group-Object PackageId
foreach ($grp in $byPackage) {
    Write-Info "$($grp.Name): $(($grp.Group.ResolvedVer | Sort-Object -Unique) -join ', ') [$(($grp.Group.Source | Sort-Object -Unique) -join ', ')]"
}

# --------------------------------------------------------------------------
# Resolve patched versions (one lookup per unique package+resolvedVersion)
# --------------------------------------------------------------------------

Write-Section "Resolving patched versions via GitHub Advisory Database"
$resolutionCache = @{}
$blockingIssues = New-Object System.Collections.Generic.List[string]

foreach ($grp in ($allVulns | Group-Object { "$($_.PackageId)|$($_.ResolvedVer)" })) {
    $sample = $grp.Group[0]
    $urls = @($grp.Group.AdvisoryUrl | Sort-Object -Unique)
    $resolution = Resolve-PatchedVersion -PackageId $sample.PackageId -ResolvedVersion $sample.ResolvedVer -AdvisoryUrls $urls
    $resolutionCache[$grp.Name] = $resolution

    if ($resolution.PatchedVersion) {
        Write-Ok "$($sample.PackageId) $($sample.ResolvedVer) -> $($resolution.PatchedVersion)"
    } else {
        Write-ErrLine "$($sample.PackageId) $($sample.ResolvedVer): no clean patched version resolved"
        foreach ($b in $resolution.Blockers) {
            Write-ErrLine "  - $b"
            $blockingIssues.Add("$($sample.PackageId) $($sample.ResolvedVer): $b")
        }
    }
}

# --------------------------------------------------------------------------
# Apply fixes
# --------------------------------------------------------------------------

Write-Section "$(if ($IsDryRun) { 'Planned changes (WhatIf)' } else { 'Applying fixes' })"

$byProjectPackage = $allVulns | Where-Object { $_.ProjectPath } | Group-Object { "$($_.ProjectPath)|$($_.PackageId)" }
foreach ($grp in $byProjectPackage) {
    $v = $grp.Group[0]
    $key = "$($v.PackageId)|$($v.ResolvedVer)"
    $resolution = $resolutionCache[$key]
    if (-not $resolution -or -not $resolution.PatchedVersion) { continue }

    $newVersion = $resolution.PatchedVersion
    $projectPath = $v.ProjectPath
    $isDirect = if ($v.PSObject.Properties.Name -contains 'IsDirect') { [bool]$v.IsDirect } else { Test-DirectReference -ProjectPath $projectPath -PackageId $v.PackageId }

    try {
        if ($isDirect) {
            if ($isCpm) {
                $changed = Set-CpmPackageVersion -PropsPath $cpmPropsPath -PackageId $v.PackageId -NewVersion $newVersion
                if ($changed) {
                    $script:Changes.Add([PSCustomObject]@{ Scope = $cpmPropsPath; Package = $v.PackageId; Old = $v.ResolvedVer; New = $newVersion; Kind = 'CPM direct (Directory.Packages.props)' })
                }
            } else {
                $changed = Set-DirectPackageReferenceVersion -ProjectPath $projectPath -PackageId $v.PackageId -NewVersion $newVersion
                if ($changed) {
                    $script:Changes.Add([PSCustomObject]@{ Scope = $projectPath; Package = $v.PackageId; Old = $v.ResolvedVer; New = $newVersion; Kind = 'Direct PackageReference' })
                }
            }
        } else {
            if ($isCpm) {
                $propsChanged = Set-CpmPackageVersion -PropsPath $cpmPropsPath -PackageId $v.PackageId -NewVersion $newVersion
                if ($propsChanged) {
                    $script:Changes.Add([PSCustomObject]@{ Scope = $cpmPropsPath; Package = $v.PackageId; Old = $v.ResolvedVer; New = $newVersion; Kind = 'CPM transitive pin (Directory.Packages.props)' })
                }
                $refChanged = Add-TransitivePackagePin -ProjectPath $projectPath -PackageId $v.PackageId -NewVersion $newVersion -IsCpm $true
                if ($refChanged) {
                    $script:Changes.Add([PSCustomObject]@{ Scope = $projectPath; Package = $v.PackageId; Old = $v.ResolvedVer; New = $newVersion; Kind = 'CPM transitive pin (PackageReference added)' })
                }
            } else {
                $changed = Add-TransitivePackagePin -ProjectPath $projectPath -PackageId $v.PackageId -NewVersion $newVersion -IsCpm $false
                if ($changed) {
                    $script:Changes.Add([PSCustomObject]@{ Scope = $projectPath; Package = $v.PackageId; Old = $v.ResolvedVer; New = $newVersion; Kind = 'Transitive pin added (PackageReference)' })
                }
            }
        }
    } catch {
        Write-ErrLine "Failed to remediate $($v.PackageId) in $projectPath : $($_.Exception.Message)"
        $blockingIssues.Add("$($v.PackageId) in $projectPath : $($_.Exception.Message)")
    }
}

# Vulnerabilities reported without a resolvable ProjectPath (text-table
# fallback only) can't be targeted for an edit - surface them as blockers
# rather than silently doing nothing.
foreach ($v in ($allVulns | Where-Object { -not $_.ProjectPath })) {
    $key = "$($v.PackageId)|$($v.ResolvedVer)"
    $resolution = $resolutionCache[$key]
    if ($resolution -and $resolution.PatchedVersion) {
        $blockingIssues.Add("$($v.PackageId) $($v.ResolvedVer): patched version $($resolution.PatchedVersion) known, but no project path could be determined to apply the fix (text-fallback parse only) - re-run with a newer SDK that supports 'dotnet list package --format json'.")
    }
}

Write-Section "Change summary"
if ($script:Changes.Count -eq 0) {
    Write-Info "(no file changes $(if ($IsDryRun) { 'would be' } else { 'were' }) made)"
} else {
    $script:Changes | Sort-Object Scope, Package | ForEach-Object {
        Write-Host ("  {0,-45} {1,-30} {2,-15} -> {3,-15} [{4}]" -f $_.Scope, $_.Package, $_.Old, $_.New, $_.Kind)
    }
}

if ($blockingIssues.Count -gt 0) {
    Write-Section "Blocking issues"
    foreach ($b in $blockingIssues) { Write-ErrLine $b }
}

if ($IsDryRun) {
    Write-Section "WhatIf complete"
    Write-Info "No files were written and no verification build was run (dry-run)."
    if ($blockingIssues.Count -gt 0) { exit 1 }
    exit 0
}

if ($script:Changes.Count -eq 0 -and $blockingIssues.Count -gt 0) {
    Write-Section "Remediation blocked"
    Write-ErrLine "No changes could be applied and blocking issues remain. See above."
    exit 1
}

# --------------------------------------------------------------------------
# Verify: re-restore + re-list-vulnerable + build
# --------------------------------------------------------------------------

Write-Section "Verification: re-restore"
$verifyRestore = Invoke-Restore -Targets $targets
Write-Info "dotnet restore exit code: $($verifyRestore.ExitCode)"

$verifyDiagnosticVulns = Get-VulnerabilitiesFromDiagnosticText -Text $verifyRestore.Combined
$verifyListVulns = Get-VulnerabilitiesFromListCommand -Targets $targets
$remainingVulns = @(@($verifyDiagnosticVulns) + @($verifyListVulns) | Where-Object { $_ })

if ($remainingVulns.Count -gt 0) {
    Write-Section "Verification FAILED: vulnerabilities remain"
    foreach ($v in $remainingVulns) {
        Write-ErrLine "$($v.PackageId) $($v.ResolvedVer) ($($v.AdvisoryUrl))"
    }
    exit 1
}
Write-Ok "No vulnerable packages remain."

if ($verifyRestore.ExitCode -ne 0) {
    Write-Section "Verification FAILED: restore still failing (non-vulnerability related)"
    Write-Host $verifyRestore.Combined
    exit 1
}

Write-Section "Verification: build ($Configuration)"
$buildResult = Invoke-BuildVerification -Targets $targets -Configuration $Configuration
Write-Info "dotnet build exit code: $($buildResult.ExitCode)"
if ($buildResult.ExitCode -ne 0) {
    Write-Section "Verification FAILED: build errors after remediation"
    Write-Host $buildResult.Combined
    exit 1
}
Write-Ok "Build succeeded with configuration '$Configuration'."

if ($blockingIssues.Count -gt 0) {
    Write-Section "Partially remediated"
    Write-Warn "Some vulnerable packages were fixed, but others remain blocked (see 'Blocking issues' above)."
    exit 1
}

Write-Section "Remediation complete"
Write-Ok "All vulnerable packages remediated; restore and build ($Configuration) are green."
exit 0
