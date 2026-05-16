<#
 .SYNOPSIS
   Builds + publishes the CIS Audit Tool, writes a SHA-256 manifest to
   BUILD_HASHES.md, then (by default) commits + pushes to origin/main.

 .NOTES
   pwsh -File .\build.ps1            # build + publish + hash + commit + push
   pwsh -File .\build.ps1 -NoPush    # build + hash, skip git push
   pwsh -File .\build.ps1 -NoCommit  # just build + hash, no git ops at all
#>
param(
    [switch]$NoCommit,
    [switch]$NoPush,
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Step([string]$msg) { Write-Host ('==> ' + $msg) -ForegroundColor Cyan }
function BT { '`' }   # one literal backtick — used inside markdown code spans

# Wrap git so its harmless stderr (CRLF warnings, "main is up-to-date", etc.)
# does not trip the strict error preference. Throws only if exit code is nonzero.
function Invoke-Git {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & git @args 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ('git ' + ($args -join ' ') + ' failed (exit ' + $LASTEXITCODE + '): ' + ($out -join "`n"))
        }
        $out | Where-Object { $_ -notmatch '^warning:' } | ForEach-Object { Write-Host $_ }
        return ($out | Where-Object { $_ -notmatch '^warning:' })
    } finally {
        $ErrorActionPreference = $prev
    }
}

Step ('dotnet build (' + $Configuration + ')')
dotnet build -c $Configuration -nologo -v minimal
if ($LASTEXITCODE -ne 0) { throw ('Build failed (exit ' + $LASTEXITCODE + ')') }

Step 'dotnet publish app -> publish\'
$publishDir = Join-Path $root 'publish'
if (Test-Path $publishDir) { Remove-Item $publishDir -Recurse -Force }
dotnet publish (Join-Path $root 'app\CISAudit.App.csproj') `
    -c $Configuration -r win-x64 --self-contained false `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
    -nologo -v minimal -o $publishDir
if ($LASTEXITCODE -ne 0) { throw ('Publish failed (exit ' + $LASTEXITCODE + ')') }

Step 'Hashing artifacts (SHA-256)'
$artifacts = Get-ChildItem $publishDir -File -Recurse |
    Where-Object { $_.Extension -in '.exe','.dll' } |
    Sort-Object FullName
$rows = foreach ($a in $artifacts) {
    $h = (Get-FileHash $a.FullName -Algorithm SHA256).Hash
    [pscustomobject]@{
        Path   = $a.FullName.Substring($root.Length + 1)
        Size   = $a.Length
        SHA256 = $h
    }
}
$rows | Format-Table -AutoSize | Out-String | Write-Host

$gitSha    = (& git rev-parse HEAD 2>$null)
$gitBranch = (& git rev-parse --abbrev-ref HEAD 2>$null)
$porc      = (& git status --porcelain 2>$null)
$gitDirty  = if ($porc) { 'dirty (uncommitted edits in tree)' } else { 'clean' }
$buildTime = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')

Step 'Writing BUILD_HASHES.md'

# Build the new "Latest build" section
$nl = "`n"
$tick = BT
$header = @()
$header += '# Build Hashes'
$header += ''
$header += 'Updated by ' + $tick + 'build.ps1' + $tick + ' after each successful publish. Each row below is the'
$header += 'SHA-256 of one artifact under publish/. Verify before deploying.'
$header += ''
$header += '## Latest build'
$header += ''
$header += '- **Built:** ' + $buildTime
$header += '- **Configuration:** ' + $Configuration
$header += '- **Runtime:** win-x64, framework-dependent, single-file'
$header += '- **Git commit:** ' + $tick + $gitSha + $tick + ' (' + $gitBranch + ')'
$header += '- **Working tree:** ' + $gitDirty
$header += ''
$header += '| File | Size (bytes) | SHA-256 |'
$header += '| --- | ---: | --- |'
foreach ($r in $rows) {
    $header += '| ' + $tick + $r.Path + $tick + ' | ' + $r.Size + ' | ' + $tick + $r.SHA256 + $tick + ' |'
}
$header += ''
$header += '## History'
$header += ''
$header += 'Older builds are appended below for traceability.'
$header += ''

# Carry over the previous "Latest build" block as a history entry
$existing = Join-Path $root 'BUILD_HASHES.md'
$historyBlocks = @()
if (Test-Path $existing) {
    $old = Get-Content $existing -Raw
    $rxLatest = '(?ms)^## Latest build\s*\n(.*?)\n## History'
    $m = [regex]::Match($old, $rxLatest)
    if ($m.Success) {
        $prev = $m.Groups[1].Value.TrimEnd()
        $stamp = ([regex]::Match($prev, '\*\*Built:\*\* ([^\r\n]+)')).Groups[1].Value
        if (-not $stamp) { $stamp = 'unknown timestamp' }
        $historyBlocks += '### Build at ' + $stamp
        $historyBlocks += ''
        $historyBlocks += $prev
        $historyBlocks += ''
    }
    $rxHistoryRest = '(?ms)^### Build at [^\r\n]+\r?\n[\s\S]*$'
    foreach ($hm in [regex]::Matches($old, $rxHistoryRest)) {
        $historyBlocks += $hm.Value.TrimEnd()
        $historyBlocks += ''
    }
}

$lines = $header + $historyBlocks
[System.IO.File]::WriteAllText($existing, ($lines -join $nl), [System.Text.UTF8Encoding]::new($false))
Write-Host ('Wrote ' + $existing)

if ($NoCommit) {
    Step 'Skipping git ops (-NoCommit)'
    return
}

Step 'git add + commit'
# Stage every working-tree change so the manifest commit reflects the exact
# source that produced these hashes. Without this we'd be recording a hash
# of binaries built from uncommitted code — useless for verification.
Invoke-Git add -A | Out-Null
$staged = Invoke-Git diff --cached --name-only
if (-not $staged) {
    Write-Host 'No changes to commit — working tree was already clean and the manifest is unchanged.'
    if (-not $NoPush) {
        Step 'git push'
        Invoke-Git push origin HEAD
    }
    return
}

$primaryHash = ($rows | Where-Object { $_.Path -like '*CISAuditTool.exe' } | Select-Object -ExpandProperty SHA256 -First 1)
if (-not $primaryHash) { $primaryHash = '(no exe in publish output)' }

# Each -m produces a separate paragraph in the commit message.
$subject = 'Build manifest update - ' + $buildTime
$body    = 'Primary artifact CISAuditTool.exe sha256: ' + $primaryHash
$trailer = 'Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>'
Invoke-Git commit -m $subject -m $body -m $trailer | Out-Null

if (-not $NoPush) {
    Step 'git push'
    Invoke-Git push origin HEAD
}

Step 'Done.'
