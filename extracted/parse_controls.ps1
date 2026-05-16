<#
 .SYNOPSIS
   Parses the CIS Win11 v5.0.1 benchmark text file into a structured JSON
   catalog used by CISAudit.Core at runtime.

 .NOTES
   Pipeline:
     1) Locate every recommendation header in the body (X.Y.Z [Ensure|Configure] '...' (Automated|Manual)).
     2) Slice the text between consecutive headers — that block is the body of one recommendation.
     3) Extract Profile (L1/L2/BL/NG), Description, Rationale, Impact, Audit, Remediation, Default Value.
     4) Attempt to auto-derive machine-checkable parameters from the Audit text.
     5) Emit Controls.json into core\Data\.

   Anything that cannot be auto-derived is marked Kind=Manual — per design,
   Manual controls are reported but excluded from the score.
#>

param(
    [string]$InTxt   = "C:\Users\njfox\CISAuditTool\extracted\benchmark.utf8.txt",
    [string]$OutJson = "C:\Users\njfox\CISAuditTool\core\Data\Controls.json"
)

$ErrorActionPreference = 'Stop'

$text = [System.IO.File]::ReadAllText($InTxt)

# --- Locate all section headers in the body --------------------------------
# Two-pass: (1) find every header position; (2) slice the body between headers.
$headerRx = [regex]'(?m)^(?<id>\d+(?:\.\d+){1,5})\s+(?<verb>Ensure|Configure)\s+''(?<title>[^'']+)''(?<tail>[^\r\n]*?)\((?<auto>Automated|Manual)\)\s*$'
$headerHits = @($headerRx.Matches($text))
# Only headers that are followed by "Profile Applicability:" within the next ~5 lines (body, not TOC)
$bodyHeaders = @()
foreach ($h in $headerHits) {
    $tail = $text.Substring($h.Index + $h.Length, [Math]::Min(400, $text.Length - $h.Index - $h.Length))
    if ($tail -match '^\s*\r?\nProfile Applicability:') {
        $bodyHeaders += $h
    }
}
Write-Host ("Body headers: {0}" -f $bodyHeaders.Count)
$headers = $bodyHeaders

# Section name lookup (number -> name) by scanning H1/H2 section markers.
# Pattern e.g. "18.10.3 App and Device Inventory" — no "Ensure".
$sectionTitles = @{}
$secRx = [regex]'(?m)^(\d+(?:\.\d+){1,4})\s+([A-Z][^\r\n]{2,80})\s*$'
foreach ($m in $secRx.Matches($text)) {
    $id = $m.Groups[1].Value
    $name = $m.Groups[2].Value.Trim()
    if ($name -notmatch '^(Ensure|Configure|Profile|Description|Rationale|Impact|Audit|Remediation|Default|References|Note)') {
        if (-not $sectionTitles.ContainsKey($id)) { $sectionTitles[$id] = $name }
    }
}

function Get-Section([string]$id) {
    # Walk up the id (18.10.3.5 -> 18.10.3 -> 18.10 -> 18) to find a parent section name.
    $parts = $id -split '\.'
    for ($i = $parts.Length - 1; $i -ge 1; $i--) {
        $k = ($parts[0..($i-1)] -join '.')
        if ($sectionTitles.ContainsKey($k)) { return $sectionTitles[$k] }
    }
    return ""
}

function Get-Field([string]$body, [string]$name, [string[]]$stopAt) {
    # Captures the text between "<name>:" and the next field header.
    $stop = ($stopAt | ForEach-Object { [regex]::Escape($_) + ':' }) -join '|'
    $rx = [regex]("(?ms)^\s*" + [regex]::Escape($name) + ":\s*\r?\n(.*?)(?=^\s*(?:$stop)\s*\r?\n|\z)")
    $m = $rx.Match($body)
    if ($m.Success) { return ($m.Groups[1].Value.Trim()) }
    return $null
}

# --- Pattern library: convert Audit text into check parameters -------------
function Resolve-Check([string]$id, [string]$title, [string]$headerTail, [string]$audit, [string]$remediation, [string]$default, [string]$autoFlag) {
    $audit = if ($audit) { $audit } else { "" }
    $rem   = if ($remediation) { $remediation } else { "" }
    $combined = "$audit`n$rem"
    $result = [ordered]@{ Kind = 'Manual'; Parameters = @{}; ExpectedDisplay = $null }

    # CIS labels "Manual" controls explicitly — those map to Manual regardless.
    if ($autoFlag -eq 'Manual') { return $result }

    # 1) Advanced Audit Policy — sections 17.x. Title is the bare subcategory
    # (e.g. "Audit Credential Validation"); expected value is in the original
    # benchmark header line (audit text contains "set as prescribed" pointing
    # back to the title's "is set to '<value>'").
    if ($id -match '^17\.') {
        $sub = $title -replace '^Audit\s+', ''
        # The expected verbiage lives in the audit/remediation prose; pull from
        # the original benchmark line which always includes "to 'Success and Failure'" etc.
        $expectedHint = $null
        $expectedRx = [regex]"(?:set to|set to include)\s+['‘]([^'’]+)['’]"
        $em = $expectedRx.Match($combined)
        if (-not $em.Success) { $em = $expectedRx.Match($title) }
        if ($em.Success) { $expectedHint = $em.Groups[1].Value }
        # Normalize CIS phrasings to literal auditpol output values.
        $expected = switch -Regex ($expectedHint) {
            'Success and Failure' { 'Success and Failure'; break }
            '^\s*Success\s*$'     { 'Success'; break }
            '^\s*Failure\s*$'     { 'Failure'; break }
            'include Failure'     { 'Failure|Success and Failure'; break }
            'include Success'     { 'Success|Success and Failure'; break }
            default               { 'Success and Failure' }
        }
        $result.Kind = 'AuditPolicy'
        $result.Parameters['subcategory'] = $sub
        $result.Parameters['expected']    = $expected
        $result.ExpectedDisplay           = $expectedHint
        return $result
    }

    # 2) User Rights Assignment — section 2.2.x. Map policy name -> SeXxxPrivilege.
    if ($id -match '^2\.2\.') {
        # Comprehensive mapping (Windows-known constants).
        $urMap = @{
            'Access Credential Manager as a trusted caller'  = 'SeTrustedCredManAccessPrivilege'
            'Access this computer from the network'          = 'SeNetworkLogonRight'
            'Act as part of the operating system'            = 'SeTcbPrivilege'
            'Adjust memory quotas for a process'             = 'SeIncreaseQuotaPrivilege'
            'Allow log on locally'                           = 'SeInteractiveLogonRight'
            'Allow log on through Remote Desktop Services'   = 'SeRemoteInteractiveLogonRight'
            'Back up files and directories'                  = 'SeBackupPrivilege'
            'Change the system time'                         = 'SeSystemtimePrivilege'
            'Change the time zone'                           = 'SeTimeZonePrivilege'
            'Create a pagefile'                              = 'SeCreatePagefilePrivilege'
            'Create a token object'                          = 'SeCreateTokenPrivilege'
            'Create global objects'                          = 'SeCreateGlobalPrivilege'
            'Create permanent shared objects'                = 'SeCreatePermanentPrivilege'
            'Create symbolic links'                          = 'SeCreateSymbolicLinkPrivilege'
            'Debug programs'                                 = 'SeDebugPrivilege'
            'Deny access to this computer from the network'  = 'SeDenyNetworkLogonRight'
            'Deny log on as a batch job'                     = 'SeDenyBatchLogonRight'
            'Deny log on as a service'                       = 'SeDenyServiceLogonRight'
            'Deny log on locally'                            = 'SeDenyInteractiveLogonRight'
            'Deny log on through Remote Desktop Services'    = 'SeDenyRemoteInteractiveLogonRight'
            'Enable computer and user accounts to be trusted for delegation' = 'SeEnableDelegationPrivilege'
            'Force shutdown from a remote system'            = 'SeRemoteShutdownPrivilege'
            'Generate security audits'                       = 'SeAuditPrivilege'
            'Impersonate a client after authentication'      = 'SeImpersonatePrivilege'
            'Increase scheduling priority'                   = 'SeIncreaseBasePriorityPrivilege'
            'Load and unload device drivers'                 = 'SeLoadDriverPrivilege'
            'Lock pages in memory'                           = 'SeLockMemoryPrivilege'
            'Log on as a batch job'                          = 'SeBatchLogonRight'
            'Log on as a service'                            = 'SeServiceLogonRight'
            'Manage auditing and security log'               = 'SeSecurityPrivilege'
            'Modify an object label'                         = 'SeRelabelPrivilege'
            'Modify firmware environment values'             = 'SeSystemEnvironmentPrivilege'
            'Perform volume maintenance tasks'               = 'SeManageVolumePrivilege'
            'Profile single process'                         = 'SeProfileSingleProcessPrivilege'
            'Profile system performance'                     = 'SeSystemProfilePrivilege'
            'Replace a process level token'                  = 'SeAssignPrimaryTokenPrivilege'
            'Restore files and directories'                  = 'SeRestorePrivilege'
            'Shut down the system'                           = 'SeShutdownPrivilege'
            'Take ownership of files or other objects'       = 'SeTakeOwnershipPrivilege'
            'Increase a process working set'                 = 'SeIncreaseWorkingSetPrivilege'
        }
        $bare = $title -replace "^Ensure\s+",'' -replace "^'", '' -replace "'.*$",''
        $bare = $bare -replace "^Configure\s+",''
        if ($urMap.ContainsKey($bare)) {
            $result.Kind = 'UserRight'
            $result.Parameters['privilege'] = $urMap[$bare]
            $expectedTitleVal = [regex]::Match($headerTail, "(?:is set to|is configured to)\s+['‘]([^'’]+)['’]")
            if ($expectedTitleVal.Success) {
                $valTxt = $expectedTitleVal.Groups[1].Value
                $result.ExpectedDisplay = $valTxt
                if ($valTxt -match '^No One$' -or $valTxt -match '^\s*$') {
                    $result.Parameters['mode'] = 'empty'
                } else {
                    $result.Parameters['mode'] = 'exact'
                    $tokens = $valTxt -split '[,;]\s*' | ForEach-Object { ($_ -replace '\s+', ' ').Trim() } | Where-Object { $_.Length -gt 0 }
                    $result.Parameters['expected'] = ($tokens -join '|')
                }
            } else {
                # "Configure 'X' is configured" — manual expected
                $result.Kind = 'Manual'
            }
            return $result
        }
    }

    # 2) Account/Password/Lockout policies — section 1.x (SystemAccess via secedit)
    # NOTE: Each branch returns early. The patterns must be specific enough that
    # only the intended rule matches. We use ^...$ anchors so e.g.
    # "Relax minimum password length limits" does NOT match "Minimum password length".
    if ($id -match '^1\.[12]\.') {
        $val = $null
        $titleVal = [regex]::Match($headerTail, "(?:is set to|is configured to)\s+['‘]([^'’]+)['’]")
        if ($titleVal.Success) { $val = $titleVal.Groups[1].Value }
        # Use the exact title for matching (case-insensitive).
        switch -Regex ($title) {
            '^Enforce password history$'                  { $result.Kind='SecurityPolicy'; $result.Parameters['section']='SystemAccess'; $result.Parameters['name']='PasswordHistorySize'; $result.Parameters['op']='gte'; if ($val -match '(\d+)') { $result.Parameters['expected']=$Matches[1] }; $result.ExpectedDisplay=$val; return $result }
            '^Maximum password age$'                      {
                # Title's "is set to 'N or fewer days, but not 0'" gives us the upper bound directly.
                $upper = 365
                if ($val -match '(\d+)') { $upper = [int]$Matches[1] }
                $result.Kind='SecurityPolicy'; $result.Parameters['section']='SystemAccess'; $result.Parameters['name']='MaximumPasswordAge'; $result.Parameters['op']='between'; $result.Parameters['expected']="1..$upper"; $result.ExpectedDisplay=$val; return $result
            }
            '^Minimum password age$'                      { $result.Kind='SecurityPolicy'; $result.Parameters['section']='SystemAccess'; $result.Parameters['name']='MinimumPasswordAge'; $result.Parameters['op']='gte'; $result.Parameters['expected']='1'; $result.ExpectedDisplay=$val; return $result }
            '^Minimum password length$'                   { $result.Kind='SecurityPolicy'; $result.Parameters['section']='SystemAccess'; $result.Parameters['name']='MinimumPasswordLength'; $result.Parameters['op']='gte'; if ($val -match '(\d+)') { $result.Parameters['expected']=$Matches[1] }; $result.ExpectedDisplay=$val; return $result }
            '^Password must meet complexity requirements$' { $result.Kind='SecurityPolicy'; $result.Parameters['section']='SystemAccess'; $result.Parameters['name']='PasswordComplexity'; $result.Parameters['op']='equals'; $result.Parameters['expected']='1'; $result.ExpectedDisplay='Enabled'; return $result }
            '^Relax minimum password length limits$'      { $result.Kind='SecurityPolicy'; $result.Parameters['section']='SystemAccess'; $result.Parameters['name']='RelaxMinimumPasswordLengthLimits'; $result.Parameters['op']='equals'; $result.Parameters['expected']='1'; $result.ExpectedDisplay='Enabled'; return $result }
            '^Store passwords using reversible encryption$' { $result.Kind='SecurityPolicy'; $result.Parameters['section']='SystemAccess'; $result.Parameters['name']='ClearTextPassword'; $result.Parameters['op']='equals'; $result.Parameters['expected']='0'; $result.ExpectedDisplay='Disabled'; return $result }
            '^Account lockout duration$'                  { $result.Kind='SecurityPolicy'; $result.Parameters['section']='SystemAccess'; $result.Parameters['name']='LockoutDuration'; $result.Parameters['op']='gte'; if ($val -match '(\d+)') { $result.Parameters['expected']=$Matches[1] }; $result.ExpectedDisplay=$val; return $result }
            '^Account lockout threshold$'                 { $result.Kind='SecurityPolicy'; $result.Parameters['section']='SystemAccess'; $result.Parameters['name']='LockoutBadCount'; $result.Parameters['op']='between'; $result.Parameters['expected']='1..5'; $result.ExpectedDisplay=$val; return $result }
            '^Allow Administrator account lockout$'       { $result.Kind='SecurityPolicy'; $result.Parameters['section']='SystemAccess'; $result.Parameters['name']='AllowAdministratorLockout'; $result.Parameters['op']='equals'; $result.Parameters['expected']='1'; $result.ExpectedDisplay='Enabled'; return $result }
            '^Reset account lockout counter after$'       { $result.Kind='SecurityPolicy'; $result.Parameters['section']='SystemAccess'; $result.Parameters['name']='ResetLockoutCount'; $result.Parameters['op']='gte'; if ($val -match '(\d+)') { $result.Parameters['expected']=$Matches[1] }; $result.ExpectedDisplay=$val; return $result }
        }
    }

    # 4) System Services — section 5.x (Disabled or Not Installed)
    if ($id -match '^5\.') {
        # Title pattern: "Ensure 'IIS Admin Service (IISADMIN)' is set to 'Disabled' or 'Not Installed'"
        $svcM = [regex]::Match($title, "\(([A-Za-z0-9_\.]+)\)")
        $expM = [regex]::Match($headerTail, "(?:is set to|is configured to)\s+['‘]([^'’]+)['’]")
        if ($svcM.Success) {
            $result.Kind = 'Service'
            $result.Parameters['serviceName'] = $svcM.Groups[1].Value
            $expVal = if ($expM.Success) { $expM.Groups[1].Value } else { 'Disabled' }
            $result.Parameters['expected'] = 'Disabled'  # primary requirement
            $allowAbsent = ($headerTail -match 'Not Installed') -or ($expVal -match 'Not Installed')
            $result.Parameters['allowAbsent'] = if ($allowAbsent) { 'true' } else { 'false' }
            $result.ExpectedDisplay = $expVal
            return $result
        }
    }

    # 5) Registry — generic: find first HKLM/HKCU path in the Audit section.
    # CIS audit format: "HKLM\Path\To\Key:ValueName" — but Word's PDF->text export
    # often wraps long names mid-word and inserts a space (e.g. "DisablePasswordCha nge",
    # "LegalNoticeCap tion"). We allow contiguous identifier chunks separated by
    # at most one internal space and strip whitespace before storing.
    $regRx = [regex]"(?im)(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\(?<key>[^:\r\n]+?):(?<name>[A-Za-z0-9_]+(?:[ \t]+[A-Za-z0-9_]+){0,2})\s*$"
    $regM = $regRx.Match($audit)
    if ($regM.Success) {
        $hive = $regM.Groups[1].Value.ToUpper()
        if ($hive -eq 'HKEY_LOCAL_MACHINE') { $hive = 'HKLM' }
        elseif ($hive -eq 'HKEY_CURRENT_USER') { $hive = 'HKCU' }
        $key = $regM.Groups['key'].Value.Trim().Trim('\')
        # Remove stray spaces that Word inserts at line breaks: "DisableInstallTrac ing" -> "DisableInstallTracing"
        $valueName = ($regM.Groups['name'].Value -replace '\s+', '')
        $result.Parameters['hive'] = $hive
        $result.Parameters['key']  = ($key -replace '\s+', '')
        $result.Parameters['name'] = $valueName
        $result.Kind = 'Registry'

        # Discover expected value type + value
        $expFromTitle = [regex]::Match($headerTail, "(?:is set to|is configured to)\s+['‘]([^'’]+)['’]")
        if ($expFromTitle.Success) { $result.ExpectedDisplay = $expFromTitle.Groups[1].Value }

        $regValRx = [regex]"REG_(?<t>DWORD|QWORD|SZ|MULTI_SZ|EXPAND_SZ)\s+value\s+of\s+(?<v>[^\.\r\n,]+)"
        $rv = $regValRx.Match($audit)
        if (-not $rv.Success) {
            # Couldn't determine expected — flag as Manual.
            $result.Kind = 'Manual'
            return $result
        }

        $rawV    = $rv.Groups['v'].Value.Trim().Trim("'""")
        $regType = $rv.Groups['t'].Value

        # "or less" / "or more" wording overrides the type. The benchmark
        # sometimes encodes numeric thresholds as REG_SZ in older sections.
        if ($audit -match "value of\s+(\d+)\s*or\s*(?:higher|greater|more)") {
            $result.Parameters['op']='gte'; $result.Parameters['expected']=$Matches[1]
        }
        elseif ($audit -match "value of\s+(\d+)\s*or\s*(?:less|fewer)") {
            $result.Parameters['op']='lte'; $result.Parameters['expected']=$Matches[1]
        }
        elseif ($rawV -match '^0x[0-9A-Fa-f]+$') {
            try { $iv = [Convert]::ToInt64($rawV, 16); $result.Parameters['op']='equals'; $result.Parameters['expected']="$iv" }
            catch { $result.Kind='Manual' }
        }
        elseif ($rawV -match '^\d+$') {
            $result.Parameters['op']='equals'; $result.Parameters['expected']=$rawV
        }
        elseif ($regType -in 'SZ','EXPAND_SZ' -and $rawV -ieq 'text') {
            # CIS placeholder — means "any non-empty string". Examples: 2.3.7.4
            # (legal notice text), 2.3.7.5 (legal notice title), banners, etc.
            $result.Parameters['op']='notEmpty'
            $result.Parameters['expected']='(any non-empty string)'
            if (-not $result.ExpectedDisplay) { $result.ExpectedDisplay = '(any non-empty string)' }
        }
        elseif ($regType -eq 'MULTI_SZ') {
            # Expected list, often empty — keep verbatim; runtime can compare.
            $result.Parameters['op']='equals'; $result.Parameters['expected']=$rawV
        }
        else {
            # String literal value (e.g. "Lock Workstation").
            $result.Parameters['op']='equals'; $result.Parameters['expected']=$rawV
        }

        if (-not $result.Parameters.ContainsKey('expected')) { $result.Kind = 'Manual' }
        if ($result.Kind -eq 'Registry') { return $result }
    }

    return $result
}

# --- Main loop -------------------------------------------------------------
$controls = New-Object System.Collections.Generic.List[object]
$counts = @{ Registry=0; SecurityPolicy=0; AuditPolicy=0; UserRight=0; Service=0; Manual=0 }
$levelCounts = @{ 1=0; 2=0; BL=0; NG=0 }

for ($idx = 0; $idx -lt $headers.Count; $idx++) {
    $m = $headers[$idx]
    $id    = $m.Groups['id'].Value
    $verb  = $m.Groups['verb'].Value
    $title = $m.Groups['title'].Value.Trim()
    $auto  = $m.Groups['auto'].Value
    # Block = text from this header's start to the next body header's start
    $startIdx = $m.Index
    if ($idx + 1 -lt $headers.Count) { $endIdx = $headers[$idx+1].Index } else { $endIdx = $text.Length }
    $block = $text.Substring($startIdx, $endIdx - $startIdx)

    # Parse the Profile Applicability block. Each control lists one or more
    # bullets like "Level 1 (L1)", "Level 2 (L2) + BitLocker (BL)", "Next-Gen Windows Security (NG)".
    $paBlock = [regex]::Match($block, "(?ms)Profile Applicability:\s*\r?\n(?<pa>.*?)(?=^\s*Description:|^\s*Rationale:)").Groups['pa'].Value
    $profiles = @()
    if ($block -match '\(L1\)') { $profiles += 'L1' }
    if ($block -match '\(L2\)') { $profiles += 'L2' }
    if ($paBlock -match '\(BL\)' -or $paBlock -match 'BitLocker') { $profiles += 'BL' }
    if ($paBlock -match '\(NG\)' -or $paBlock -match 'Next.?Gen') { $profiles += 'NG' }
    $profiles = @($profiles | Sort-Object -Unique)
    foreach ($p in $profiles) {
        if ($p -eq 'L1') { $levelCounts[1]++ }
        elseif ($p -eq 'L2') { $levelCounts[2]++ }
        else { $levelCounts[$p]++ }
    }
    $primaryLevel = if ($profiles -contains 'L2') { 2 } else { 1 }

    $stopWords = 'Profile Applicability','Description','Rationale','Impact','Audit','Remediation','Default Value','References','CIS Controls','Note'
    $desc    = Get-Field $block 'Description' $stopWords
    $rationale = Get-Field $block 'Rationale' $stopWords
    $impact  = Get-Field $block 'Impact' $stopWords
    $audit   = Get-Field $block 'Audit' $stopWords
    $rem     = Get-Field $block 'Remediation' $stopWords
    $default = Get-Field $block 'Default Value' $stopWords

    $headerTail = $m.Groups['tail'].Value
    $check = Resolve-Check -id $id -title $title -headerTail $headerTail -audit $audit -remediation $rem -default $default -autoFlag $auto

    $counts[$check.Kind]++

    $section = Get-Section $id

    $obj = [ordered]@{
        Id              = $id
        Title           = $title.Trim()
        Level           = $primaryLevel
        Profiles        = $profiles
        Section         = $section
        AutomatedFlag   = $auto
        Description     = $desc
        Rationale       = $rationale
        Impact          = $impact
        AuditText       = $audit
        Remediation     = $rem
        DefaultValue    = $default
        Kind            = $check.Kind
        Parameters      = $check.Parameters
        ExpectedDisplay = $check.ExpectedDisplay
    }
    $controls.Add($obj)
}

# Ensure output folder exists
$outDir = Split-Path $OutJson -Parent
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Force $outDir | Out-Null }

# Sort by section id for stable output
$sorted = $controls | Sort-Object @{Expression={ ($_.Id -split '\.' | ForEach-Object { '{0:D4}' -f [int]$_ }) -join '.' }}
$json = $sorted | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($OutJson, $json, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "=========================="
Write-Host "Catalog: $OutJson"
Write-Host ("Total: {0}" -f $controls.Count)
Write-Host "By kind:"
$counts.GetEnumerator() | Sort-Object Name | ForEach-Object { Write-Host ("  {0,-16} {1}" -f $_.Name, $_.Value) }
Write-Host "By profile bullet:"
$levelCounts.GetEnumerator() | Sort-Object Name | ForEach-Object { Write-Host ("  {0,-4} {1}" -f $_.Name, $_.Value) }
