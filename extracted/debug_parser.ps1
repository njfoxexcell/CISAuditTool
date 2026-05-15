# Quick debug — dump a few section 2.2 results
$json = [System.IO.File]::ReadAllText('C:\Users\njfox\CISAuditTool\core\Data\Controls.json')
$ctrl = $json | ConvertFrom-Json
$ur = $ctrl | Where-Object { $_.Id -like '2.2.*' }
Write-Host "Total 2.2.x: $($ur.Count)"
$ur | Select-Object -First 5 | ForEach-Object {
    Write-Host "$($_.Id) [$($_.Kind)] $($_.Title)"
    if ($_.Parameters) {
        $_.Parameters.PSObject.Properties | ForEach-Object { Write-Host "  $($_.Name): $($_.Value)" }
    }
}
$kinds = $ur | Group-Object Kind | ForEach-Object { "$($_.Name)=$($_.Count)" }
Write-Host "Kinds: $($kinds -join ', ')"