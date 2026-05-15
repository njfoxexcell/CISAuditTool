param(
    [string]$PdfPath = "C:\Users\njfox\Desktop\CIS Benchmarks\CIS_Microsoft_Windows_11_Enterprise_Benchmark_v5.0.1.pdf",
    [string]$OutTxt  = "C:\Users\njfox\CISAuditTool\extracted\benchmark.txt"
)

$ErrorActionPreference = 'Stop'
Write-Host "Opening Word..."
$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = 0  # wdAlertsNone

try {
    Write-Host "Opening PDF (this triggers Word's PDF conversion)..."
    # Use late-bound InvokeMember so we don't fight PowerShell's ByRef bool marshalling.
    $docs = $word.Documents
    $args = @($PdfPath, $false, $true, $false)   # FileName, ConfirmConversions, ReadOnly, AddToRecentFiles
    $doc = $docs.GetType().InvokeMember(
        'Open',
        [System.Reflection.BindingFlags]::InvokeMethod,
        $null,
        $docs,
        $args
    )

    Write-Host ("Pages: {0}" -f $doc.ComputeStatistics(2))   # wdStatisticPages=2
    Write-Host "Saving as plain text..."
    $saveArgs = @($OutTxt, 2)  # FileName, FileFormat=wdFormatText
    $doc.GetType().InvokeMember('SaveAs', [System.Reflection.BindingFlags]::InvokeMethod, $null, $doc, $saveArgs)
    $doc.GetType().InvokeMember('Close', [System.Reflection.BindingFlags]::InvokeMethod, $null, $doc, @($false))
    Write-Host "Saved: $OutTxt"
}
finally {
    $word.Quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
}
