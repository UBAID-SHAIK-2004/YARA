# ============================================
# SIMPLE MALWARE SCANNER USING YARA
# ============================================

$YaraPath    = "C:\Users\ubaid\YARA\yara64.exe"
$RulesPath   = "C:\Users\ubaid\YARA-Project\rules\master_rules.yar"
$SamplesPath = "C:\Users\ubaid\YARA-Project\samples"
$ResultsPath = "C:\Users\ubaid\YARA-Project\results\scan_results.txt"

# Scan timer
$StartTime = Get-Date

# Count total files scanned
$TotalFiles = (Get-ChildItem -Path $SamplesPath -Recurse -File).Count

Write-Host "========================================"
Write-Host " SIMPLE MALWARE SCANNER USING YARA"
Write-Host "========================================"
Write-Host ""

Write-Host "Scan Started :" $StartTime
Write-Host "Target Folder:" $SamplesPath
Write-Host ""

# Run YARA
$Results = @(& $YaraPath -r $RulesPath $SamplesPath)

# Save report
$Results | Out-File -FilePath $ResultsPath -Encoding utf8

# End timer
$EndTime = Get-Date
$Duration = $EndTime - $StartTime

$DetectionCount = $Results.Count

Write-Host ""
Write-Host "========== SCAN SUMMARY =========="
Write-Host "Total Files Scanned :" $TotalFiles
Write-Host "Rule Matches        :" $DetectionCount
Write-Host "Scan Duration       :" ("{0:N3}" -f $Duration.TotalSeconds) "Seconds"
Write-Host "=================================="
Write-Host ""

Write-Host "Detection Results:"
$Results