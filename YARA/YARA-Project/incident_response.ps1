# ============================================
# YARA INCIDENT RESPONSE SCANNER
# ============================================

$YaraPath = "C:\Users\ubaid\YARA\yara64.exe"
$RulesPath = "C:\Users\ubaid\YARA-Project\rules\master_rules.yar"
$SamplesPath = "C:\Users\ubaid\YARA-Project\ThreatHunt"
$ReportPath = "C:\Users\ubaid\YARA-Project\results\incident_report.txt"

$ScanTime = Get-Date

# Run YARA recursively
$Results = @(& $YaraPath -r $RulesPath $SamplesPath)

# Create report header
"============================================" | Out-File $ReportPath
"          YARA INCIDENT RESPONSE REPORT" | Out-File $ReportPath -Append
"============================================" | Out-File $ReportPath -Append
"" | Out-File $ReportPath -Append

"Scan Time: $ScanTime" | Out-File $ReportPath -Append
"Target: $SamplesPath" | Out-File $ReportPath -Append
"Rules: $RulesPath" | Out-File $ReportPath -Append
"" | Out-File $ReportPath -Append

if ($Results.Count -eq 0) {

    "No YARA detections found." | Out-File $ReportPath -Append
    Write-Host "No detections found."

}
else {

    Write-Host "Detections found: $($Results.Count)"
    Write-Host ""

    foreach ($Result in $Results) {

        if ($Result -match "^(.*?) (C:\\.*)$") {

            $RuleName = $Matches[1]
            $FilePath = $Matches[2]

            if (Test-Path $FilePath) {

                $Hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash

                "--------------------------------------------" | Out-File $ReportPath -Append
                "YARA Rule : $RuleName" | Out-File $ReportPath -Append
                "File      : $FilePath" | Out-File $ReportPath -Append
                "SHA-256   : $Hash" | Out-File $ReportPath -Append
                "Detected  : $ScanTime" | Out-File $ReportPath -Append
                "" | Out-File $ReportPath -Append

                Write-Host "Rule  : $RuleName"
                Write-Host "File  : $FilePath"
                Write-Host "SHA256: $Hash"
                Write-Host ""

            }
        }
    }
}

"============================================" | Out-File $ReportPath -Append
"End of Incident Response Report" | Out-File $ReportPath -Append

Write-Host "============================================"
Write-Host "Incident response report saved to:"
Write-Host $ReportPath