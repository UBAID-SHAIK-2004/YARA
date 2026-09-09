# ============================================
# YARA THREAT HUNTING SCANNER
# ============================================

$YaraPath = "C:\Users\ubaid\YARA\yara64.exe"
$RulesPath = "C:\Users\ubaid\YARA-Project\rules\master_rules.yar"
$HuntPath = "C:\Users\ubaid\YARA-Project\ThreatHunt"
$ReportPath = "C:\Users\ubaid\YARA-Project\results\threat_hunting_report.txt"

$StartTime = Get-Date

Write-Host "============================================"
Write-Host "          YARA THREAT HUNTING"
Write-Host "============================================"
Write-Host ""
Write-Host "Hunt Target: $HuntPath"
Write-Host ""

$Results = @(& $YaraPath -r $RulesPath $HuntPath)

$EndTime = Get-Date
$Duration = ($EndTime - $StartTime).TotalMilliseconds

# Report header
"============================================" | Out-File $ReportPath
"          YARA THREAT HUNTING REPORT" | Out-File $ReportPath -Append
"============================================" | Out-File $ReportPath -Append
"" | Out-File $ReportPath -Append

"Hunt Time: $StartTime" | Out-File $ReportPath -Append
"Target: $HuntPath" | Out-File $ReportPath -Append
"Rules: $RulesPath" | Out-File $ReportPath -Append
"Duration: $Duration ms" | Out-File $ReportPath -Append
"" | Out-File $ReportPath -Append

if ($Results.Count -eq 0) {

    Write-Host "No suspicious indicators detected."
    "Result: No suspicious indicators detected." | Out-File $ReportPath -Append

}
else {

    Write-Host "Suspicious indicators detected: $($Results.Count)"
    Write-Host ""

    "Detection Count: $($Results.Count)" | Out-File $ReportPath -Append
    "" | Out-File $ReportPath -Append

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
                "Detected  : $StartTime" | Out-File $ReportPath -Append
                "" | Out-File $ReportPath -Append

                Write-Host "Rule: $RuleName"
                Write-Host "File: $FilePath"
                Write-Host "SHA-256: $Hash"
                Write-Host ""

            }
        }
    }
}

"============================================" | Out-File $ReportPath -Append
"Threat hunting completed." | Out-File $ReportPath -Append

Write-Host "============================================"
Write-Host "Threat hunting completed."
Write-Host "Report saved to:"
Write-Host $ReportPath
Write-Host "============================================"