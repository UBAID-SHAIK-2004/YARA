# Endpoint Security Scan using YARA

$YaraPath = "C:\Users\ubaid\YARA\yara64.exe"
$RulesPath = "C:\Users\ubaid\YARA-Project\rules\master_rules.yar"

$Folders = @(
"$HOME\Downloads",
"$HOME\Desktop",
"$HOME\Documents"
)

$Report = "C:\Users\ubaid\YARA-Project\results\endpoint_report.txt"

Remove-Item $Report -ErrorAction Ignore

foreach($Folder in $Folders){

    Write-Host ""
    Write-Host "Scanning: $Folder"

    if(Test-Path $Folder){

        $Output = & $YaraPath -r $RulesPath $Folder

        if($Output){
            "========== $Folder ==========" | Add-Content $Report
            $Output | Add-Content $Report
            Write-Host "Suspicious indicators found."
        }
        else{
            "========== $Folder ==========" | Add-Content $Report
            "No suspicious indicators detected." | Add-Content $Report
            Write-Host "No suspicious indicators found."
        }

    }
}
Write-Host ""
Write-Host "Endpoint report saved to:"
Write-Host $Report