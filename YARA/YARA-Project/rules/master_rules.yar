rule Test_Malware_Detection
{
    meta:
        description = "Detects a controlled test signature"
        author = "YARA Malware Scanner Project"
        severity = "High"

    strings:
        $test1 = "TEST_MALWARE_SIGNATURE"

    condition:
        $test1
}


rule Suspicious_PowerShell_Indicator
{
    meta:
        description = "Detects controlled PowerShell-related indicators"
        author = "YARA Malware Scanner Project"
        severity = "Medium"

    strings:
        $ps1 = "powershell.exe"
        $ps2 = "Invoke-Expression"

    condition:
        any of them
}


rule Suspicious_Script_Indicator
{
    meta:
        description = "Detects controlled scripting indicators"
        author = "YARA Malware Scanner Project"
        severity = "Medium"

    strings:
        $s1 = "wscript.exe"
        $s2 = "cscript.exe"
        $s3 = "Scripting.FileSystemObject"

    condition:
        any of them
}


rule Suspicious_Command_Indicator
{
    meta:
        description = "Detects controlled command execution indicators"
        author = "YARA Malware Scanner Project"
        severity = "Low"

    strings:
        $cmd1 = "cmd.exe /c"
        $cmd2 = "regsvr32.exe"
        $cmd3 = "rundll32.exe"

    condition:
        any of them
}