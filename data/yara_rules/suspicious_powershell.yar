/*
    PowerShell patterns commonly used to download and run code in memory
    without writing a file to disk (fileless execution) - a well-known
    technique for both malware droppers and legitimate admin scripts, which
    is exactly why this requires 3 of the 9 patterns together rather than
    flagging on any single one (e.g. "-WindowStyle Hidden" alone is far too
    common in ordinary scripts to mean anything by itself).
*/
rule Suspicious_PowerShell_Download_Execute
{
    meta:
        description = "PowerShell patterns commonly used to download and run code in memory"
        severity = "suspicious"
    strings:
        $encoded = "-EncodedCommand" nocase
        $enc_short = " -enc " nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $webclient = "Net.WebClient" nocase
        $downloadstring = "DownloadString" nocase
        $iex = "IEX(" nocase
        $iex2 = "Invoke-Expression" nocase
        $reflection = "Reflection.Assembly" nocase
    condition:
        3 of them
}
