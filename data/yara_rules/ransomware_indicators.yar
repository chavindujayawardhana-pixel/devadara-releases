/*
    Common phrasing found in ransomware ransom notes. Requires 3 of the 7
    phrases to match (not just 1) since any single phrase alone (e.g.
    "bitcoin wallet") is too generic and shows up in plenty of legitimate
    software - the combination is what's distinctive.
*/
rule Ransomware_Note_Language
{
    meta:
        description = "Common phrasing found in ransomware ransom notes"
        severity = "suspicious"
    strings:
        $s1 = "your files have been encrypted" nocase
        $s2 = "all your files are encrypted" nocase
        $s3 = "decrypt your files" nocase
        $s4 = "pay the ransom" nocase
        $s5 = "bitcoin wallet" nocase
        $s6 = "restore your files" nocase
        $s7 = ".onion" nocase
    condition:
        3 of them
}
