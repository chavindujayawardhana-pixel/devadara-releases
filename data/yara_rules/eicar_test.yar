/*
    Detects the EICAR standard antivirus test string - a harmless,
    industry-standard file every AV product recognizes on purpose, used to
    verify a scanner is actually working. Real malware never contains this
    string; it exists specifically so tools like this one can prove they
    detect something without needing real malware to test against.

    https://www.eicar.org/download-anti-malware-testfile/
*/
rule EICAR_Test_File
{
    meta:
        description = "Detects the EICAR standard antivirus test string"
        severity = "high"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
