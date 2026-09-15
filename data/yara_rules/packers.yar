/*
    Detects files packed with UPX, a common (and itself legitimate)
    executable compressor. Packing isn't inherently malicious - plenty of
    legitimate software uses UPX to shrink binaries - but malware also uses
    it heavily to evade signature-based detection, so it's worth a
    "suspicious" flag for a human to weigh alongside everything else, not a
    "malware" verdict on its own.
*/
rule UPX_Packed_Executable
{
    meta:
        description = "File appears to be packed with UPX"
        severity = "suspicious"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx_sig = "UPX!"
    condition:
        2 of them
}
