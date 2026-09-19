# batch_signature_check.ps1
#
# Checks Get-AuthenticodeSignature for multiple files in one PowerShell
# process, invoked by devadara/signature_scanner.py::check_digital_signatures_batch().
#
# Each path arrives as its own separate process argument (bound here via
# ValueFromRemainingArguments) - never woven into script text - preserving
# the same "path is a value, never code" guarantee the single-file check
# already makes. -File (not -Command) is required for this: PowerShell's
# -Command only forwards the FIRST trailing CLI argument to a script
# block's parameters, silently dropping the rest - confirmed by direct
# testing. ValueFromRemainingArguments is required too: without it, only
# the first positional argument binds to $TargetPaths even via -File.
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$TargetPaths
)

$results = foreach ($p in $TargetPaths) {
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $p
        [PSCustomObject]@{
            Path      = $p
            Status    = $sig.Status.ToString()
            Publisher = $sig.SignerCertificate.Subject
            NotAfter  = $sig.SignerCertificate.NotAfter
            NotBefore = $sig.SignerCertificate.NotBefore
        }
    } catch {
        [PSCustomObject]@{
            Path = $p; Status = "Error"; Publisher = $null; NotAfter = $null; NotBefore = $null
        }
    }
}

ConvertTo-Json -InputObject $results -Compress
