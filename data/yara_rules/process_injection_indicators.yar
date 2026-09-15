/*
    Windows API names commonly combined for process injection (writing and
    running code inside another process). Each API individually has
    legitimate uses (debuggers, some anti-cheat and security tools use
    these too) - it's the combination of several together in one binary
    that's the actual signal, hence requiring 3 of 6 rather than any one.
*/
rule Process_Injection_API_Combo
{
    meta:
        description = "Windows API names commonly combined for process injection"
        severity = "suspicious"
    strings:
        $api1 = "VirtualAllocEx"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"
        $api4 = "NtUnmapViewOfSection"
        $api5 = "SetThreadContext"
        $api6 = "QueueUserAPC"
    condition:
        3 of them
}
