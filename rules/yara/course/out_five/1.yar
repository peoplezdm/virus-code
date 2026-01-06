rule exam_1_wannacrypt0r
{
    meta:
        author = "zhangdemin"
        date = "2025-10-13"
        class="virus"

    strings:
        $s1 = "OpenSCManagerA" nocase
        $s2 = "CreateServiceA" nocase
        $s3 = "StartServiceA" nocase
        $s4 = "CloseServiceHandle" nocase
        $s5 = "RegQueryValueExA" nocase
        $s6 = "CreateProcessA" nocase
        $s7 = "CopyFileA" nocase

    condition:
        filesize > 1KB and filesize < 5MB and
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        for 6 of ($s1,$s2,$s3,$s4,$s5,$s6,$s7):(#>=1)
}