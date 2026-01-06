rule exam_2_hrtg
{
    meta:
        author = "zhangdemin"
        date = "2025-10-13"
        class="virus"

    strings:
        $s1 = "RegSetValueExA" nocase
        $s2 = "RegCreateKeyExA" nocase
        $s3 = "RegOpenKeyExA" nocase
        $s4 = "CreateMutexA" nocase
        $s5 = "CreateProcessA" nocase
        $s6 = "CreateThread" nocase
        $s7 = "CreateFileA" nocase
        $s8 = "ShellExecuteA" nocase
        $s9 = "www.globalsign.com" nocase

    condition:
        filesize > 1KB and filesize < 50MB and
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        $s9 and
        for 4 of ($s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8):(#>=1)
}