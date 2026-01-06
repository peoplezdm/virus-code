rule exam_4_yhzll
{
    meta:
        author = "zhangdemin"
        date = "2025-10-13"
        class="virus"

    strings:
        $s1 = "RegSetValueExA" nocase
        $s2 = "CreateProcessA" nocase
        $s3 = "CreateThread" nocase
        $s4 = "recv" nocase
        $s5 = "bilibili" nocase

    condition:
        filesize > 1KB and
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        $s5 and
        for 1 of ($s1,$s2,$s3,$s4):(#>=1)
}