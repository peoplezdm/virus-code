rule exam_5_bossdamaior
{
    meta:
        author = "zhangdemin"
        date = "2025-10-13"
        class="virus"

    strings:
        $s1 = "FindResourceA" nocase
        $s2 = "CreateFileA" nocase
        $s3 = "ShellExecuteExA" nocase
        $s4 = "PathRenameExtensionA" nocase
        $s5 = "www.pcfreetime.com" nocase

    condition:
        filesize > 1KB and
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        $s5 and
        for 2 of ($s1,$s2,$s3,$s4):(#>=1)
}
