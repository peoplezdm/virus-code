rule exam_3_bug32
{
    meta:
        author = "zhangdemin"
        date = "2025-10-13"
        class="virus"

    strings:
        $s1 = "CreateFileA" nocase
        $s2 = "DeleteFileA" nocase
        $s3 = "CreateDirectoryA" nocase
        $s4 = "ShellExecuteExA" nocase
        $s5 = "PathRenameExtensionA" nocase
        $s6 = "FindResourceA" nocase
        $s7 = "GetCommandLineA" nocase
        $s8 = "malloc" nocase
        $s9 = "BUG32"

    condition:
        filesize > 1KB and
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        $s9 and
        for 4 of ($s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8):(#>=1)
}