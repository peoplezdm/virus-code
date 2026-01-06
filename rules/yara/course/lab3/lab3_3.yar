rule Lab03_03 {
   meta:
      description = " - file Lab03-03.exe"
      date = "2024-10-03"
      hash1 = "ae8a1c7eb64c42ea2a04f97523ebf0844c27029eb040d910048b680f884b9dce"
   strings:
      $s16 = "KERNEL32.dll" fullword ascii
      $s17 = "practicalmalwareanaysis.log" fullword ascii

   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of them
}