rule Lab06_04 {
   meta:
      description = " - file Lab06-04.dll"
      author = "Luhaozhhhe"
      date = "2024-10-19"

   strings:
      $s1 = "C:\\Temp\\cc.exe"
      $s2 = "RegSetValueExA"
      $s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

   condition:
       filesize < 100KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and all of them
}