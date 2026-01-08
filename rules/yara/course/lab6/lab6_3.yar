rule Lab06_03 {
   meta:
      description = " - file Lab06-03.dll"
      author = "Luhaozhhhe"
      date = "2024-10-19"

   strings:
      $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
      $s2 = "C:\\Temp\\cc.exe"
      $s3 = "C:\\Temp"

   condition:
       filesize < 100KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and all of them
}