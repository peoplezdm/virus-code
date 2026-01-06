rule Lab06_01 {
   meta:
      description = " - file Lab06-01.dll"
      date = "2024-10-19"

   strings:
      $s1 = "Success: Internet Connection"
      $s2 = "InternetGetConnectedState" wide ascii nocase
      $s3 = "Error 1.1: No Internet" 
      
   condition:
       filesize < 100KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and all of them
}