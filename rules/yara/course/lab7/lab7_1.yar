rule Lab07_01 {
   meta:
      description = " - file Lab07-01.exe"
      date = "2024-10-27"

   strings:
      $string1 = "HGL345" 
      $string2 = "http://www.malwareanalysisbook.com"
      $string3 = "Internet Explorer 8.0"
      
   condition:
       filesize < 50KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and all of them
}