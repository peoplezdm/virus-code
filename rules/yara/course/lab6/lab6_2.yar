rule Lab06_02 {
   meta:
      description = " - file Lab06-02dll"
      author = "Luhaozhhhe"
      date = "2024-10-19"

   strings:
      $s1 = "http://www.practicalmalwareanalysis.com/cc.htm" wide ascii
      $s2 = "Internet Explorer 7.5/pma"
      $s3 = "Error 2.3: Fail to get command"

   condition:
       filesize < 100KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and all of them
}