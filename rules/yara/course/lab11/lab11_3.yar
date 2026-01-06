rule Lab11_03_dll {
   meta:
      description = " - file Lab11-03.dll"
      date = "2024-11-18"

   strings:
      $string1 = "Lab1103dll.dll" wide ascii
      $string2 = "zzz69806582" wide ascii
      

   condition:
      all of them
}

rule Lab11_03_exe {
   meta:
      description = " - file Lab11-03.exe"
      date = "2024-11-18"

   strings:
      $string1 = "net start cisvc" wide ascii nocase
      $string2 = "zzz69806582" wide ascii
      $string3 = "Lab11-03.dll" wide ascii

   condition:
      2 of them
}