rule Lab12_01_exe {
   meta:
      description = " - file Lab12-01.exe"
      date = "2024-12-02"

   strings:
      $string1 =  "explorer.exe" wide ascii
      $string2 = "psapi.dll" wide ascii
      $string3 = "Lab12-01.dll" wide ascii
      
   condition:
      all of them
}