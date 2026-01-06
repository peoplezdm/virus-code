rule Lab11_02_dll {
   meta:
      description = " - file Lab11-02.dll"
      date = "2024-11-18"

   strings:
      $string1 = "AppInit_DLLs" wide ascii
      $string2 = "Lab11-02.ini" wide ascii
      $string3 = "OUTLOOK.EXE" wide ascii
      

   condition:
      all of them
}