rule Lab12_02_exe {
   meta:
      description = " - file Lab12-02.exe"
      date = "2024-12-02"

   strings:
      $string1= "GetThreadContext" wide ascii
      $string2= "ReadProcessMemory" wide ascii
      $string3= "LockResource" wide ascii
      $string4= "LOCALIZATION" wide ascii
      
   condition:
      all of them
}