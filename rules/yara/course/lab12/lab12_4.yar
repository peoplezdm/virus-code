rule Lab12_04_exe {
   meta:
      description = " - file Lab12-04.exe"
      date = "2024-12-02"

   strings:
      $string1= "http://www.practicalmalwareanalysis.com/updater.exe" wide ascii
      $string2= "wupdmgrd.exe" wide ascii nocase

   condition:
      all of them
}