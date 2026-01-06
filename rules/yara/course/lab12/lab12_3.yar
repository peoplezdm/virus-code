rule Lab12_03_exe {
   meta:
      description = " - file Lab12-03.exe"
      date = "2024-12-02"

   strings:
      $string1= "practicalmalwareanalysis.log" wide ascii
      $string2= "BACKSPACE" wide ascii nocase

   condition:
      all of them
}