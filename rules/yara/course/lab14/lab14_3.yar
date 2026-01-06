rule Lab14_03_exe {
   meta:
      description = " - file Lab14-03.exe"
      date = "2024-12-04"

   strings:
      $string1= "http://www.practicalmalwareanalysis.com/start.htm"
      $string2= "autobat.exe"

   condition:
      all of them
}