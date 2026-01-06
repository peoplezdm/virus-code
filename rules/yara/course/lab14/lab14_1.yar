rule Lab14_01_exe {
   meta:
      description = " - file Lab14-01.exe"
      date = "2024-12-05"

   strings:
      $string1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" wide ascii
      $string2 = "http://www.practicalmalwareanalysis.com/%s/%c.png" wide ascii
      
   condition:
      all of them
}