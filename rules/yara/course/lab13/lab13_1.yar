rule Lab13_01_exe {
   meta:
      description = " - file Lab13-01.exe"
      date = "2024-12-04"

   strings:
      $string1 = "Mozilla/4.0" wide ascii
      $string2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" wide ascii
      $string3 = "http://%s/%s/" wide ascii
      
   condition:
      all of them
}