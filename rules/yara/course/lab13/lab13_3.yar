rule Lab13_03_exe {
   meta:
      description = " - file Lab13-03.exe"
      date = "2024-12-04"

   strings:
      $string1= "CDEFGHIJKLMNOPQRSTUVWXYZABcdefghijklmnopqrstuvwxyzab0123456789+/" wide ascii
      $string2= "cmd.exe" wide ascii

   condition:
      all of them
}