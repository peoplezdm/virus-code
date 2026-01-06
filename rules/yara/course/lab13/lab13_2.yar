rule Lab13_02_exe {
   meta:
      description = " - file Lab13-02.exe"
      date = "2024-12-04"

   strings:
      $string1= "temp%08x" wide ascii
      $string2= "GetACP" wide ascii
      $string3= "GetDC" wide ascii
      
   condition:
      all of them
}