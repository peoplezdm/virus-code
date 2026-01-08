rule Lab12_01_dll {
   meta:
      description = " - file Lab12-01.dll"
      date = "2024-12-02"

   strings:
      $string1 =  "Press OK to reboot" wide ascii
      $string2 = "Practical Malware Analysis %d" wide ascii nocase
      
   condition:
      all of them
}