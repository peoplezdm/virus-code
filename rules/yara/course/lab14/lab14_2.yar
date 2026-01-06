rule Lab14_02_exe {
   meta:
      description = " - file Lab14-02.exe"
      date = "2024-12-05"

   strings:
      $string1= "WXYZlabcd3fghijko12e456789ABCDEFGHIJKL+/MNOPQRSTUVmn0pqrstuvwxyz" wide ascii
      $string2= "/c del" wide ascii nocase
      $string3= "cmd.exe" wide ascii
      
   condition:
      all of them
}