rule Lab07_02 {
   meta:
      description = " - file Lab07-02"
      date = "2024-10-27"

   strings:
      $string_1 = "_controlfp"
      $string_2="__setusermatherr"
      $fun_1 = "OleUninitialize"
      $fun_2 = "CoCreateInstance" 
      $fun_3= "OleInitialize"
      $dll_1="MSVCRT.dll" nocase 
      $dll_2="OLEAUT32.dll" nocase
      $dll_3="ole32.dll" nocase

   condition:
       filesize < 100KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and all of them
}