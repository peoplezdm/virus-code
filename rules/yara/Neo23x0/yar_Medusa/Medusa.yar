rule Medusa_4K_Sports {
    meta:
        description = "Detects Medusa variant associated with '4K Sports'"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-20"
        version = "1.0"
        reference = "https://www.cleafy.com/cleafy-labs/medusa-reborn-a-new-compact-variant-discovered"
        copyright = "InfoSEC"

    strings:
        $app_name = "4K Sports" ascii nocase
        $url = "a4a4a4a.life" ascii nocase
        $hash1 = "1db5ce9cbb3932ce2e11e5b3cd900ee2" ascii
        $hash2 = "97abc0aa3819e161ca1f7f3e78025e15" ascii
        $hash3 = "8468c1cda925021ed911fd9c17915eec" ascii
        $file_name = "4K_Sports" ascii nocase

    condition:
        any of ($app_name, $url, $hash*, $file_name)
}

rule Medusa_Purolator {
    meta:
        description = "Detects Medusa variant associated with 'Purolator'"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-20"
        version = "1.0"
        reference = "https://www.cleafy.com/cleafy-labs/medusa-reborn-a-new-compact-variant-discovered"
        copyright = "InfoSEC"

    strings:
        $app_name = "Purolator" ascii nocase
        $url1 = "a4a4a4a.life" ascii nocase
        $url2 = "unkunknunkkkkk.info" ascii nocase
        $url3 = "cincincintopcin.info" ascii nocase
        $hash1 = "cb1280f6e63e4908d52b5bee6f65ec63" ascii
        $hash2 = "a5aeb6ccc48fea88cf6c6bcc69940f8a" ascii
        $hash3 = "bd7b9dd5ca8c414ff2c4744df41e7031" ascii
        $file_name = "Purolator" ascii nocase

    condition:
        any of ($app_name, $url*, $hash*, $file_name)
}

rule Medusa_Inat_TV_Video_Oynaticisi {
    meta:
        description = "Detects Medusa variant associated with 'İnat TV Video Oynaticisi'"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-20"
        version = "1.0"
        reference = "https://www.cleafy.com/cleafy-labs/medusa-reborn-a-new-compact-variant-discovered"
        copyright = "InfoSEC"

    strings:
        $app_name = "İnat TV Video Oynaticisi" ascii nocase
        $url = "tony1303sock.top" ascii nocase
        $hash1 = "4c12987ac5d56a35258b3b7cdc87f038" ascii
        $hash2 = "3fbe1323bdef176a6011a534e15a80f0" ascii
        $hash3 = "0e7c37e28871f439539b3d87242def55" ascii
        $file_name = "İnat_TV_Video_Oynaticisi" ascii nocase

    condition:
        any of ($app_name, $url, $hash*, $file_name)
}

rule Medusa_Chrome_Update {
    meta:
        description = "Detects Medusa variant associated with 'Chrome Güncelleme'"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-20"
        version = "1.0"
        reference = "https://www.cleafy.com/cleafy-labs/medusa-reborn-a-new-compact-variant-discovered"
        copyright = "InfoSEC"

    strings:
        $app_name = "Chrome Güncelleme" ascii nocase
        $url = "baahhhs21.info" ascii nocase
        $hash1 = "185f8c23fd680cae560aad220e137886" ascii
        $hash2 = "3b7df8e68eca9a4bcc559d79a2c5a4c7" ascii
        $file_name = "Chrome_Guncelleme" ascii nocase

    condition:
        any of ($app_name, $url, $hash*, $file_name)
}
