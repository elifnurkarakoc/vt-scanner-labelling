## VT-Scanner & Labelling


***VT-Scanner*** is a tool that allows file querying and url querying in VirusTotal.

According to antivirus results from VirusTotal, it presents what the query is with "VT Scanner Label".

        C:\Users\ELIFNUR\Downloads\vt-scanner>vtscanner.py --help
        
         _    ________   _____
        | |  / /_  __/  / ___/_________ _____  ____  ___  _____
        | | / / / /     \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
        | |/ / / /     ___/ / /__/ /_/ / / / / / / /  __/ /
        |___/ /_/     /____/\___/\__,_/_/ /_/_/ /_/\___/_/
        
                           Developed By: Elif Nur KARAKOC
        
        usage: virustotal2.py [-h] --apikey APIKEY [--filescan FILESCAN] [--filereport FILEREPORT] [--urlreport URLREPORT]
        
        It provides URL and file query by using VirusTotal API.
        
        optional arguments:
          -h, --help            show this help message and exit
          --apikey APIKEY       VirusTotal API Key.
          --filescan FILESCAN   Upload and scan a file
          --filereport FILEREPORT
                                Report a file
          --urlreport URLREPORT
                                Report an URL
    
   ### Example usage
   - --urlreport
   
    C:\Users\ELIFNUR\Desktop\vt-scanner>vtscanner.py --apikey "YOUR API KEY" --urlreport "https://bankraifcz.online/"
    
     _    ________   _____
    | |  / /_  __/  / ___/_________ _____  ____  ___  _____
    | | / / / /     \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
    | |/ / / /     ___/ / /__/ /_/ / / / / / / /  __/ /
    |___/ /_/     /____/\___/\__,_/_/ /_/_/ /_/\___/_/
    
                       Developed By: Elif Nur KARAKOC
    
    +-------+-----------+---------------------+---------------------+
    | Total | Positives |     VirusTotal%     |      Scan date      |
    +-------+-----------+---------------------+---------------------+
    |   79  |     2     | 0.02531645569620253 | 2020-07-03 15:10:15 |
    +-------+-----------+---------------------+---------------------+
    +---------------+---------------+-----------+-----------+------------------+
    |    CLEAN MX   |  BitDefender  |  Spamhaus |  Fortinet | VT Scanner Label |
    +---------------+---------------+-----------+-----------+------------------+
    | phishing site | phishing site | spam site | spam site |     phishing     |
    +---------------+---------------+-----------+-----------+------------------+
      
  

- --filereport 


      C:\Users\ELIFNUR\Desktop\vt-scanner>vtscanner.py --apikey "YOUR API KEY" --filereport 0a2d1ecedf3f79754aa2c18d62e75287
        
         _    ________   _____
        | |  / /_  __/  / ___/_________ _____  ____  ___  _____
        | | / / / /     \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
        | |/ / / /     ___/ / /__/ /_/ / / / / / / /  __/ /
        |___/ /_/     /____/\___/\__,_/_/ /_/_/ /_/\___/_/
        
                           Developed By: Elif Nur KARAKOC
        
        +----------------------------------+------------------------------------------+------------------------------------------------------------------+-------+-----------+--------------------+---------------------+
        |               MD5                |                   SHA1                   |                              SHA256                              | Total | Positives |    VirusTotal%     |      Scan date      |
        +----------------------------------+------------------------------------------+------------------------------------------------------------------+-------+-----------+--------------------+---------------------+
        | 0a2d1ecedf3f79754aa2c18d62e75287 | 4dc6c7ad46c152ee6ebf26488fd5136dd9acfa4f | e800fce6aadc7792b912abbb693aafe0905a5ab52bc92de9e2a50089de312be9 |   72  |     61    | 0.8472222222222222 | 2020-07-03 19:06:19 |
        +----------------------------------+------------------------------------------+------------------------------------------------------------------+-------+-----------+--------------------+---------------------+
        +----------------------+-------------------------------------------+
        |      Antivirus       |                   Result                  |
        +----------------------+-------------------------------------------+
        |         Bkav         |           W32.BanloadBCQ.Trojan           |
        |        ClamAV        |     Win.Trojan.CobaltStrike-8091534-0     |
        |       FireEye        |        Generic.mg.0a2d1ecedf3f7975        |
        |    CAT-QuickHeal     |         Trojan.GenericRI.S7544384         |
        |        McAfee        |            Artemis!0A2D1ECEDF3F           |
        |       Cylance        |                   Unsafe                  |
        |        VIPRE         |          Trojan.Win32.Generic!BT          |
        |       Sangfor        |                  Malware                  |
        |     K7AntiVirus      |           Riskware ( 0050f89b1 )          |
        |       Alibaba        | TrojanDownloader:Win32/CoinMiner.d82be1ab |
        |         K7GW         |           Riskware ( 0050f89b1 )          |
        |      Cybereason      |              malicious.edf3f7             |
        |       Arcabit        |             Trojan.Razy.D74D4E            |
        |      TrendMicro      |       Coinminer.Win64.MALXMR.SMCGR24      |
        |        F-Prot        |          W32/S-d757aa55!Eldorado          |
        |       Symantec       |             Packed.Generic.551            |
        |         APEX         |                 Malicious                 |
        |       Paloalto       |                 generic.ml                |
        |        Cynet         |           Malicious (score: 90)           |
        |      Kaspersky       |   Trojan-Downloader.Win32.Banload.abipe   |
        |     BitDefender      |          Gen:Variant.Razy.478542          |
        |    NANO-Antivirus    |        Trojan.Win32.Banker1.fpaaqi        |
        |   MicroWorld-eScan   |          Gen:Variant.Razy.478542          |
        |       Tencent        |          Trojan.Win64.CoinMiner.b         |
        |       Ad-Aware       |          Gen:Variant.Razy.478542          |
        |        Sophos        |               Troj/Miner-XY               |
        |        Comodo        |           Malware@#1o6dn8f5288bn          |
        |       F-Secure       |         Trojan.TR/Crypt.XPACK.Gen         |
        |        DrWeb         |            Trojan.BtcMine.3361            |
        |        Zillya        |       Downloader.Banload.Win32.89529      |
        |       Invincea       |                 heuristic                 |
        |       Trapmine       |          suspicious.low.ml.score          |
        |       Emsisoft       |        Gen:Variant.Razy.478542 (B)        |
        |        Cyren         |       W64/CoinMiner.AX.gen!Eldorado       |
        |       Webroot        |               W32.Trojan.Gen              |
        |        Avira         |             TR/Crypt.XPACK.Gen            |
        |       Fortinet       |              W64/Miner.UU!tr              |
        |      Antiy-AVL       |     Trojan[Backdoor]/Win32.Inject.msf     |
        |       Endgame        |        malicious (high confidence)        |
        |      Microsoft       |           Trojan:Win64/CoinMiner          |
        |       AegisLab       |         Trojan.Win32.Banload.tqMl         |
        |      ZoneAlarm       |   Trojan-Downloader.Win32.Banload.abipe   |
        |      AhnLab-V3       |        Trojan/Win32.Cometer.R289456       |
        |       Acronis        |                 suspicious                |
        |   BitDefenderTheta   |      Gen:NN.ZexaF.34130.@3W@aubbsodi      |
        |        ALYac         |          Gen:Variant.Razy.478542          |
        |         MAX          |           malware (ai score=82)           |
        |        VBA32         |          RiskTool.Win64.BitMiner          |
        |     Malwarebytes     |             Trojan.MalPack.GO             |
        |      ESET-NOD32      |             Win64/CoinMiner.SY            |
        | TrendMicro-HouseCall |       Coinminer.Win64.MALXMR.SMCGR24      |
        |        Rising        |      Trojan.CoinMiner!1.C2B5 (CLOUD)      |
        |        Yandex        |          Trojan.Agent!KkQWKOQcsJ8         |
        |        Ikarus        |      Trojan-Downloader.Win32.Banload      |
        |       eGambit        |               Trojan.Generic              |
        |        GData         |          Gen:Variant.Razy.478542          |
        |      MaxSecure       |        Trojan.Malware.121218.susgen       |
        |         AVG          |             Win32:Malware-gen             |
        |        Panda         |                  Trj/CI.A                 |
        |     CrowdStrike      |      win/malicious_confidence_60% (W)     |
        |      Qihoo-360       |        Win32/Trojan.Downloader.093        |
        |   VT Scanner Label   |                   Trojan                  |
        +----------------------+-------------------------------------------+
- --filescan
- 



 

    C:\Users\ELIFNUR\Desktop\vt-scanner>vtscanner.py --apikey "YOUR API KEY" --filescan "C:\\Users\\ELIFNUR\\Downloads\\ZoomInstaller.exe"    

                                       
    
     _    ________   _____
    | |  / /_  __/  / ___/_________ _____  ____  ___  _____
    | | / / / /     \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
    | |/ / / /     ___/ / /__/ /_/ / / / / / / /  __/ /
    |___/ /_/     /____/\___/\__,_/_/ /_/_/ /_/\___/_/
    
                       Developed By: Elif Nur KARAKOC
    
    +----------------------------------+------------------------------------------+------------------------------------------------------------------+-------+-----------+-------------+---------------------+
    |               MD5                |                   SHA1                   |                              SHA256                              | Total | Positives | VirusTotal% |      Scan date      |
    +----------------------------------+------------------------------------------+------------------------------------------------------------------+-------+-----------+-------------+---------------------+
    | 08c695a062029eeb4596a7b1e8b4b0e6 | 714d19917d117e9d1f5404c82752256576e256be | 602a024f3ad69c953994b989c0441a5b3f54242878af2242d9dbf7e2b9c998bf |   71  |     0     |     0.0     | 2020-07-03 18:31:23 |
    +----------------------------------+------------------------------------------+------------------------------------------------------------------+-------+-----------+-------------+---------------------+

#### Task Lists
 - [ ] Result JSON
 - [ ] URL SCAN
 - [ ] Domain Report
 - [ ] IP Report

