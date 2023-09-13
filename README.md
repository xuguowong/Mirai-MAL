# Mirai-Variant

## 参考资料
VB2018 paper: Tracking Mirai variants  
https://www.virusbulletin.com/virusbulletin/2018/12/vb2018-paper-tracking-mirai-variants/  
Seven new Mirai variants and the aspiring cybercriminal behind them  
https://blog.avast.com/hacker-creates-seven-new-variants-of-the-mirai-botnet  

## Sora、Owari
* OWARI+0x54、OWARI+0x66
* Two different prompt lines are used: ‘OWARI09123id9i123xd912’ and ‘Follow twitter.com/1337Wicked’
https://www.virusbulletin.com/virusbulletin/2018/12/vb2018-paper-tracking-mirai-variants/  
https://blog.newskysecurity.com/understanding-the-iot-hacker-a-conversation-with-owari-sora-iot-botnet-author-117feff56863  
* Wicked的回答是：“Sora现在是一个被停滞的项目，我会继续对Owari进行研究。我目前的计划是继续对已有项目进行更新，因此不会很快出现第三个新的项目。”


## Satori、JenX、OMG、Wicked-2018 may
https://www.netscout.com/blog/asert/omg-mirai-minions-are-wicked  MAY 31ST, 2018
### Satori
* NETSCOUT Arbor saw several variants of Satori in the wild from December 2017 through January 2018. 
* simply modifies the XOR key to “0x07”
### JenX
### OMG

### Satori   -December 2017 
Huawei Home Routers in Botnet Recruitment    December 21, 2017  
https://research.checkpoint.com/2017/good-zero-day-skiddie/    
https://blog.netlab.360.com/warning-satori-a-new-mirai-variant-is-spreading-in-worm-style-on-port-37215-and-52869-en/    5 DECEMBER 2017  
https://securityaffairs.co/wordpress/67040/malware/satori-botnet-mirai-variant.html    December 23, 2017   
* “A Zero-Day vulnerability (CVE-2017-17215) in the Huawei home router HG532 has been discovered by Check Point Researchers, and hundreds of thousands of attempts to exploit it have already been found in the wild.
* The delivered payload has been identified as OKIRU/SATORI, an updated variant of Mirai.
* The suspected threat actor behind the attack has been identified by his nickname, ‘Nexus Zeta’.” states the report published by Check Point security.
* "unixfreaxjp" from  "MalwareMustDie" , "2018-01-05"  
https://github.com/unixfreaxjp/rules/blob/master/malware/MALW_Mirai_Satori_ELF.yar
* Add GPON exploit in 2018.5  
https://blog.netlab.360.com/gpon-exploit-in-the-wild-ii-satori-botnet/  
* Satori (also known as Mirai Okiru, and detected by Trend Micro as ELF_MIRAI.AUSR)  
https://www.trendmicro.com/vinfo/ph/security/news/internet-of-things/source-code-of-iot-botnet-satori-publicly-released-on-pastebin   2018.Jan
### Okiru -December 2017 
* Okiru & Satori
https://www.reddit.com/r/LinuxMalware/comments/7p00i3/quick_notes_for_okiru_satori_variant_of_mirai/  2018.Jan  
![image](https://github.com/xuguowong/Mirai-MAL/assets/128561542/df446260-3451-467c-bd85-434832575e70)  
* 专门感染ARC CPU的Linux恶意软件
* "unixfreaxjp" from  "MalwareMustDie" , "2018-01-05"  
https://github.com/unixfreaxjp/rules/blob/master/malware/MALW_Mirai_Okiru_ELF.yar
```
  Ada
  $s1 = "/usr/dvr_main _8182T_1108"
  $s2 = "/var/Challenge"
  $s3 = "/mnt/mtd/app/gui"
  
  (wuhd(ibs(sdw   '/proc/net/tcp'
  cquObkwbu       'dvrHelper'
  ardlcqu         'fuckdvr'
  rtpftobub        'uswashere'
  en`ehsWbni      'bigbotPein'
  WHTS'(dci*d`n(      'POST /cdn-cgi/'
  bkaKhfc   'elfLoad'
  bifekb     'enable'
  t~tsbj     'system'
  tobkk      'shell
  (eni(ert~eh   '/bin/busybo'
  HLNUR      'OKIRU'
  ='fwwkbs    ': applet'
  `bs='fwwkbs'ihs'ahric   'get: applet not found'
  asw='fwwkbs'ihs'ahric     'ftp: applet not found'
  doh='fwwkbs'ihs'ahric
  BDOHCHIB      'ECHODONE'
  'dfs'(eni(ert~eh
  '{{'ponkb'ubfc'n<'ch'(eni(ert~eh
  'bdoh'<'chib';'(eni(ert~eh
  '{{'(eni(ert~eh
  'cc'na:(eni(ert~eh
  'et:55'dhris:6h
  'p`bs<'(eni(ert~eh
  'sasw<'(eni(ert~eh
```
https://www.securityartwork.es/2018/03/13/analysis-of-linux-okiru/  
https://slab.qq.com/news/tech/1705.html  
https://blog.netlab.360.com/warning-satori-a-new-mirai-variant-is-spreading-in-worm-style-on-port-37215-and-52869-en/  
https://www.securityartwork.es/2018/03/13/analysis-of-linux-okiru/  
* XOR algorithm, specifically with the key 0x07

### Masuta -Jan 2018
Masuta : Satori Creators’ Second Botnet Weaponizes A New Router Exploit.   
https://blog.newskysecurity.com/masuta-satori-creators-second-botnet-weaponizes-a-new-router-exploit-2ddc51cc52a7   Jan 24, 2018  
https://zhuanlan.zhihu.com/p/33457121  
*	Satori开发者的第二个僵尸网络，利用新的路由器漏洞实现武器化
*	xored by ((DE^DE)^FF) ^BA or 0x45
*	PureMasuta Variant & Exploit Usage
*	EDB 38722 D-Link HNAP Bug: hxxp://purenetworks.com/HNAP1/GetDeviceSettings
*	 CVE-2014–8361 and CVE-2017–17215 in his Satori botnet project, A third SOAP exploit, TR-069 bug,EDB 38722 the fourth SOAP related exploit   
https://www.virusbulletin.com/virusbulletin/2018/12/vb2018-paper-tracking-mirai-variants/
*	Two different prompt lines are used: ‘gosh that chinese family at the other table sure ate alot’ and ‘The Void’.
*	In some samples the C&Cs are hard coded in resolve_cnc_addr() but old default C&Cs are still kept in configurations.
https://sidechannel.tempestsi.com/new-variant-of-the-mirai-botnet-has-activity-detected-in-brazil-a3456c548088  Jul 26, 2018 
*	D-Link DSL-2750B等五个漏洞

### Omni -May 2018
https://blog.newskysecurity.com/cve-2018-10561-dasan-gpon-exploit-weaponized-in-omni-and-muhstik-botnets-ad7b1f89cff3  
https://blog.netlab.360.com/gpon-exploit-in-the-wild-iii-mettle-hajime-mirai-omni-imgay/  
*	target the vulnerable GPON routers
*	This leads us to conclude that Omni botnet is brewing in the same lab as Owari.
*	WICKED、Sora、Owari和Omni僵尸网络的关联
*	正如我们在/bin目录下所看到的，Sora和Owari僵尸网络样本现在已经不再更新，二者已经被Omni取代
https://www.fortinet.com/blog/threat-research/a-wicked-family-of-bots   May 17, 2018
https://zhuanlan.zhihu.com/p/37123460   May 2018

### Wicked -May 2018
https://www.netscout.com/blog/asert/omg-mirai-minions-are-wicked  MAY 31ST, 2018  
https://www.virusbulletin.com/virusbulletin/2018/12/vb2018-paper-tracking-mirai-variants/  
*	 Wicked is using “0x37” as the XOR key
*	Netgear routers and CCTV-DVR devices
*	WICKED、Sora、Owari和Omni僵尸网络的关联


### Shinoa -May 2018
https://www.fortinet.com/blog/threat-research/shinoa--owari--mirai--what-s-with-all-the-anime-references-


### Omni、Okane--June 2018
https://unit42.paloaltonetworks.com/unit42-finds-new-mirai-gafgyt-iotlinux-botnet-campaigns/  
July 20, 2018    
https://zhuanlan.zhihu.com/p/40514566   
CAMPAIGN 1: An evolution of Omni-after May 2018  
*	Since then the same family has evolved to incorporate several more exploits( 11  vulnerabilities)
*	Aside from using the standard XOR encryption, table key 0xBAADF00D(0xea)
*	Samples rely solely on exploits for propagation and don’t perform a credential brute-force attack.  
CAMPAIGN 2: Okane--June 2018
*	0xDEACFBEF(0x66)
*	exploits
*	a credential brute force attack
*	Digging deeper reveals that samples using these attack methods have been part of a Mirai code fork from as early as August 2017.  
CAMPAIGN 3: Hakai
*	0xDEDEFFBA
*	......


### Miori-December 2018
Miori IoT Botnet Delivered via ThinkPH Exploit
https://www.trendmicro.com/en_us/research/18/l/with-mirai-comes-miori-iot-botnet-delivered-via-thinkphp-remote-code-execution-exploit.html
*	ThinkPHP RCE 
*	XOR key: 0x62
```
JavaScript
/bin/busybox MIORI (infection verification)
MIORI: applet not found (infection verification)
'miori remastered infection successful!!'
your device just got infected to a bootnoot
```

### Backdoor.Linux.MIRAI.AR
https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/backdoor.linux.mirai.ar
*	 via ThinkPHP Remote Code Execution exploit
*	your device just got infected to a bootnoot
*	lolis{BLOCKED}er.com:42352


### IZ1H9 
*	XOR key: 0xE0  
```
Plain Text
/bin/busybox IZ1H9 (infection verification)
IZ1H9: applet not found
j.#0388 (printed out in console after execution)
```

### APEP
XOR key: 0x04
```
Plain Text
/bin/busybox APEP (infection verification)
CIA NIGGER
terryadavis
```
*	Aside from Miori, several known Mirai variants like IZ1H9 and APEP were also spotted using the same RCE exploit for their arrival method. 
*	It should be noted that aside from dictionary attacks via Telnet, APEP also spreads by taking advantage of CVE-2017-17215, which involves another RCE vulnerability and affects Huawei HG532 router devices, for its attacks. The vulnerability was also reported to be involved in Satori and Brickerbot variants. Huawei has since released a security notice and outlined measures to circumvent possible exploitation.


### Backdoor.Linux.MIRAI.AS
https://www.trendmicro.com/vinfo/tw/threat-encyclopedia/malware/backdoor.linux.mirai.as
*	It may spread to other devices by taking advantage of CVE-2017-17215 which is another remote code execution for specific Huawei routers
*	CIA NIGGER       lKeeGp->NiGGeR   lKeeGp/lKeeGpF
*	密码表


### YOWAI -Jan 2019
*	We found a new Mirai variant we’ve called Yowai and Gafgyt variant Hakai abusing a ThinkPHP flaw for propagation and DDoS attacks.
*	Backdoor.Linux.YOWAI.A
https://www.trendmicro.com/en_us/research/19/a/thinkphp-vulnerability-abused-by-botnets-hakai-and-yowai.html?_ga=2.98405279.1228685734.1611507832-1111072250.1576638258
https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/Backdoor.Linux.YOWAI.A
https://www.freebuf.com/articles/terminal/195498.html
```
Makefile
CVE-2018-10561  GPON Routers CI
CVE-2014-8361   UPnP SOAP Command Execution
ThinkPHP exploit
Linksys Remote Code Execution
CCTV-DVR Remote Code Execution

Yowai: Raping you sorry

OxhlwSG8
tlJwpbo6
S2fGqNFs
```

### Echobot--April 2019
Mirai Variant Spotted Using Multiple Exploits, Targets Various Routers   April 04, 2019
https://www.trendmicro.com/vinfo/ie/security/news/internet-of-things/mirai-variant-spotted-using-multiple-exploits-targets-various-routers
*	malware authors named it ECHOBOT
*	Exploits
```
C#
Exploit for CVE-2014-8361
Exploit for CVE-2013-4863 and CVE-2016-6255
A privilege escalation security flaw in the ZyXEL P660HN-T v1 
Authentication bypass (CVE-2018-10561) and command injection (CVE-2018-10562) 
An arbitrary command execution vulnerability (CVE-2017-17215) in Huawei Router HG532, This security flaw is also exploited by other IoT botnet malware Satori and Miori.
A remote code execution (RCE) flaw in Linksys E-Series routers that was also exploited by TheMoon, one of the earliest IoT botnet malware.
An RCE exploit for the ThinkPHP 5.0.23/5.1.31, also observed the Hakai and Yowai 
```
*	New credentials: videoflow, huigu309, CRAFTSPERSON, ALC#FGU, and wbox123
*	hxxp://192[.]210[.]135[.]113/ECHO/ECHOBOT[.]mips

### Trojan.Linux.MIRAI.SMMR1 ???
https://www.freebuf.com/articles/terminal/190554.html  
路由器漏洞频发，Mirai新变种来袭  
NetGear路由器  
GPON光纤路由器  
华为HG532系列路由器  
linksys多款路由器  
□ 099b88bb74e9751abb4091ac4f1d690d  
```
Plain Text
【trend:Backdoor.Linux.MIRAI.SMMR1】但是现在搜索不到这个了么，换成Backdoor.Linux.GAFGYT.SMMR1？？？-->这个存疑
【ka：HEUR:Backdoor.Linux.Mirai.b】
Tencent：Backdoor.Linux.Mirai.wao
Microsoft：Backdoor:Linux/Mirai.YA!MTB
46.17.47.82
```
*	样本与 mirai 是同一个家族的样本，是 mirai 病毒的一个变种。代码结构和解密后的字符串均非常相似，不同的是此变种使用了3个路由器漏洞进行传播。
*	多个watchdog 检测路径
*	该 Twitter 的作者 Philly 是一个美国人，病毒存放的路径为 nigr（Philly 的自称），从 Twitter 中未发现直接与蠕虫相关的推文。
□ 另一个样本以及相关  
f657400270b9e5d78b8395e9ac6c689311d8afd371982ef696d67d31758c1751  
```
Makefile
【ECHOBOT.mips】from vt
TrendMicro：Trojan.Linux.MIRAI.SMMR1 【目前这个分类找不到？？？】
Kaspersky：HEUR:Backdoor.Linux.Mirai.ad
Microsoft：DDoS:Linux/Gafgyt.YA!MTB
Tencent：Backdoor.Linux.Mirai.wao
但是也不是Backdoor.Linux.GAFGYT.SMMR1
```

### Echobot by unit 42
https://unit42.paloaltonetworks.com/new-mirai-variant-targets-enterprise-wireless-presentation-display-systems/   March 18, 2019 
*	This latest sample contains a total of 27 exploits, of which are 11 new to Mirai.
https://unit42.paloaltonetworks.com/new-mirai-variant-adds-8-new-exploits-targets-additional-iot-devices/  June 6, 2019
*	8 New Exploits
*	The encryption key used for the string table is 0xDFDAACFD, which is the equivalent of a byte wise XOR with 0x54
*	New credentials: blueangel/blueangel ......
Backdoor.Linux.MIRAI.VWIQG  
https://www.trendmicro.com/vinfo/my/threat-encyclopedia/malware/backdoor.linux.mirai.vwiqg


### New Mirai Variant
New Mirai Variant Uses Multiple Exploits    May 23, 2019
https://www.trendmicro.com/en_us/research/19/e/new-mirai-variant-uses-multiple-exploits-to-target-routers-and-other-devices.html
*	0x22（标准Mirai字符串）
*	0x37（带“watchdog”的字符串）
*	0xea（暴力攻击的凭证：“telecomadmin”，“admintelecom”等）
*	As previously mentioned, this variant is the first Mirai variant to have used all 13 exploits in a single campaign. 



### Backdoor.Linux.MIRAI.VWIPT
https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/Backdoor.Linux.MIRAI.VWIPT



### Asher-- July 2019
https://www.trendmicro.com/en_us/research/19/h/back-to-back-campaigns-neko-mirai-and-bashlite-malware-variants-use-various-exploits-to-target-several-routers-devices.html  
https://www.freebuf.com/articles/terminal/211572.html
*	执行“/bin/busybox {any string}”命令, 设备系统给出响应“{any string} applet not found”, 在这个样本中，使用的是“Asher”
* telnet login credentials



### Backdoor.Linux.MIRAI.VWIRC
https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/backdoor.linux.mirai.vwirc
*	Asher = SylveonsAreCuteUwu
*	密码表OxhlwSG8
*	MVPower DVR TV-7104HE 1.8.4 115215B9 - Shell Command Execution (Metasploit)
*	Realtek SDK - Miniigd UPnP SOAP Command Execution (Metasploit)
*	GPON Routers - Authentication Bypass / Command Injection


### IoT.Linux.MIRAI.DLEU
https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/IoT.Linux.MIRAI.DLEU/



### Mukashi--March  2020
https://unit42.paloaltonetworks.com/new-mirai-variant-mukashi/  
http://www.hackdig.com/03/hack-74767.htm  
Zyxel NAS设备  
https://www.zyxel.com/support/mirai_malware_variant.shtml  
*	Zyxel Network
*	Mukashi uses a custom decryption routine to encrypt these commands and credentials. A decryption script is provided in the appendix.
*	juantech
*	45.84.196.75


### Mirai Botnet Attack IoT Devices via CVE-2020-5902
https://www.trendmicro.com/en_us/research/20/g/mirai-botnet-attack-iot-devices-via-cve-2020-5902.html  
https://documents.trendmicro.com/assets/IoCs_Appendix_Mirai-Botnet-Exploit-Weaponized-to-Attack-IoT-Devices-via-CVE-2020-5902.pdf  



### Trojan.SH.MIRAI.BOI
sora.{architecture}  
https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/Trojan.SH.MIRAI.BOI/  
https://paper.seebug.org/1286/  
### SORA  
https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/sora-and-unstable-2-mirai-variants-target-video-surveillance-storage-systems February 05, 2020  
XOR-encrypted with the key DEDEFBAF  
XOR-encryption to hide its strings (key: DEADDAAD).  



### DarkNexus
https://www.bitdefender.com/files/News/CaseStudies/study/319/Bitdefender-PR-Whitepaper-DarkNexus-creat4349-en-EN-interactive.pdf  
https://csirt.cy/a-new-emerging-iot-botnet-malware-dark-nexus-spotted-in-the-wild/  
https://arstechnica.com/information-technology/2020/04/meet-dark_nexus-quite-possibly-the-most-potent-iot-botnet-ever/  
https://thehackernews.com/2020/04/darknexus-iot-ddos-botnet.html  
https://threatpost.com/dark_nexus-botnet-asus-dlink-routers/154571/  



### LeetHozer botnet 27 APRIL 2020
https://blog.netlab.360.com/the-leethozer-botnet-en/



### Mozi, Another Botnet Using DHT   23 DECEMBER 2019/
https://blog.netlab.360.com/mozi-another-botnet-using-dht/
```
Makefile
130.239.18.159:6881
dht.transmissionbt.com:6881
87.98.162.88:6881
82.221.103.244:6881
212.129.33.59:6881
router.bittorrent.com:6881
bttracker.debian.org:6881
GET /Mozi.m HTTP/1.0 ---> 83??/17000
但是这个的相关样本是漏洞大全
```


### Mirai, Lizard Squad, and BigBotPein
![image](https://github.com/xuguowong/Mirai-MAL/assets/128561542/11a91353-0c5b-49ae-8ca6-311e323cc5b5)

https://www.securitynewspaper.com/2018/02/03/lizard-squad-alive-continuing-activities-bigbotpein-report/  
https://www.hackread.com/wp-content/uploads/2018/01/Lizard-Squad-BigBotPein-hackers-ddos-attackers.pdf  
```
YAML
Trojan_Linux_MIRAI_g
s2 = "GET /pein.arm"
$s1="bigbotPein"
$s2={47 45 54 20 2f 70 65 69 6e}
```
Mirai Compiled for New Processors Surfaces in the Wild  April 8, 2019   
https://unit42.paloaltonetworks.com/mirai-compiled-for-new-processor-surfaces/  


### A List of Top 20 IoT Blackhat Hackers
Tracking the People Behind Botnets: A List of Top 20 IoT Blackhat Hackers  
https://blog.newskysecurity.com/tracking-the-people-behind-botnets-a-list-of-top-20-iot-blackhat-hackers-3a67d7bd3be0  
*	ROOT.SENPAI 
*	DADDYL33T



























