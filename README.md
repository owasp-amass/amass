
# [![OWASP Logo](https://github.com/OWASP/Amass/blob/master/images/owasp_logo.png) OWASP Amass](https://www.owasp.org/index.php/OWASP_Amass_Project)

[![CircleCI Status](https://circleci.com/gh/OWASP/Amass/tree/master.svg?style=shield)](https://circleci.com/gh/OWASP/Amass/tree/master)
[![GitHub release](https://img.shields.io/github/release/OWASP/Amass)](https://github.com/OWASP/Amass/releases)
[![Go Version](https://img.shields.io/badge/go-1.13-blue.svg)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

[![Bugcrowd LevelUp 0x04](https://img.shields.io/badge/Bugcrowd-LevelUp%200x04-orange.svg)](https://www.youtube.com/watch?v=C-GabM2db9A)
[![DEF CON 27 Demo Labs](https://img.shields.io/badge/DEF%20CON%2027-Demo%20Labs-purple.svg)](https://www.defcon.org/html/defcon-27/dc-27-demolabs.html)
[![DEF CON 27 Recon Village](https://img.shields.io/badge/DEF%20CON%2027-Recon%20Village-red.svg)](https://reconvillage.org/)

----

<p align="center">
  <img alt="DNS Enumeration" src="https://github.com/OWASP/Amass/blob/master/images/amass.gif" width="577" height="685" />
</p>

----

The OWASP Amass Project has developed a tool to help information security professionals perform network mapping of attack surfaces and perform external asset discovery using open source information gathering and active reconnaissance techniques.

**Information Gathering Techniques Used:**

* **DNS:** Basic enumeration, Brute forcing (upon request), Reverse DNS sweeping, Subdomain name alterations/permutations, Zone transfers (upon request)
* **Scraping:** Ask, Baidu, Bing, DNSDumpster, DNSTable, Dogpile, Exalead, Google, HackerOne, IPv4Info, Netcraft, PTRArchive, Riddler, SiteDossier, ViewDNS, Yahoo
* **Certificates:** Active pulls (upon request), Censys, CertSpotter, Crtsh, Entrust, GoogleCT
* **APIs:** AlienVault, BinaryEdge, BufferOver, CIRCL, CommonCrawl, DNSDB, HackerTarget, Mnemonic, NetworksDB, PassiveTotal, RADb, Robtex, SecurityTrails, ShadowServer, Shodan, Spyse (CertDB & FindSubdomains), Sublist3rAPI, TeamCymru, ThreatCrowd, Twitter, Umbrella, URLScan, VirusTotal
* **Web Archives:** ArchiveIt, ArchiveToday, Arquivo, LoCArchive, OpenUKArchive, UKGovArchive, Wayback

----

## Documentation

Use the [Installation Guide](https://github.com/OWASP/Amass/blob/master/doc/install.md) to get started.

Go to the [User's Guide](https://github.com/OWASP/Amass/blob/master/doc/user_guide.md) for additional information.

## Community

[![Contribute Yes](https://img.shields.io/badge/contribute-yes-brightgreen.svg)](https://github.com/OWASP/Amass/blob/master/CONTRIBUTING.md)
[![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/rtN8GMd)
[![Follow on Twitter](https://img.shields.io/twitter/follow/owaspamass.svg?logo=twitter)](https://twitter.com/owaspamass)

### Project Leader

[![Follow on Twitter](https://img.shields.io/twitter/follow/jeff_foley.svg?logo=twitter)](https://twitter.com/jeff_foley)

* OWASP: [Caffix](https://www.owasp.org/index.php/User:Caffix)
* GitHub: [@caffix](https://github.com/caffix)

### Contributors

This project improves thanks to all the people who contribute:

[![Follow on Twitter](https://img.shields.io/twitter/follow/emtunc.svg?logo=twitter)](https://twitter.com/emtunc)
[![Follow on Twitter](https://img.shields.io/twitter/follow/kalbasit.svg?logo=twitter)](https://twitter.com/kalbasit)
[![Follow on Twitter](https://img.shields.io/twitter/follow/fork_while_fork.svg?logo=twitter)](https://twitter.com/fork_while_fork)
[![Follow on Twitter](https://img.shields.io/twitter/follow/rbadguy1.svg?logo=twitter)](https://twitter.com/rbadguy1)
[![Follow on Twitter](https://img.shields.io/twitter/follow/danjomart.svg?logo=twitter)](https://twitter.com/danjomart)
[![Follow on Twitter](https://img.shields.io/twitter/follow/shane_ditton.svg?logo=twitter)](https://twitter.com/shane_ditton)
[![Follow on Twitter](https://img.shields.io/twitter/follow/dhauenstein.svg?logo=twitter)](https://twitter.com/dhauenstein)
[![Follow on Twitter](https://img.shields.io/twitter/follow/THB_STX.svg?logo=twitter)](https://twitter.com/THB_STX)
[![Email NanoDano](https://img.shields.io/badge/NanoDano-nanodano%40devdungeon.com-blue.svg)](mailto:nanodano@devdungeon.com)
[![Follow on Twitter](https://img.shields.io/twitter/follow/DanielMiessler.svg?logo=twitter)](https://twitter.com/DanielMiessler)
[![Follow on Twitter](https://img.shields.io/twitter/follow/ngkogkos.svg?logo=twitter)](https://github.com/ngkogkos)
[![Follow on Twitter](https://img.shields.io/twitter/follow/Jhaddix.svg?logo=twitter)](https://twitter.com/Jhaddix)
[![Follow on Twitter](https://img.shields.io/twitter/follow/Vltraheaven.svg?logo=twitter)](https://twitter.com/Vltraheaven)

## Mentions

[![Rawsec's CyberSecurity Inventory](https://inventory.rawsec.ml/img/badges/Rawsec-inventoried-FF5050_flat.svg)](https://inventory.rawsec.ml/)

* [Red Team Methodology - A Naked Look](https://www.slideshare.net/JasonLang1/red-team-methodology-a-naked-look-169879355)
* [Asset Enumeration: Expanding a Target's Attack Surface](https://captmeelo.com/bugbounty/2019/09/02/asset-enumeration.html)
* [Das Sicherheitswerkzeug Kali Linux steht in der Version 2019.3 bereit](https://www.heise.de/security/meldung/Das-Sicherheitswerkzeug-Kali-Linux-steht-in-der-Version-2019-3-bereit-4512459.html)
* [Commando VM 2.0: Customization, Containers, and Kali, Oh My!](https://www.fireeye.com/blog/threat-research/2019/08/commando-vm-customization-containers-kali.html)
* [8 Free Tools to Be Showcased at Black Hat and DEF CON](https://www.darkreading.com/application-security/8-free-tools-to-be-showcased-at-black-hat-and-def-con/d/d-id/1335356?image_number=5)
* [amass — Automated Attack Surface Mapping](https://danielmiessler.com/study/amass/)
* [Aquatone — A Tool for Domain Flyovers](https://github.com/michenriksen/aquatone)
* [Collaborating with the Crowd – Recapping LevelUp 0X04](https://www.bugcrowd.com/blog/recapping_levelup_0x04/)
* [Subdomain Enumeration: 2019 Workflow](https://0xpatrik.com/subdomain-enumeration-2019/)
* [REMOTE CODE EXECUTION ! 😜 Recon Wins](https://medium.com/@vishnu0002/remote-code-execution-recon-wins-e9c1db79f3da)
* [Where You’ll Find Us: An Overview of SecurityTrails Integrations](https://securitytrails.com/blog/integrations-overview)
* [Web tools, or where to start a pentester?](https://habr.com/en/company/dsec/blog/452836/)
* [Tool for detailed DNS enumeration and creation of network infrastructure maps](https://www.gurudelainformatica.es/2019/05/herramienta-para-enumeracion-detallada.html)
* [Top 7 Subdomain Scanner Tools: Find Subdomains in Seconds](https://securitytrails.com/blog/subdomain-scanner-find-subdomains)
* [Cyber Talent Gap: How to Do More With Less](https://www.digitalshadows.com/blog-and-research/cyber-talent-gap-how-to-do-more-with-less/)
* [My Recon Process — DNS Enumeration](https://medium.com/@noobhax/my-recon-process-dns-enumeration-d0e288f81a8a)
* [Week in OSINT #2019–16: From OSINT for pentesting, to OCR and OWASP](https://medium.com/week-in-osint/week-in-osint-2019-16-8ccfe0da1a70)
* [Stop Using Python for Subdomain Enumeration](http://sec.alexflor.es/post/subdomain_enum/)
* [My Personal OSINT Techniques, Part 1 of 2: Key & Layer, Contingency Seeding](https://0x00sec.org/t/my-personal-osint-techniques-part-1-of-2-key-layer-contingency-seeding/)
* [Subdomain Enumeration Tools – 2019 Update](https://www.yeahhub.com/subdomain-enumeration-tools-2019-update/)
* [Leaked Salesforce API access token at IDEA.com](https://medium.com/@jonathanbouman/leaked-salesforce-api-access-token-at-ikea-com-132eea3844e0)
* [Week in OSINT #2019–11: This time a collection of mostly tools and sites](https://medium.com/week-in-osint/week-in-osint-2019-11-62774ffe7a2)
* [Bug Hunting Methodology (part-1)](https://blog.usejournal.com/bug-hunting-methodology-part-1-91295b2d2066)
* [100 ways to discover (part 1)](https://sylarsec.com/2019/01/11/100-ways-to-discover-part-1/)
* [Pose a Threat: How Perceptual Analysis Helps Bug Hunters](https://www.bishopfox.com/news/2018/12/appsec-california-pose-a-threat-how-perpetual-analysis-helps-bug-hunters/)
* [A penetration tester’s guide to subdomain enumeration](https://blog.appsecco.com/a-penetration-testers-guide-to-sub-domain-enumeration-7d842d5570f6)
* [Abusing access control on a large online e-commerce site to register as supplier](https://medium.com/@fbotes2/governit-754becf85cbc)
* [Black Hat Training, Making the Cloud Rain Shells!: Discovery and Recon](https://www.blackhat.com/eu-18/training/schedule/index.html#aws--azure-exploitation-making-the-cloud-rain-shells-11060)
* [Subdomains Enumeration Cheat Sheet](https://pentester.land/cheatsheets/2018/11/14/subdomains-enumeration-cheatsheet.html)
* [Search subdomains and build graphs of network structure with Amass](https://miloserdov.org/?p=2309)
* [Getting started in Bug Bounty](https://medium.com/@ehsahil/getting-started-in-bug-bounty-7052da28445a)
* [Source code disclosure via exposed .git folder](https://pentester.land/tutorials/2018/10/25/source-code-disclosure-via-exposed-git-folder.html)
* [Amass, the best application to search for subdomains](https://www.h1rd.com/hacking/amass-para-buscar-subdominios)
* [Subdomain Takeover: Finding Candidates](https://0xpatrik.com/subdomain-takeover-candidates/)
* [Paul's Security Weekly #564: Technical Segment - Bug Bounty Hunting](https://wiki.securityweekly.com/Episode564)
* [The Bug Hunters Methodology v3(ish)](https://www.youtube.com/watch?v=Qw1nNPiH_Go)
* [Doing Recon the Correct Way](https://enciphers.com/doing-recon-the-correct-way/)
* [Discovering subdomains](https://www.sjoerdlangkemper.nl/2018/06/20/discovering-subdomains/)
* [Asset Discovery: Doing Reconnaissance the Hard Way](https://0xpatrik.com/asset-discovery/)
* [Project Sonar: An Underrated Source of Internet-wide Data](https://0xpatrik.com/project-sonar-guide/)
* [Top Five Ways the Red Team breached the External Perimeter](https://medium.com/@adam.toscher/top-five-ways-the-red-team-breached-the-external-perimeter-262f99dc9d17)

## Stargazers over Time

 [![Stargazers over Time](https://starcharts.herokuapp.com/OWASP/Amass.svg)](https://starcharts.herokuapp.com/OWASP/Amass)
