
# [![OWASP Logo](./images/owasp_logo.png) OWASP Amass](https://owasp.org/www-project-amass/)

[![CircleCI Status](https://circleci.com/gh/OWASP/Amass/tree/master.svg?style=shield)](https://circleci.com/gh/OWASP/Amass/tree/master)
[![GitHub release](https://img.shields.io/github/release/OWASP/Amass)](https://github.com/OWASP/Amass/releases)
[![Go Version](https://img.shields.io/badge/go-1.14-blue.svg)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

[![Bugcrowd LevelUp 0x04](https://img.shields.io/badge/Bugcrowd-LevelUp%200x04-orange.svg)](https://www.youtube.com/watch?v=C-GabM2db9A)
[![DEF CON 27 Demo Labs](https://img.shields.io/badge/DEF%20CON%2027-Demo%20Labs-purple.svg)](https://www.defcon.org/html/defcon-27/dc-27-demolabs.html)
[![DEF CON 27 Recon Village](https://img.shields.io/badge/DEF%20CON%2027-Recon%20Village-red.svg)](https://reconvillage.org/)

----

<p align="center">
  <img alt="DNS Enumeration" src="./images/amass.gif" width="577" height="685" />
</p>

----

The OWASP Amass Project has developed a tool to help information security professionals perform network mapping of attack surfaces and perform external asset discovery using open source information gathering and active reconnaissance techniques.

**Information Gathering Techniques Used:**

* **DNS:** Basic enumeration, Brute forcing (optional), Reverse DNS sweeping, Subdomain name alterations/permutations, Zone transfers (optional)
* **Scraping:** Ask, Baidu, Bing, DNSDumpster, DNSTable, Dogpile, Exalead, Google, HackerOne, IPv4Info, Netcraft, PTRArchive, Riddler, SiteDossier, ViewDNS, Yahoo
* **Certificates:** Active pulls (optional), Censys, CertSpotter, Crtsh, Entrust, GoogleCT
* **APIs:** AlienVault, BinaryEdge, BufferOver, CIRCL, CommonCrawl, DNSDB, GitHub, HackerTarget, IPToASN, Mnemonic, NetworksDB, PassiveTotal, Pastebin, RADb, Robtex, SecurityTrails, ShadowServer, Shodan, Spyse (CertDB & FindSubdomains), Sublist3rAPI, TeamCymru, ThreatCrowd, Twitter, Umbrella, URLScan, VirusTotal, WhoisXML
* **Web Archives:** ArchiveIt, ArchiveToday, Arquivo, LoCArchive, OpenUKArchive, UKGovArchive, Wayback

----

## Documentation

Use the [Installation Guide](./doc/install.md) to get started.

Go to the [User's Guide](./doc/user_guide.md) for additional information.

See the [Tutorial](./doc/tutorial.md) for example usage.

## Community

[![Contribute Yes](https://img.shields.io/badge/contribute-yes-brightgreen.svg)](./CONTRIBUTING.md)
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

## Top Mentions

* [SANS ISC: Offensive Tools Are For Blue Teams Too](https://isc.sans.edu/forums/diary/Offensive+Tools+Are+For+Blue+Teams+Too/25842/)
* [How to Use OWASP Amass: An Extensive Tutorial](https://www.dionach.com/blog/how-to-use-owasp-amass-an-extensive-tutorial/)
* [10 Recon Tools For Bug Bounty](https://medium.com/@hackbotone/10-recon-tools-for-bug-bounty-bafa8a5961bd)
* [Bug Bounty Tips: Amass Recon Tool](https://www.youtube.com/watch?v=QRkKzYH4efI)
* [OWASP Amass OSINT Reconnaissance](https://medium.com/hacker-toolbelt/owasp-amass-osint-reconnaissance-9b57d81fb958)
* [Top Linux Distros for Ethical Hacking and Penetration Testing](https://securitytrails.com/blog/top-linux-distributions-ethical-hacking-pentesting)
* [Asset Enumeration: Expanding a Target's Attack Surface](https://captmeelo.com/bugbounty/2019/09/02/asset-enumeration.html)
* [Commando VM 2.0: Customization, Containers, and Kali, Oh My!](https://www.fireeye.com/blog/threat-research/2019/08/commando-vm-customization-containers-kali.html)
* [amass — Automated Attack Surface Mapping](https://danielmiessler.com/study/amass/)
* [My Recon Process — DNS Enumeration](https://medium.com/@noobhax/my-recon-process-dns-enumeration-d0e288f81a8a)
* [Search subdomains and build graphs of network structure with Amass](https://miloserdov.org/?p=2309)
* [The Bug Hunters Methodology v3(ish)](https://www.youtube.com/watch?v=Qw1nNPiH_Go)
