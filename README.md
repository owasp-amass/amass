# [![OWASP Logo](./images/owasp_logo.png) OWASP Amass](https://owasp.org/www-project-amass/)

<p align="center">
  <img src="https://github.com/owasp-amass/amass/blob/master/images/amass_video.gif">
</p>

[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-48A646.svg)](https://owasp.org/projects/#sec-flagships)
[![GitHub Release](https://img.shields.io/github/release/owasp-amass/amass)](https://github.com/owasp-amass/amass/releases/latest)
[![Docker Images](https://img.shields.io/docker/pulls/caffix/amass.svg)](https://hub.docker.com/r/caffix/amass)
[![Follow on Twitter](https://img.shields.io/twitter/follow/owaspamass.svg?logo=twitter)](https://twitter.com/owaspamass)
[![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/HNePVyX3cp)

![GitHub Test Status](https://github.com/owasp-amass/amass/workflows/tests/badge.svg)
[![GoDoc](https://pkg.go.dev/badge/github.com/owasp-amass/amass/v4?utm_source=godoc)](https://pkg.go.dev/github.com/owasp-amass/amass/v4)
[![License](https://img.shields.io/badge/license-apache%202-blue)](https://www.apache.org/licenses/LICENSE-2.0)
[![Go Report](https://goreportcard.com/badge/github.com/owasp-amass/amass)](https://goreportcard.com/report/github.com/owasp-amass/amass)
[![CodeFactor](https://www.codefactor.io/repository/github/owasp-amass/amass/badge)](https://www.codefactor.io/repository/github/owasp-amass/amass)
[![Maintainability](https://api.codeclimate.com/v1/badges/234e4885e406953f91d0/maintainability)](https://codeclimate.com/github/owasp-amass/amass/maintainability)
[![codecov](https://codecov.io/gh/owasp-amass/amass/branch/master/graph/badge.svg?token=zoPKxvLT1n)](https://codecov.io/gh/owasp-amass/amass)

The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.

**Information Gathering Techniques Used:**

| Technique    | Data Sources |
|:-------------|:-------------|
| APIs         | 360PassiveDNS, Ahrefs, AnubisDB, BeVigil, BinaryEdge, BufferOver, BuiltWith, C99, Chaos, CIRCL, DNSDB, DNSRepo, Deepinfo, Detectify, FOFA, FullHunt, GitHub, GitLab, GrepApp, Greynoise, HackerTarget, Hunter, IntelX, LeakIX, Maltiverse, Mnemonic, Netlas, Pastebin, PassiveTotal, PentestTools, Pulsedive, Quake, SOCRadar, Searchcode, Shodan, Spamhaus, Sublist3rAPI, ThreatBook, ThreatMiner, URLScan, VirusTotal, Yandex, ZETAlytics, ZoomEye |
| Certificates | Active pulls (optional), Censys, CertCentral, CertSpotter, Crtsh, Digitorus, FacebookCT |
| DNS          | Brute forcing, Reverse DNS sweeping, NSEC zone walking, Zone transfers, FQDN alterations/permutations, FQDN Similarity-based Guessing |
| Routing      | ASNLookup, BGPTools, BGPView, BigDataCloud, IPdata, IPinfo, RADb, Robtex, ShadowServer, TeamCymru |
| Scraping     | AbuseIPDB, Ask, Baidu, Bing, CSP Header, DNSDumpster, DNSHistory, DNSSpy, DuckDuckGo, Gists, Google, HackerOne, HyperStat, PKey, RapidDNS, Riddler, Searx, SiteDossier, Yahoo |
| Web Archives | Arquivo, CommonCrawl, HAW, PublicWWW, UKWebArchive, Wayback |
| WHOIS        | AlienVault, AskDNS, DNSlytics, ONYPHE, SecurityTrails, SpyOnWeb, WhoisXMLAPI |

----

## Installation [![Go Version](https://img.shields.io/github/go-mod/go-version/owasp-amass/amass)](https://golang.org/dl/) [![Docker Images](https://img.shields.io/docker/pulls/caffix/amass.svg)](https://hub.docker.com/r/caffix/amass) [![GitHub Downloads](https://img.shields.io/github/downloads/owasp-amass/amass/latest/total.svg)](https://github.com/owasp-amass/amass/releases/latest)

> You can find some additional installation variations in the [Installation Guide](./doc/install.md).

### Prebuilt Packages

1. Simply unzip the [package](https://github.com/owasp-amass/amass/releases/latest)
2. Put the precompiled binary into your path
3. Start using OWASP Amass!

#### Homebrew

```bash
brew tap owasp-amass/amass
brew install amass
```

### Docker Container

1. Install [Docker](https://www.docker.com)
2. Pull the Docker image by running `docker pull caffix/amass`
3. Run `docker run -v OUTPUT_DIR_PATH:/.config/amass/ caffix/amass enum -d example.com`

The volume argument allows the Amass graph database to persist between executions and output files to be accessed on the host system. The first field (left of the colon) of the volume option is the amass output directory that is external to Docker, while the second field is the path, internal to Docker, where amass will write the output files.

### From Source

1. Install [Go](https://golang.org/doc/install) and setup your Go workspace
2. Download OWASP Amass by running `go install -v github.com/owasp-amass/amass/v4/...@master`
3. At this point, the binary should be in `$GOPATH/bin`

## Documentation [![GoDoc](https://pkg.go.dev/badge/github.com/owasp-amass/amass/v4?utm_source=godoc)](https://pkg.go.dev/github.com/owasp-amass/amass/v4)

Use the [Installation Guide](./doc/install.md) to get started.

Go to the [User's Guide](./doc/user_guide.md) for additional information.

See the [Tutorial](./doc/tutorial.md) for example usage.

See the [Amass Scripting Engine Manual](./doc/scripting.md) for greater control over your enumeration process.

## Troubleshooting [![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/HNePVyX3cp)

If you need help with installation and/or usage of the tool, please join our [Discord server](https://discord.gg/HNePVyX3cp) where community members can best help you.

:stop_sign:   **Please avoid opening GitHub issues for support requests or questions!**

## Contributing [![Contribute Yes](https://img.shields.io/badge/contribute-yes-brightgreen.svg)](./CONTRIBUTING.md) [![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/HNePVyX3cp)

We are always happy to get new contributors on board! Please check [CONTRIBUTING.md](CONTRIBUTING.md) to learn how to
contribute to our codebase, and join our [Discord Server](https://discord.gg/HNePVyX3cp) to discuss current project goals.

## Testimonials

### [![Accenture Logo](./images/accenture_logo.png) Accenture](https://www.accenture.com/)

*"Accenture’s adversary simulation team has used Amass as our primary tool suite on a variety of external enumeration projects and attack surface assessments for clients. It’s been an absolutely invaluable basis for infrastructure enumeration, and we’re really grateful for all the hard work that’s gone into making and maintaining it – it’s made our job much easier!"*

\- Max Deighton, Accenture Cyber Defense Manager

### [![Visma Logo](./images/visma_logo.png) Visma](https://www.visma.com/)

*"For an internal red team, the organisational structure of Visma puts us against a unique challenge. Having sufficient, continuous visibility over our external attack surface is an integral part of being able to efficiently carry out our task. When dealing with hundreds of companies with different products and supporting infrastructure we need to always be on top of our game.*

*For years, OWASP Amass has been a staple in the asset reconnaissance field, and keeps proving its worth time after time. The tool keeps constantly evolving and improving to adapt to the new trends in this area."*

\- Joona Hoikkala ([@joohoi](https://github.com/joohoi)) & Alexis Fernández ([@six2dez](https://github.com/six2dez)), Visma Red Team

## References [![DEF CON 30 Recon Village](https://img.shields.io/badge/defcon%2030-recon%20village-lightgrey.svg)](https://twitter.com/jeff_foley/status/1562246069278445568/photo/1) [![DEF CON 28 Red Team Village](https://img.shields.io/badge/defcon%2028-red%20team%20village-red.svg)](https://www.youtube.com/c/RedTeamVillage/featured) [![DEF CON 27 Demo Labs](https://img.shields.io/badge/defcon%2027-demo%20labs-purple.svg)](https://www.defcon.org/html/defcon-27/dc-27-demolabs.html) 

Did you write a blog post, magazine article or do a podcast about OWASP Amass? Or maybe you held or joined a conference talk or meetup session, a hacking workshop or public training where this project was mentioned?

Add it to our ever-growing list of [REFERENCES.md](REFERENCES.md) by forking and opening a Pull Request!

### Top Mentions

* [Phillip Wylie | Securing APIs Through External Attack Surface Management (EASM)](https://www.uscybersecurity.net/csmag/securing-apis-through-external-attack-surface-management-easm/)
* [Kento Stewart | Mapping Your External Perimeter during an Incident with OWASP Amass](https://www.youtube.com/watch?v=23tQ4zLA-9A)
* [WhoisXML API | OWASP Amass and WhoisXML API Are Now Integration Partners](https://main.whoisxmlapi.com/success-stories/cyber-security-solutions/owasp-amass-and-whoisxml-api-are-now-integration-partners)
* [Intigriti | Hacker tools: Amass – Hunting for Subdomains](https://blog.intigriti.com/2021/06/08/hacker-tools-amass-hunting-for-subdomains)
* [Hakluke | Guide to Amass — How to Use Amass More Effectively for Bug Bounties](https://medium.com/@hakluke/haklukes-guide-to-amass-how-to-use-amass-more-effectively-for-bug-bounties-7c37570b83f7)
* [SecurityTrails | OWASP Amass: A Solid Information Gathering Tool](https://securitytrails.com/blog/owasp-amass)
* [TrustedSec | Upgrade Your Workflow, Part 1: Building OSINT Checklists](https://www.trustedsec.com/blog/upgrade-your-workflow-part-1-building-osint-checklists/)
* [SANS ISC | Offensive Tools Are For Blue Teams Too](https://isc.sans.edu/forums/diary/Offensive+Tools+Are+For+Blue+Teams+Too/25842/)
* [Jason Haddix | LevelUp 0x02 - The Bug Hunters Methodology v3(ish)](https://www.youtube.com/watch?v=Qw1nNPiH_Go)
* [Daniel Miessler | amass — Automated Attack Surface Mapping](https://danielmiessler.com/study/amass/)
* [Dionach | How to Use OWASP Amass: An Extensive Tutorial](https://www.dionach.com/blog/how-to-use-owasp-amass-an-extensive-tutorial/)
* [nynan | How to **Actually** Use Amass More Effectively — Bug Bounty](https://medium.com/@nynan/how-to-actually-use-amass-more-effectively-bug-bounty-59e83900de02)
* [ToolWar | Extreme Subdomain Enumeration/Scanning on Windows : OWASP Amass](https://www.youtube.com/watch?v=mEQnVkSG19M)

## Licensing [![License](https://img.shields.io/badge/license-apache%202-blue)](https://www.apache.org/licenses/LICENSE-2.0)

This program is free software: you can redistribute it and/or modify it under the terms of the [Apache license](LICENSE). OWASP Amass and any contributions are Copyright © by Jeff Foley 2017-2023. Some subcomponents have separate licenses.

## Documentation

Use the [Installation Guide](https://github.com/4k4xs4pH1r3/Amass/blob/master/doc/install.md) to get started.

Go to the [User's Guide](https://github.com/OWASP/Amass/blob/master/doc/user_guide.md) for additional information.

## Community

Join our Discord server: [![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/rtN8GMd)

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
[![Follow on Twitter](https://img.shields.io/twitter/follow/sec_for_safety.svg?logo=twitter)](https://twitter.com/sec_for_safety)
[![Follow on Twitter](https://img.shields.io/twitter/follow/ngkogkos.svg?logo=twitter)](https://github.com/ngkogkos)
[![Follow on Twitter](https://img.shields.io/twitter/follow/Jhaddix.svg?logo=twitter)](https://twitter.com/Jhaddix)
[![Follow on Twitter](https://img.shields.io/twitter/follow/Vltraheaven.svg?logo=twitter)](https://twitter.com/Vltraheaven)

## Mentions

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

![Network graph](./images/network_06092018.png "Amass Network Mapping")

