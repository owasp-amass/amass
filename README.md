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
| APIs         | 360PassiveDNS, Ahrefs, AnubisDB, BeVigil, BinaryEdge, BufferOver, BuiltWith, C99, Chaos, CIRCL, DNSDB, DNSRepo, Deepinfo, Detectify, FOFA, FullHunt, GitHub, GitLab, GrepApp, Greynoise, HackerTarget, Hunter, IntelX, LeakIX, Maltiverse, Mnemonic, Netlas, Pastebin, PassiveTotal, PentestTools, Pulsedive, Quake, SOCRadar, Searchcode, Shodan, Spamhaus, Sublist3rAPI, SubdomainCenter, ThreatBook, ThreatMiner, URLScan, VirusTotal, Yandex, ZETAlytics, ZoomEye |
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

## Corporate Supporters

[![ZeroFox Logo](./images/zerofox_logo.png)](https://www.zerofox.com/) [![IPinfo Logo](./images/ipinfo_logo.png)](https://ipinfo.io/) [![WhoisXML API Logo](./images/whoisxmlapi_logo.png)](https://www.whoisxmlapi.com/)

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

## Contributing [![Contribute Yes](https://img.shields.io/badge/contribute-yes-brightgreen.svg)](./CONTRIBUTING.md) [![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/HNePVyX3cp)

We are always happy to get new contributors on board! Please check [CONTRIBUTING.md](CONTRIBUTING.md) to learn how to
contribute to our codebase, and join our [Discord Server](https://discord.gg/HNePVyX3cp) to discuss current project goals.

## Troubleshooting [![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/HNePVyX3cp)

If you need help with installation and/or usage of the tool, please join our [Discord server](https://discord.gg/HNePVyX3cp) where community members can best help you.

:stop_sign:   **Please avoid opening GitHub issues for support requests or questions!**

## Licensing [![License](https://img.shields.io/badge/license-apache%202-blue)](https://www.apache.org/licenses/LICENSE-2.0)

This program is free software: you can redistribute it and/or modify it under the terms of the [Apache license](LICENSE). OWASP Amass and any contributions are Copyright © by Jeff Foley 2017-2023. Some subcomponents have separate licenses.

![Network graph](./images/network_06092018.png "Amass Network Mapping")
