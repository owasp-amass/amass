# [![OWASP Logo](./images/owasp_logo.png) OWASP Amass](https://owasp.org/www-project-amass/)

<p align="center">
  <img src="https://github.com/OWASP/Amass/blob/master/images/amass_video.gif">
</p>

[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-48A646.svg)](https://owasp.org/projects/#sec-flagships)
[![GitHub Release](https://img.shields.io/github/release/OWASP/Amass)](https://github.com/OWASP/Amass/releases)
[![GitHub Release Date](https://img.shields.io/github/release-date/OWASP/Amass)](https://github.com/OWASP/Amass/releases/latest)
[![Docker Images](https://img.shields.io/docker/pulls/caffix/amass.svg)](https://hub.docker.com/r/caffix/amass)
[![Follow on Twitter](https://img.shields.io/twitter/follow/owaspamass.svg?logo=twitter)](https://twitter.com/owaspamass)
[![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/rtN8GMd)

[![GoDoc](https://img.shields.io/static/v1?label=godoc&message=reference&color=blue)](https://pkg.go.dev/github.com/OWASP/Amass/v3?tab=overview)
[![License](https://img.shields.io/github/license/OWASP/Amass)](https://www.apache.org/licenses/LICENSE-2.0)
[![CircleCI Status](https://circleci.com/gh/OWASP/Amass/tree/master.svg?style=shield)](https://circleci.com/gh/OWASP/Amass/tree/master)
[![Go Report](https://goreportcard.com/badge/github.com/OWASP/Amass)](https://goreportcard.com/report/github.com/OWASP/Amass)
[![CodeFactor](https://www.codefactor.io/repository/github/OWASP/Amass/badge)](https://www.codefactor.io/repository/github/OWASP/Amass)
[![Maintainability](https://api.codeclimate.com/v1/badges/41c139f7cf5c23df1e58/maintainability)](https://codeclimate.com/github/OWASP/Amass/maintainability)
[![Codecov](https://codecov.io/gh/OWASP/Amass/branch/master/graph/badge.svg)](https://codecov.io/gh/OWASP/Amass)

The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.

**Information Gathering Techniques Used:**

| Technique    | Data Sources |
|:-------------|:-------------|
| DNS          | Brute forcing, Reverse DNS sweeping, NSEC zone walking, Zone transfers, FQDN alterations/permutations, FQDN Similarity-based Guessing |
| Scraping     | Ask, Baidu, Bing, BuiltWith, DNSDumpster, HackerOne, RapidDNS, Riddler, SiteDossier, ViewDNS, Yahoo |
| Certificates | Active pulls (optional), Censys, CertSpotter, Crtsh, FacebookCT, GoogleCT |
| APIs         | AlienVault, BinaryEdge, BufferOver, C99, CIRCL, Cloudflare, CommonCrawl, DNSDB, GitHub, HackerTarget, IPToASN, Mnemonic, NetworksDB, PassiveTotal, Pastebin, RADb, ReconDev, Robtex, SecurityTrails, ShadowServer, Shodan, Spyse, Sublist3rAPI, TeamCymru, ThreatCrowd, ThreatMiner, Twitter, Umbrella, URLScan, VirusTotal, WhoisXML, ZETAlytics, ZoomEye |
| Web Archives | ArchiveIt, LoCArchive, UKGovArchive, Wayback |

----

## Installation [![Go Version](https://img.shields.io/github/go-mod/go-version/OWASP/Amass)](https://golang.org/dl/) [![Docker Images](https://img.shields.io/docker/pulls/caffix/amass.svg)](https://hub.docker.com/r/caffix/amass) [![GitHub Downloads](https://img.shields.io/github/downloads/OWASP/Amass/latest/total.svg)](https://github.com/OWASP/Amass/releases/latest)

> You can find some additional installation variations in the [Installation Guide](./doc/install.md).

### Prebuilt Packages

1. Simply unzip the [package](https://github.com/OWASP/Amass/releases/latest)
2. Put the precompiled binary into your path
3. Start using OWASP Amass!

#### Homebrew

```bash
brew tap caffix/amass
brew install amass
```

#### Snapcraft

```bash
sudo snap install amass
```

### Docker Container

1. Install [Docker](https://www.docker.com)
2. Pull the Docker image by running `docker pull caffix/amass`
3. Run `docker run -v OUTPUT_DIR_PATH:/.config/amass/ caffix/amass --version`

The volume argument allows the Amass graph database to persist between executions and output files to be accessed on the host system. The first field (left of the colon) of the volume option is the amass output directory that is external to Docker, while the second field is the path, internal to Docker, where amass will write the output files.

The wordlists maintained in the Amass git repository are available in `/examples/wordlists/` within the docker container. For example, to use `all.txt`:

```bash
docker run -v OUTPUT_DIR_PATH:/.config/amass/ caffix/amass enum -brute -w /wordlists/all.txt -d example.com
```

### From Sources

1. Install [Go](https://golang.org/doc/install) and setup your Go workspace
2. Add the Go Module environment variable by running `export GO111MODULE=on`
3. Download OWASP Amass by running `go get -v github.com/OWASP/Amass/v3/...`
4. At this point, the binary should be in `$GOPATH/bin`

## Documentation [![GoDoc](https://img.shields.io/static/v1?label=godoc&message=reference&color=blue)](https://pkg.go.dev/github.com/OWASP/Amass/v3?tab=overview)

Use the [Installation Guide](./doc/install.md) to get started.

Go to the [User's Guide](./doc/user_guide.md) for additional information.

See the [Tutorial](./doc/tutorial.md) for example usage.

See the [Amass Scripting Engine Manual](./doc/scripting.md) for greater control over your enumeration process.

## Troubleshooting [![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/rtN8GMd)

If you need help with installation and/or usage of the tool, please join our [Discord server](https://discord.gg/rtN8GMd) where community members can best try to help you.

:stop_sign:   **Please avoid opening GitHub issues for support requests or questions!**

## Contributing [![Contribute Yes](https://img.shields.io/badge/contribute-yes-brightgreen.svg)](./CONTRIBUTING.md) [![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/rtN8GMd)

We are always happy to get new contributors on board! Please check [CONTRIBUTING.md](CONTRIBUTING.md) to learn how to
contribute to our codebase, and join our [Discord Server](https://discord.gg/rtN8GMd) to discuss current project goals.

The OWASP Amass core project team are:

* [Jeff Foley](https://github.com/caffix) aka `caffix`
  [![Follow on Twitter](https://img.shields.io/twitter/follow/jeff_foley.svg?logo=twitter)](https://twitter.com/jeff_foley)
* [Anthony Rhodes](https://github.com/fork-while-fork) aka `fork-while-fork`
  [![Follow on Twitter](https://img.shields.io/twitter/follow/fork_while_fork.svg?logo=twitter)](https://twitter.com/fork_while_fork)

For a list of all contributors to the OWASP Amass Project please visit our [HALL_OF_FAME.md](HALL_OF_FAME.md).

## References [![Bugcrowd LevelUp 0x04](https://img.shields.io/badge/bugcrowd-levelup%200x04-orange.svg)](https://www.youtube.com/watch?v=C-GabM2db9A) [![DEF CON 27 Demo Labs](https://img.shields.io/badge/defcon%2027-demo%20labs-purple.svg)](https://www.defcon.org/html/defcon-27/dc-27-demolabs.html) [![DEF CON 27 Recon Village](https://img.shields.io/badge/defcon%2027-recon%20village-lightgrey.svg)](https://reconvillage.org/) [![DEF CON 28 Red Team Village](https://img.shields.io/badge/defcon%2028-red%20team%20village-red.svg)](https://www.youtube.com/c/RedTeamVillage/featured) [![Bugcrowd LevelUp 0x07](https://img.shields.io/badge/bugcrowd-levelup%200x07-orange.svg)](https://www.twitch.tv/videos/723418873)

Did you write a blog post, magazine article or do a podcast about or mentioning OWASP Amass? Or maybe you held or joined a conference talk or meetup session, a hacking workshop or public training where this project was mentioned?

Add it to our ever-growing list of [REFERENCES.md](REFERENCES.md) by forking and opening a Pull Request!

### Top Mentions

* [Hakluke’s Guide to Amass — How to Use Amass More Effectively for Bug Bounties](https://medium.com/@hakluke/haklukes-guide-to-amass-how-to-use-amass-more-effectively-for-bug-bounties-7c37570b83f7)
* [SecurityTrails | OWASP Amass: A Solid Information Gathering Tool](https://securitytrails.com/blog/owasp-amass)
* [TrustedSec | Upgrade Your Workflow, Part 1: Building OSINT Checklists](https://www.trustedsec.com/blog/upgrade-your-workflow-part-1-building-osint-checklists/)
* [SANS ISC | Offensive Tools Are For Blue Teams Too](https://isc.sans.edu/forums/diary/Offensive+Tools+Are+For+Blue+Teams+Too/25842/)
* [Daniel Miessler | amass — Automated Attack Surface Mapping](https://danielmiessler.com/study/amass/)
* [Dionach | How to Use OWASP Amass: An Extensive Tutorial](https://www.dionach.com/blog/how-to-use-owasp-amass-an-extensive-tutorial/)
* [Jason Haddix | LevelUp 0x02 - The Bug Hunters Methodology v3(ish)](https://www.youtube.com/watch?v=Qw1nNPiH_Go)
* [FireEye | Commando VM 2.0: Customization, Containers, and Kali, Oh My!](https://www.fireeye.com/blog/threat-research/2019/08/commando-vm-customization-containers-kali.html)
* [Hacker Toolbelt | OWASP Amass OSINT Reconnaissance](https://medium.com/hacker-toolbelt/owasp-amass-osint-reconnaissance-9b57d81fb958)
* [ToolWar | Extreme Subdomain Enumeration/Scanning on Windows : OWASP Amass](https://www.youtube.com/watch?v=mEQnVkSG19M)
* [Ghost Lulz | YouTube - Bug Bounty Tips: Amass Recon Tool](https://www.youtube.com/watch?v=QRkKzYH4efI)
* [HackbotOne | 10 Recon Tools For Bug Bounty](https://hackbotone.com/blog/10-recon-tools-for-bug-bounty)
* [Capt. Meelo | Asset Enumeration: Expanding a Target's Attack Surface](https://captmeelo.com/bugbounty/2019/09/02/asset-enumeration.html)
* [Noobhax | My Recon Process — DNS Enumeration](https://medium.com/@noobhax/my-recon-process-dns-enumeration-d0e288f81a8a)

## Licensing [![License](https://img.shields.io/github/license/OWASP/Amass)](https://www.apache.org/licenses/LICENSE-2.0)

This program is free software: you can redistribute it and/or modify it under the terms of the [Apache license](LICENSE). OWASP Amass and any
contributions are Copyright © by Jeff Foley 2017-2020.

![Network graph](./images/network_06092018.png "Amass Network Mapping")
