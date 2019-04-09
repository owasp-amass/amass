
# [![OWASP Logo](https://github.com/OWASP/Amass/blob/master/images/owasp_logo.png) OWASP Amass](https://www.owasp.org/index.php/OWASP_Amass_Project)

[![GitHub Issues](https://img.shields.io/github/issues/OWASP/Amass.svg)](https://github.com/OWASP/Amass/issues)
[![CircleCI Status](https://circleci.com/gh/OWASP/Amass/tree/master.svg?style=shield)](https://circleci.com/gh/OWASP/Amass/tree/master)
[![GitHub tag](https://img.shields.io/github/tag/OWASP/Amass.svg)](https://github.com/OWASP/Amass/tags)
[![Go Version](https://img.shields.io/badge/go-1.10-blue.svg)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Contribute Yes](https://img.shields.io/badge/contribute-yes-brightgreen.svg)](https://github.com/OWASP/Amass/blob/master/CONTRIBUTING.md)
[![Chat](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/rtN8GMd)

[![Packaging status](https://repology.org/badge/vertical-allrepos/amass.svg)](https://repology.org/metapackage/amass/versions)
[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-white.svg)](https://snapcraft.io/amass)

----

<p align="center">
  <img alt="DNS Enumeration" src="https://github.com/OWASP/Amass/blob/master/images/amass.gif" width="577" height="685" />
</p>

----

The OWASP Amass tool suite obtains subdomain names by scraping data sources, recursive brute forcing, crawling web archives, permuting/altering names and reverse DNS sweeping. Additionally, Amass uses the IP addresses obtained during resolution to discover associated netblocks and ASNs. All the information is then used to build maps of the target networks.

**Information Gathering Techniques Used:**

* **DNS:** Basic enumeration, Brute forcing (upon request), Reverse DNS sweeping, Subdomain name alterations/permutations, Zone transfers (upon request)
* **Scraping:** Ask, Baidu, Bing, CommonCrawl, DNSDB, DNSDumpster, DNSTable, Dogpile, Exalead, FindSubdomains, Google, IPv4Info, Netcraft, PTRArchive, Riddler, SiteDossier, ThreatCrowd, VirusTotal, Yahoo
* **Certificates:** Active pulls (upon request), Censys, CertDB, CertSpotter, Crtsh, Entrust
* **APIs:** BinaryEdge, BufferOver, CIRCL, HackerTarget, PassiveTotal, Robtex, SecurityTrails, Shodan, Twitter, Umbrella, URLScan
* **Web Archives:** ArchiveIt, ArchiveToday, Arquivo, LoCArchive, OpenUKArchive, UKGovArchive, Wayback

----

## How to Install

### Prebuilt

A [precompiled version is available](https://github.com/OWASP/Amass/releases) for each release.

If your operating environment supports [Snap](https://docs.snapcraft.io/core/install), you can [click here to install](https://snapcraft.io/amass), or perform the following from the command-line:

```bash
sudo snap install amass
```

On Kali, follow these steps to install Snap and Amass + use AppArmor (for autoload):

```bash
sudo apt install snapd
sudo systemctl start snapd
sudo systemctl enable snapd
sudo systemctl start apparmor
sudo systemctl enable apparmor
```

Add the Snap bin directory to your PATH:

```bash
export PATH=$PATH:/snap/bin
```

Periodically, execute the following command to update all your snap packages:

```bash
sudo snap refresh
```

### Using Docker

1. Build the [Docker](https://docs.docker.com/) image:

```bash
sudo docker build -t amass https://github.com/OWASP/Amass.git
```

2. Run the Docker image:

```bash
sudo docker run amass --passive -d example.com
```

The wordlists maintained in the Amass git repository are available in `/wordlists/` within the docker container. For example, to use `all.txt`:

```bash
sudo docker run amass -w /wordlists/all.txt -d example.com
```

### From Source

If you prefer to build your own binary from the latest release of the source code, make sure you have a correctly configured **Go >= 1.10** environment. More information about how to achieve this can be found [on the golang website.](https://golang.org/doc/install) Then, take the following steps:

1. Download OWASP Amass:

```bash
go get -u github.com/OWASP/Amass/...
```

2. If you wish to rebuild the binaries from the source code:

```bash
cd $GOPATH/src/github.com/OWASP/Amass

go install ./...
```

At this point, the binaries should be in *$GOPATH/bin*.

3. Several wordlists can be found in the following directory:

```bash
ls $GOPATH/src/github.com/OWASP/Amass/wordlists/
```

## Documentation

Go to the [User's Guide](https://github.com/OWASP/Amass/blob/master/doc/user_guide.md) for additional information.

## Community

Join our Discord server: [![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/rtN8GMd)

### Project Lead

[![Follow on Twitter](https://img.shields.io/twitter/follow/jeff_foley.svg?logo=twitter)](https://twitter.com/jeff_foley)

* OWASP: [Caffix](https://www.owasp.org/index.php/User:Caffix)
* GitHub: [@caffix](https://github.com/caffix)

### Contributors

This project improves thanks to all the people who contribute:

[![Follow on Twitter](https://img.shields.io/twitter/follow/emtunc.svg?logo=twitter)](https://twitter.com/emtunc)
[![Follow on Twitter](https://img.shields.io/twitter/follow/kalbasit.svg?logo=twitter)](https://twitter.com/kalbasit)
[![Follow on Twitter](https://img.shields.io/twitter/follow/fork_while_fork.svg?logo=twitter)](https://twitter.com/fork_while_fork)
[![Follow on Twitter](https://img.shields.io/twitter/follow/rbadguy1.svg?logo=twitter)](https://twitter.com/rbadguy1)
[![Follow on Twitter](https://img.shields.io/twitter/follow/adam_zinger.svg?logo=twitter)](https://twitter.com/adam_zinger)
[![Follow on Twitter](https://img.shields.io/twitter/follow/architekton1.svg?logo=twitter)](https://twitter.com/architekton1)
[![Follow on Twitter](https://img.shields.io/twitter/follow/danjomart.svg?logo=twitter)](https://twitter.com/danjomart)
[![Follow on Twitter](https://img.shields.io/twitter/follow/_b3nj4m1n__.svg?logo=twitter)](https://twitter.com/_b3nj4m1n__)

## Mentions

* [Leaked Salesforce API access token at IDEA.com](https://medium.com/@jonathanbouman/leaked-salesforce-api-access-token-at-ikea-com-132eea3844e0)
* [Week in OSINT #2019–11: This time a collection of mostly tools and sites](https://medium.com/week-in-osint/week-in-osint-2019-11-62774ffe7a2)
* [Bug Hunting Methodology (part-1)](https://blog.usejournal.com/bug-hunting-methodology-part-1-91295b2d2066)
* [100 ways to discover (part 1)](https://sylarsec.com/2019/01/11/100-ways-to-discover-part-1/)
* [OWASP Amass – DNS Enumeration and Network Mapping](http://www.sectechno.com/owasp-amass-dns-enumeration-and-network-mapping/)
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
* [Best Hacking Tools List for Hackers & Security Professionals 2018](http://kalilinuxtutorials.com/best-hacking-tools-list/amp/)
* [Amass - Subdomain Enumeration Tool](https://hydrasky.com/network-security/kali-tools/amass-subdomain-enumeration-tool/)
* [Subdomain enumeration](http://10degres.net/subdomain-enumeration/)
* [Asset Discovery: Doing Reconnaissance the Hard Way](https://0xpatrik.com/asset-discovery/)
* [Project Sonar: An Underrated Source of Internet-wide Data](https://0xpatrik.com/project-sonar-guide/)
* [Go is for everyone](https://changelog.com/gotime/71)
* [Top Five Ways the Red Team breached the External Perimeter](https://medium.com/@adam.toscher/top-five-ways-the-red-team-breached-the-external-perimeter-262f99dc9d17)

## Stargazers over Time

 [![Stargazers over Time](https://starcharts.herokuapp.com/OWASP/Amass.svg)](https://starcharts.herokuapp.com/OWASP/Amass)
