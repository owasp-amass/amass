
# [![OWASP Logo](https://github.com/OWASP/Amass/blob/master/images/owasp_logo.png) OWASP Amass](https://www.owasp.org/index.php/OWASP_Amass_Project)

[![GitHub Issues](https://img.shields.io/github/issues/OWASP/Amass.svg)](https://github.com/OWASP/Amass/issues) 
[![CircleCI Status](https://circleci.com/gh/OWASP/Amass/tree/master.svg?style=shield)](https://circleci.com/gh/OWASP/Amass/tree/master)
[![GitHub tag](https://img.shields.io/github/tag/OWASP/Amass.svg)](https://github.com/OWASP/Amass/tags) 
[![Go Version](https://img.shields.io/badge/go-1.10-blue.svg)](https://golang.org/dl/) 
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0) 
[![Contribute Yes](https://img.shields.io/badge/contribute-yes-brightgreen.svg)](https://github.com/OWASP/Amass/blob/master/CONTRIBUTING.md) 
[![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/rtN8GMd) 


----


<p align="center">
  <img alt="DNS Enumeration" src="https://github.com/OWASP/Amass/blob/master/images/amass.gif" width="656" height="702" />
</p>


----

The OWASP Amass tool suite obtains subdomain names by scraping data sources, recursive brute forcing, crawling web archives, permuting/altering names and reverse DNS sweeping. Additionally, Amass uses the IP addresses obtained during resolution to discover associated netblocks and ASNs. All the information is then used to build maps of the target networks.

----


## How to Install


#### Prebuilt

[![Packaging status](https://repology.org/badge/vertical-allrepos/amass.svg)](https://repology.org/metapackage/amass/versions) 

A [precompiled version is available](https://github.com/OWASP/Amass/releases) for each release.

If you are on a distribution such as **Kali Linux**, and have never used snap previously, follow these steps to access snap packages:
```
$ sudo apt install snapd

$ sudo systemctl start snapd
```

Add the snap binaries to your PATH using a method similar to the following:
```
$ export PATH=$PATH:/snap/bin
```

If your operating environment supports [Snap](https://docs.snapcraft.io/core/install), you can [click here to install](https://snapcraft.io/amass), or perform the following from the command-line:
```
$ sudo snap install amass
```


Periodically, execute the following command to update all your snap packages:
```
$ sudo snap refresh
```

#### Using Docker

1. Build the [Docker](https://docs.docker.com/) image:
```
sudo docker build -t amass https://github.com/OWASP/Amass.git
```

2. Run the Docker image:
```
sudo docker run amass --passive -d example.com
```

#### From Source

If you would prefer to build your own binary from the latest version of the source code, make sure you have a correctly configured **Go >= 1.10** environment. More information about how to achieve this can be found [on the golang website.](https://golang.org/doc/install) Then, take the following steps:

1. Download [amass](https://github.com/OWASP/Amass/releases):
```
$ go get -u github.com/OWASP/Amass/...
```

2. If you wish to rebuild the binaries from the source code:
```
$ cd $GOPATH/src/github.com/OWASP/Amass

$ go install ./...
```

At this point, the binaries should be in *$GOPATH/bin*.

3. Several wordlists can be found in the following directory:
```
$ ls $GOPATH/src/github.com/OWASP/Amass/wordlists/
```

## Documentation

Go to the [User's Guide](https://github.com/OWASP/Amass/blob/master/doc/user_guide.md) for additional information.


## Community

[![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/rtN8GMd) 


### Project Lead

Jeff Foley [![Follow on Twitter](https://img.shields.io/twitter/follow/jeff_foley.svg?logo=twitter)](https://twitter.com/jeff_foley) 

 - OWASP: [Caffix](https://www.owasp.org/index.php/User:Caffix)
 - GitHub: [@caffix](https://github.com/caffix)


### Contributors

This project improves thanks to all the people who contribute:

[![Follow on Twitter](https://img.shields.io/twitter/follow/emtunc.svg?logo=twitter)](https://twitter.com/emtunc) 
[![Follow on Twitter](https://img.shields.io/twitter/follow/ylcodes.svg?logo=twitter)](https://twitter.com/ylcodes) 
[![Follow on Twitter](https://img.shields.io/twitter/follow/fork_while_fork.svg?logo=twitter)](https://twitter.com/fork_while_fork) 
[![Follow on Twitter](https://img.shields.io/twitter/follow/rbadguy1.svg?logo=twitter)](https://twitter.com/rbadguy1) 
[![Follow on Twitter](https://img.shields.io/twitter/follow/adam_zinger.svg?logo=twitter)](https://twitter.com/adam_zinger) 


## Mentions

 - [Black Hat Training, Making the Cloud Rain Shells!: Discovery and Recon](https://www.blackhat.com/eu-18/training/schedule/index.html#aws--azure-exploitation-making-the-cloud-rain-shells-11060)
 - [Subdomains Enumeration Cheat Sheet](https://pentester.land/cheatsheets/2018/11/14/subdomains-enumeration-cheatsheet.html)
 - [Getting started in Bug Bounty](https://medium.com/@ehsahil/getting-started-in-bug-bounty-7052da28445a)
 - [Source code disclosure via exposed .git folder](https://pentester.land/tutorials/2018/10/25/source-code-disclosure-via-exposed-git-folder.html)
 - [Amass, the best application to search for subdomains](https://www.h1rd.com/hacking/amass-para-buscar-subdominios)
 - [Subdomain Takeover: Finding Candidates](https://0xpatrik.com/subdomain-takeover-candidates/)
 - [Paul's Security Weekly #564: Technical Segment - Bug Bounty Hunting](https://wiki.securityweekly.com/Episode564)
 - [The Bug Hunters Methodology v3(ish)](https://www.youtube.com/watch?v=Qw1nNPiH_Go)
 - [Doing Recon the Correct Way](https://enciphers.com/doing-recon-the-correct-way/)
 - [Discovering subdomains](https://www.sjoerdlangkemper.nl/2018/06/20/discovering-subdomains/)
 - [Best Hacking Tools List for Hackers & Security Professionals 2018](http://kalilinuxtutorials.com/best-hacking-tools-list/amp/)
 - [Amass - Subdomain Enumeration Tool](https://hydrasky.com/network-security/kali-tools/amass-subdomain-enumeration-tool/)
 - [Subdomain enumeration](http://10degres.net/subdomain-enumeration/)
 - [Asset Discovery: Doing Reconnaissance the Hard Way](https://0xpatrik.com/asset-discovery/)
 - [Project Sonar: An Underrated Source of Internet-wide Data](https://0xpatrik.com/project-sonar-guide/)
 - [Go is for everyone](https://changelog.com/gotime/71)
 - [Top Five Ways the Red Team breached the External Perimeter](https://medium.com/@adam.toscher/top-five-ways-the-red-team-breached-the-external-perimeter-262f99dc9d17)


 ## Stargazers over Time

 [![Stargazers over Time](https://starcharts.herokuapp.com/OWASP/Amass.svg)](https://starcharts.herokuapp.com/OWASP/Amass)