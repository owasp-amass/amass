
# [![OWASP Logo](https://github.com/OWASP/Amass/blob/master/images/owasp_logo.png) OWASP Amass](https://www.owasp.org/index.php/OWASP_Amass_Project)

[![GitHub Issues](https://img.shields.io/github/issues/OWASP/Amass.svg)](https://github.com/OWASP/Amass/issues) 
[![CircleCI Status](https://circleci.com/gh/OWASP/Amass/tree/master.svg?style=shield)](https://circleci.com/gh/OWASP/Amass/tree/master)
[![GitHub tag](https://img.shields.io/github/tag/OWASP/Amass.svg)](https://github.com/OWASP/Amass/tags) 
[![Go Version](https://img.shields.io/badge/go-1.10-blue.svg)](https://golang.org/dl/) 
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0) 
[![Contribute Yes](https://img.shields.io/badge/contribute-yes-brightgreen.svg)](https://github.com/OWASP/Amass/blob/master/CONTRIBUTING.md) 
[![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/rtN8GMd) 


----

The OWASP Amass tool suite obtains subdomain names by scraping data sources, recursive brute forcing, crawling web archives, permuting/altering names and reverse DNS sweeping. Additionally, Amass uses the IP addresses obtained during resolution to discover associated netblocks and ASNs. All the information is then used to build maps of the target networks.

----

![Network graph](https://github.com/OWASP/Amass/blob/master/images/network_06092018.png "Amass Network Mapping")

## How to Install

[![Packaging status](https://repology.org/badge/vertical-allrepos/amass.svg)](https://repology.org/metapackage/amass/versions) 

#### Prebuilt

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

## Using the Tool Suite

The most basic use of the tool, which includes reverse DNS lookups and name alterations:
```
$ amass -d example.com
```

The example below is a good place to start with amass:
```
$ amass -src -ip -brute -min-for-recursive 3 -d example.com
[Google] www.example.com
[VirusTotal] ns.example.com
...
13139 names discovered - archive: 171, cert: 2671, scrape: 6290, brute: 991, dns: 250, alt: 2766
```

Add some additional domains to the enumeration:
```
$ amass -d example1.com,example2.com -d example3.com
```

Switches available through the amass CLI:

| Flag | Description | Example |
|------|-------------|---------|
| -active | Enable active recon methods | amass -active -d example.com net -p 80,443,8080 |
| -bl  | Blacklist undesired subdomains from the enumeration | amass -bl blah.example.com -d example.com |
| -blf | Identify blacklisted subdomains from a file | amass -blf data/blacklist.txt -d example.com |
| -brute | Perform brute force subdomain enumeration | amass -brute -d example.com |
| -config | Path to the INI configuration file | amass -config amass_settings.ini |
| -d   | Provide a domain name to include in the enumeration | amass -d example.com |
| -df  | Specify the domains to be enumerated via text file | amass -df domains.txt |
| -do  | Write all the data operations to a JSON file | amass -do data.json -d example.com |
| -ef  | Path to a file providing data sources to exclude | amass -ef exclude.txt -d example.com |
| -exclude | Data source names separated by commas to be excluded | amass -exclude crtsh -d example.com |
| -h   | Show the amass usage information | amass -h |
| -if  | Path to a file providing data sources to include | amass -if include.txt -d example.com |
| -include-unresolvable | Output DNS names that did not resolve | amass -include-unresolvable -d example.com |
| -include | Data source names separated by commas to be included | amass -include crtsh -d example.com |
| -ip  | Print IP addresses with the discovered names | amass -ip -d example.com |
| -json | All discoveries written as individual JSON objects | amass -json out.json -d example.com |
| -list | Print the names of all available data sources | amass -l |
| -log | Log all error messages to a file | amass -log amass.log -d example.com |
| -min-for-recursive | Number of subdomain names required for recursive brute forcing to begin | amass -brute -min-for-recursive 3 -d example.com |
| -noalts | Disable alterations of discovered names | amass -noalts -d example.com |
| -passive | A purely passive mode of execution | amass --passive -d example.com |
| -norecursive | Disable recursive brute forcing | amass -brute -norecursive -d example.com |
| -o   | Write the results to a text file | amass -o out.txt -d example.com |
| -oA  | Output to all available file formats with prefix | amass -oA amass_scan -d example.com |
| -r   | Specify your own DNS resolvers | amass -r 8.8.8.8,1.1.1.1 -d example.com |
| -rf  | Specify DNS resolvers with a file | amass -rf data/resolvers.txt -d example.com |
| -src | Print data sources for the discovered names | amass -src -d example.com |
| -T   | Timing templates 0 (slowest) through 5 (fastest) (default 3) | amass -T 5 -d example.com |
| -version | Print the version number of amass | amass -version |
| -w   | Change the wordlist used during brute forcing | amass -brute -w wordlist.txt -d example.com |

#### amass.netdomains

**Caution:** If you use the amass.netdomains tool, it will attempt to reach out to every IP address within the identified infrastructure and obtain domains names from reverse DNS requests and TLS certificates. This is "loud" and can reveal your reconnaissance activities to the organization being investigated.

| Flag | Description | Example |
|------|-------------|---------|
| -org | Search string provided against AS description information | amass.netdomains -org Facebook |
| -asn  | ASNs separated by commas (can be used multiple times) | amass.netdomains -asn 13374,14618 |
| -cidr | CIDRs separated by commas (can be used multiple times) | amass.netdomains -cidr 104.154.0.0/15 |
| -addr | IPs and ranges (192.168.1.1-254) separated by commas | amass.netdomains -addr 192.168.2.1-64 |
| -p | Ports separated by commas (default: 443) | amass.netdomains -cidr 104.154.0.0/15 -p 443,8080 |
| -whois | All discovered domains are run through reverse whois | amass.netdomains -whois -asn 13374 |

#### amass.viz

Create enlightening network graph visualizations that provide structure to the information you gather. This tool requires an input file generated by the amass '-do' flag.

Switches for outputting the DNS and infrastructure findings as a network graph:

| Flag | Description | Example |
|------|-------------|---------|
| -maltego | Output a Maltego Graph Table CSV file | amass.viz -maltego net.csv -i data_ops.json |
| -d3  | Output a D3.js v4 force simulation HTML file | amass.viz -d3 net.html -i data_ops.json |
| -gexf | Output to Graph Exchange XML Format (GEXF) | amass.viz -gephi net.gexf -i data_ops.json |
| -graphistry | Output Graphistry JSON | amass.viz -graphistry net.json -i data_ops.json |
| -visjs | Output HTML that employs VisJS | amass.viz -visjs net.html -i data_ops.json |


#### amass.db

Have amass send all the DNS and infrastructure information gathered to a graph database. This tool requires an input file generated by the amass '-do' flag.

```
$ amass.db -neo4j neo4j:DoNotUseThisPassword@localhost:7687 -i data_ops.json
```

## Integrating OWASP Amass into Your Work

If you are using the amass package within your own Go code, be sure to properly seed the default pseudo-random number generator:
```go
import(
    "fmt"
    "math/rand"
    "time"

    "github.com/OWASP/Amass/amass"
)

func main() {
    // Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	enum := amass.NewEnumeration()
	// Setup the most basic amass configuration
	enum.Config.AddDomain("example.com")
	
	go func() {
		for result := range enum.Output {
			fmt.Println(result.Name)
		}
	}()
	
	enum.Start()
}
```

## Importing OWASP Amass Results into Maltego

1. Output your Amass enumeration data using the '-do' flag:
```
$ amass -src -ip --active -brute -do owasp.json -d owasp.org
```

2. Convert the Amass data into a Maltego graph table CSV file:
```
$ amass.viz -i owasp.json --maltego owasp.csv
```

3. Import the CSV file with the correct Connectivity Table settings:

![Connectivity table](https://github.com/OWASP/Amass/blob/master/images/maltego_graph_import_wizard.png "Connectivity Table Settings")

4. All the Amass findings will be brought into your Maltego Graph:

![Maltego results](https://github.com/OWASP/Amass/blob/master/images/maltego_results.png "Maltego Results")

## Community

[![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/rtN8GMd) 

### Author

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

## Amass Terminal Capture 

Presented at Facebook (and shared publically) for the Sept. 2018 OWASP London Chapter meeting:

[![asciicast](https://asciinema.org/a/v6B1qdMRlLRUflpkwRPhvCTaY.png)](https://asciinema.org/a/v6B1qdMRlLRUflpkwRPhvCTaY)