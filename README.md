
# [![OWASP Logo](https://github.com/OWASP/Amass/blob/master/images/owasp_logo.png) OWASP Amass](https://www.owasp.org/index.php/OWASP_Amass_Project)

[![GitHub Issues](https://img.shields.io/github/issues/OWASP/Amass.svg)](https://github.com/OWASP/Amass/issues) 
[![CircleCI Status](https://circleci.com/gh/OWASP/Amass/tree/master.svg?style=shield)](https://circleci.com/gh/OWASP/Amass/tree/master)
[![GitHub Release](https://img.shields.io/github/release/OWASP/Amass.svg)](https://github.com/OWASP/Amass/releases) 
[![Go Version](https://img.shields.io/badge/go-1.10-blue.svg)](https://golang.org/dl/) 
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0) 
[![Contribute Yes](https://img.shields.io/badge/contribute-yes-brightgreen.svg)](https://github.com/OWASP/Amass/blob/master/CONTRIBUTING.md)
[![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/rtN8GMd) 
[![Follow on Twitter](https://img.shields.io/twitter/follow/jeff_foley.svg?logo=twitter)](https://twitter.com/jeff_foley)

----

The OWASP Amass tool obtains subdomain names by scraping data sources, recursive brute forcing, crawling web archives, permuting/altering names and reverse DNS sweeping. Additionally, Amass uses the IP addresses obtained during resolution to discover associated netblocks and ASNs. All the information is then used to build maps of the target networks.

----

![Network graph](https://github.com/OWASP/Amass/blob/master/images/network_06092018.png "Internet Satellite Imagery")

## How to Install

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

If you would like snap to get you the latest unstable build of OWASP Amass, type the following command:
```
$ sudo snap install --edge amass
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

## Using the Tool

The most basic use of the tool, which includes reverse DNS lookups and name alterations:
```
$ amass -d example.com
```

**If you need Amass to run faster** and only use the passive data sources:
```
$ amass --passive -d example.com
```

If you are running Amass within a virtual machine, you may want to slow it down a bit:
```
$ amass -freq 480 -d example.com
```

The example below is a good place to start with amass:
```
$ amass -v -ip -brute -min-for-recursive 3 -d example.com
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
| -d   | Provide a domain name to include in the enumeration | amass -d example.com |
| -df  | Specify the domains to be enumerated via text file | amass -df domains.txt |
| -do  | Write all the data operations to a JSON file | amass -do data.json -d example.com |
| -freq | Throttle the rate of DNS queries by number per minute | amass -freq 120 -d example.com |
| -h   | Show the amass usage information | amass -h |
| -ip  | Print IP addresses with the discovered names | amass -ip -d example.com |
| -json | All discoveries written as individual JSON objects | amass -json out.json -d example.com |
| -l   | List all the domains to be used during enumeration | amass -whois -l -d example.com |
| -log | Log all error messages to a file | amass -log amass.log -d example.com |
| -min-for-recursive | Number of subdomain names required for recursive brute forcing to begin | amass -brute -min-for-recursive 3 -d example.com |
| -noalts | Disable alterations of discovered names | amass -noalts -d example.com |
| -passive | A purely passive mode of execution | amass --passive -d example.com |
| -norecursive | Disable recursive brute forcing | amass -brute -norecursive -d example.com |
| -o   | Write the results to a text file | amass -o out.txt -d example.com |
| -oA  | Output to all available file formats with prefix | amass -oA amass_scan -d example.com |
| -r   | Specify your own DNS resolvers | amass -r 8.8.8.8,1.1.1.1 -d example.com |
| -rf  | Specify DNS resolvers with a file | amass -rf data/resolvers.txt -d example.com |
| -v   | Output includes data source and summary information | amass -v -d example.com |
| -version | Print the version number of amass | amass -version |
| -w   | Change the wordlist used during brute forcing | amass -brute -w wordlist.txt -d example.com |
| -whois | Search using reverse whois information | amass -whois -d example.com |


#### amass.netdomains

**Caution:** If you use the amass.netdomains tool, it will attempt to reach out to every IP address within the identified infrastructure and obtain domains names from reverse DNS requests and TLS certificates. This is "loud" and can reveal your reconnaissance activities to the organization being investigated.

Lookup ASNs by searching the descriptions registered by organizations:
```
$ amass.netdomains -org Facebook
32934, FACEBOOK - Facebook, Inc., US
54115, FACEBOOK-CORP - Facebook Inc, US
63293, FACEBOOK-OFFNET - Facebook, Inc., US
```

To discover all domains hosted within target ASNs, use the following option:
```
$ amass.netdomains -asn 13374,14618
```

To investigate target CIDRs, use this option:
```
$ amass.netdomains -cidr 192.184.113.0/24,104.154.0.0/15
```

For specific IPs or address ranges, use this option:
```
$ amass.netdomains -addr 192.168.1.44,192.168.2.1-64
```

By default, port 443 will be checked for certificates, but the ports can be changed as follows:
```
$ amass.netdomains -cidr 192.168.1.0/24 -p 80,443,8080
```

#### amass.viz

Create enlightening network graph visualizations that provide structure to the information you gather. This tool requires an input file generated by the amass '-do' flag.

Switches for outputting the DNS and infrastructure findings as a network graph:

| Flag | Description | Example |
|------|-------------|---------|
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
    output := make(chan *amass.AmassOutput)

    go func() {
        for result := range output {
            fmt.Println(result.Name)
        }
    }()
    // Seed the default pseudo-random number generator
    rand.Seed(time.Now().UTC().UnixNano())
    // Setup the most basic amass configuration
    enum := amass.NewEnumeration()
    enum.Output = output
    enum.AddDomain("example.com")
    enum.Start()
}
```

## Settings for the OWASP Amass Maltego Local Transform

1. Setup a new local transform within Maltego:

![Maltego setup process](https://github.com/OWASP/Amass/blob/master/images/maltegosetup1.png "Setup")

2. Configure the local transform to properly execute the go program:

![Maltego configuration](https://github.com/OWASP/Amass/blob/master/images/maltegosetup2.png "Configure")

3. Go into the Transform Manager, and disable the **debug info** option:

![Disabling debug](https://github.com/OWASP/Amass/blob/master/images/maltegosetup3.png "Disable Debug")

## Community

 - [Discord Server](https://discord.gg/rtN8GMd) - Discussing OSINT, network recon and developing security tools using Go

## Mentions

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

## Example Amass Terminal Capture 

Presented at Facebook (and shared publically) for the Sept. 2018 OWASP London Chapter meeting:

[![asciicast](https://asciinema.org/a/v6B1qdMRlLRUflpkwRPhvCTaY.png)](https://asciinema.org/a/v6B1qdMRlLRUflpkwRPhvCTaY)