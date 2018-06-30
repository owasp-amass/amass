# Amass 

[![GitHub release](https://img.shields.io/github/release/caffix/amass.svg)](https://github.com/caffix/amass/releases) [![GitHub issues](https://img.shields.io/github/issues/caffix/amass.svg)](https://github.com/caffix/amass/issues) [![Go Version](https://img.shields.io/badge/go-1.10-blue.svg)](https://golang.org/dl/) [![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0) [![Chat on Discord](https://img.shields.io/discord/433729817918308352.svg?logo=discord)](https://discord.gg/rtN8GMd) [![Follow on Twitter](https://img.shields.io/twitter/follow/jeff_foley.svg?style=social&logo=twitter)](https://twitter.com/jeff_foley)


```

                  .+++:.            :                             .+++.                   
                +W@@@@@@8        &+W@#               o8W8:      +W@@@@@@#.   oW@@@W#+     
               &@#+   .o@##.    .@@@o@W.o@@o       :@@#&W8o    .@#:  .:oW+  .@#+++&#&     
              +@&        &@&     #@8 +@W@&8@+     :@W.   +@8   +@:          .@8           
              8@          @@     8@o  8@8  WW    .@W      W@+  .@W.          o@#:         
              WW          &@o    &@:  o@+  o@+   #@.      8@o   +W@#+.        +W@8:       
              #@          :@W    &@+  &@+   @8  :@o       o@o     oW@@W+        oW@8      
              o@+          @@&   &@+  &@+   #@  &@.      .W@W       .+#@&         o@W.    
               WW         +@W@8. &@+  :&    o@+ #@      :@W&@&         &@:  ..     :@o    
               :@W:      o@# +Wo &@+        :W: +@W&o++o@W. &@&  8@#o+&@W.  #@:    o@+    
                :W@@WWWW@@8       +              :&W@@@@&    &W  .o#@@W&.   :W@WWW@@&     
                  +o&&&&+.                                                    +oooo.      


```


----

The Amass tool obtains subdomain names by scraping data sources, recursive brute forcing, crawling web archives, permuting and altering names, and reverse DNS sweeping. Additionally, Amass uses the IP addresses obtained during resolution to discover associated netblocks and ASNs. All the information is then used to build maps of the target networks.

----


![Image of a network graph](https://github.com/caffix/amass/blob/master/examples/network_06092018.png "Internet Satellite Imagery")


## How to Install

#### Prebuilt

A [precompiled version is available](https://github.com/caffix/amass/releases) for each release.

If your operating environment supports [Snap](https://docs.snapcraft.io/core/install), you can [click here to install](https://snapcraft.io/amass), or perform the following from the command-line:
```
$ sudo snap install amass
```


If you would like snap to get you the latest unstable build of amass, type the following command:
```
$ sudo snap install --edge amass
```
 

#### From Source

If you would prefer to build your own binary from the latest version of the source code, make sure you have a correctly configured **Go >= 1.10** environment. More information about how to achieve this can be found [on the golang website.](https://golang.org/doc/install) Then, take the following steps:

1. Download [amass](https://github.com/caffix/amass):
```
$ go get -u github.com/caffix/amass
```

At this point, the amass binary should be in *$GOPATH/bin*.


2. Several wordlists can be found in the following directory:
```
$ ls $GOPATH/src/github.com/caffix/amass/wordlists/
```


## Using the Tool

The most basic use of the tool, which includes reverse DNS lookups and name alterations:
```
$ amass -d example.com
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


Additional switches available through the amass CLI:

| Flag | Description | Example |
|------|-------------|---------|
| -active | Enable active recon methods | amass -active -d example.com net -p 80,443,8080 |
| -bl  | Blacklist undesired subdomains from the enumeration | amass -bl blah.example.com -d example.com |
| -blf | Identify blacklisted subdomains from a file | amass -blf data/blacklist.txt -d example.com |
| -brute | Perform brute force subdomain enumeration | amass -brute -d example.com |
| -df  | Specify the domains to be enumerated via text file | amass -df domains.txt |
| -freq | Throttle the rate of DNS queries by number per minute | amass -freq 120 -d example.com |
| -ip  | Print IP addresses with the discovered names | amass -ip -d example.com |
| -json | All discoveries written as individual JSON objects | amass -json out.json -d example.com |
| -l   | List all the domains to be used during enumeration | amass -whois -l -d example.com |
| -log | Log all error messages to a file | amass -log amass.log -d example.com |
| -min-for-recursive | Discoveries required for recursive brute forcing | amass -brute -min-for-recursive 3 -d example.com |
| -noalts | Disable alterations of discovered names | amass -noalts -d example.com |
| -nodns | A purely passive mode of execution | amass -nodns -d example.com |
| -norecursive | Disable recursive brute forcing | amass -brute -norecursive -d example.com |
| -o   | Write the results to a text file | amass -o out.txt -d example.com |
| -oA  | Output to all available file formats with prefix | amass -oA amass_scan -d example.com |
| -r   | Specify your own DNS resolvers | amass -r 8.8.8.8,1.1.1.1 -d example.com |
| -rf  | Specify DNS resolvers with a file | amass -rf data/resolvers.txt -d example.com |
| -w   | Change the wordlist used during brute forcing | amass -brute -w wordlist.txt -d example.com |
| -whois | Search using reverse whois information | amass -whois -d example.com |



Have amass send all the DNS and infrastructure enumerations to the Neo4j graph database:
```
$ amass -neo4j neo4j:DoNotUseThisPassword@localhost:7687 -d example.com
```


Here are switches for outputting the DNS and infrastructure findings as a network graph:

| Flag | Description | Example |
|------|-------------|---------|
| -d3  | Output a D3.js v4 force simulation HTML file | amass -d3 network.html -d example |
| -visjs | Output HTML that employs VisJS | amass -visjs network.html -d example.com |
| -graphistry | Output Graphistry JSON | amass -graphistry network.json -d example.com |
| -gephi | Output to Graph Exchange XML Format (GEXF) | amass -gephi network.gexf -d example.com |



#### Network/Infrastructure Options

**Caution:** If you use these options, amass will attempt to reach out to every IP address within the identified infrastructure and obtain names from TLS certificates. This is "loud" and can reveal your reconnaissance activities to the organization being investigated.

All the flags shown here require the 'net' subcommand to be specified **first**.

To discover all domains hosted within target ASNs, use the following option:
```
$ amass net -asn 13374,14618
```


To investigate within target CIDRs, use this option:
```
$ amass net -cidr 192.184.113.0/24,104.154.0.0/15
```


For specific IPs or address ranges, use this option:
```
$ amass net -addr 192.168.1.44,192.168.2.1-64
```


By default, port 443 will be checked for certificates, but the ports can be changed as follows:
```
$ amass net -cidr 192.168.1.0/24 -p 80,443,8080
```

## Integrating Amass into Your Work

If you are using the amass package within your own Go code, be sure to properly seed the default pseudo-random number generator:
```go
import(
    "fmt"
    "math/rand"
    "time"

    "github.com/caffix/amass/amass"
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
    config := amass.CustomConfig(&amass.AmassConfig{Output: output})
    config.AddDomains([]string{"example.com"})

    // Begin the enumeration process
    amass.StartEnumeration(config)
}
```


## Settings for the Amass Maltego Local Transform

1. Setup a new local transform within Maltego:

![Image of Maltego setup process](https://github.com/caffix/amass/blob/master/examples/maltegosetup1.png "Setup")


2. Configure the local transform to properly execute the go program:

![Image of Maltego configuration](https://github.com/caffix/amass/blob/master/examples/maltegosetup2.png "Configure")


3. Go into the Transform Manager, and disable the **debug info** option:

![Image of disabling debugging in Maltego](https://github.com/caffix/amass/blob/master/examples/maltegosetup3.png "Disable Debug")


## Community

 - [Discord Server](https://discord.gg/rtN8GMd) - Discussing OSINT, network recon and developing security tools using Go


## Mentions

 - [Discovering subdomains](https://www.sjoerdlangkemper.nl/2018/06/20/discovering-subdomains/)
 - [Best Hacking Tools List for Hackers & Security Professionals 2018](http://kalilinuxtutorials.com/best-hacking-tools-list/amp/)
 - [Amass - Subdomain Enumeration Tool](https://hydrasky.com/network-security/kali-tools/amass-subdomain-enumeration-tool/)
 - [Subdomain enumeration](http://10degres.net/subdomain-enumeration/)
 - [Asset Discovery: Doing Reconnaissance the Hard Way](https://0xpatrik.com/asset-discovery/)
 - [Go is for everyone](https://changelog.com/gotime/71)
 - [Top Five Ways the Red Team breached the External Perimeter](https://medium.com/@adam.toscher/top-five-ways-the-red-team-breached-the-external-perimeter-262f99dc9d17)


## Let Me Know What You Think

**NOTE: Still under development**

**Author: Jeff Foley @jeff_foley**

**Company: ClaritySec, Inc. / @claritysecinc**
