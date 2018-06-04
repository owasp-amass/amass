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

Amass is the subdomain enumeration tool with the greatest number of disparate data sources that performs analysis of the resolved names in order to deliver the largest number of quality results.

Amass performs scraping of data sources, recursive brute forcing, crawling of web archives, permuting and altering of names, reverse DNS sweeping, and machine learning to obtain additional subdomain names. The architecture makes it easy to add new subdomain enumeration techniques as they are developed.

DNS name resolution is performed across many public servers so the authoritative server will see traffic coming from different locations.

----


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


Add some additional domains to the enumeration:
```
$ amass -d example1.com,example2.com -d example3.com
```


You can also provide the initial domain names via an input file:
```
$ amass -df domains.txt
```


Get amass to provide the sources that discovered the subdomain names and print summary information:
```
$ amass -v -d example.com
[Google] www.example.com
[VirusTotal] ns.example.com
...
13242 names discovered - scrape: 211, dns: 4709, archive: 126, brute: 169, alt: 8027
```


Have amass print IP addresses with the discovered names:
```
$ amass -ip -d example.com
```


Have amass write the results to a text file:
```
$ amass -ip -o out.txt -d example.com
```


Have all the data collected written to a file as individual JSON objects:
```
$ amass -json out.txt -d example.com
```


Have amass send all the DNS and infrastructure enumerations to the Neo4j graph database:
```
$ amass -neo4j neo4j:DoNotUseThisPassword@localhost:7687 -d example.com
```


Specify your own DNS resolvers on the command-line or from a file:
```
$ amass -v -d example.com -r 8.8.8.8,1.1.1.1
```


The resolvers file can be provided using the following command-line switch:
```
$ amass -v -d example.com -rf data/resolvers.txt
```


If you would like to blacklist some subdomains:
```
$ amass -bl blah.example.com -d example.com
```


The blacklisted subdomains can be specified from a text file as well:
```
$ amass -blf data/blacklist.txt -d example.com
```


The amass feature that performs alterations on discovered names and attempt resolution can be disabled:
```
$ amass -noalts -d example.com
```


Use active information gathering techniques to attempt DNS zone transfers on all discovered authoritative name servers and obtain TLS/SSL certificates for discovered hosts on all specified ports:
```
$ amass -active -d example.com net -p 80,443,8080
```

Caution, this is an active technique that will reveal your IP address to the target organization.


Have amass perform brute force subdomain enumeration as well:
```
$ amass -brute -d example.com
```


By default, amass performs recursive brute forcing on new subdomains; this can be disabled:
```
$ amass -brute -norecursive -d example.com
```


If you would like to perform recursive brute forcing after enough discoveries have been made:
```
$ amass -brute -min-for-recursive 3 -d example.com
```


Change the wordlist used during the brute forcing phase of the enumeration:
```
$ amass -brute -w wordlist.txt -d example.com
```


Throttle the rate of DNS queries by number per minute:
```
$ amass -freq 120 -d example.com
```


Allow amass to include additional domains in the search using reverse whois information:
```
$ amass -whois -d example.com
```


You can have amass list all the domains discovered with reverse whois before performing the enumeration:
```
$ amass -whois -l -d example.com
```

Only the first domain provided is used while performing the reverse whois operation.


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
    output := make(chan *amass.AmassRequest)

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

![alt text](https://github.com/caffix/amass/blob/master/examples/maltegosetup1.png "Setup")


2. Configure the local transform to properly execute the go program:

![alt text](https://github.com/caffix/amass/blob/master/examples/maltegosetup2.png "Configure")


3. Go into the Transform Manager, and disable the **debug info** option:

![alt text](https://github.com/caffix/amass/blob/master/examples/maltegosetup3.png "Disable Debug")


## Community

 - [Discord Server](https://discord.gg/rtN8GMd) - Discussing OSINT, network recon and developing security tools using Go


## Mentions

 - [Subdomain enumeration](http://10degres.net/subdomain-enumeration/)
 - [Asset Discovery: Doing Reconnaissance the Hard Way](https://0xpatrik.com/asset-discovery/)
 - [Subdomain Enumeration Tool: Amass](https://n0where.net/subdomain-enumeration-tool-amass)
 - [Go is for everyone](https://changelog.com/gotime/71)
 - [Top Five Ways the Red Team breached the External Perimeter](https://medium.com/@adam.toscher/top-five-ways-the-red-team-breached-the-external-perimeter-262f99dc9d17)


## Let Me Know What You Think

**NOTE: Still under development**

**Author: Jeff Foley @jeff_foley**

**Company: ClaritySec, Inc. / @claritysecinc**
