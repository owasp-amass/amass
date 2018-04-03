# Amass v1.3.0 - Jeff Foley (@jeff_foley)

### On the Smart and Quiet Side

[![](https://img.shields.io/badge/go-1.10-blue.svg)](https://github.com/moovweb/gvm) [![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)[![Snap Status](https://build.snapcraft.io/badge/caffix/amass.svg)](https://build.snapcraft.io/user/caffix/amass)


The amass tool searches Internet data sources, performs brute force subdomain enumeration, searches web archives, and uses machine learning to generate additional subdomain name guesses. DNS name resolution is performed across many public servers so the authoritative server will see the traffic coming from different locations.

## How to Install

#### Prebuilt

A [precompiled version is available](https://github.com/caffix/amass/releases) for each release.

If your operating environment supports [Snap](https://docs.snapcraft.io/core/install), you can [click here to install](https://snapcraft.io/amass), or perform the following from the command-line:
```
$ sudo snap install amass
```


If you would like snap get you the latest unstable build of amass, type the following command:
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
$ amass example.com
```

Be sure that the target **domain is the last parameter** provided to amass, then followed by any extra domains.

You can also provide the initial domain names via an input file:
```
$ amass -d domains.txt
```


Get amass to provide summary information:
```
$ amass -v example.com
www.example.com
ns.example.com
...
13242 names discovered - scrape: 211, dns: 4709, archive: 126, brute: 169, alt: 8027
```


Have amass provide the source that discovered the subdomain name:
```
$ amass -vv example.com
[Google] www.example.com
[VirusTotal] ns.example.com
...
```


Have amass print IP addresses with the discovered names:
```
$ amass -ip example.com
```


Have amass write the results to a text file:
```
$ amass -ip -o example.txt example.com
```


The amass feature that performs alterations on discovered names and attempt resolution can be disabled:
```
$ amass -noalts example.com
```


Have amass perform brute force subdomain enumeration as well:
```
$ amass -brute example.com
```


By default, amass performs recursive brute forcing on new subdomains; this can be disabled:
```
$ amass -brute -norecursive example.com
```


Change the wordlist used during the brute forcing phase of the enumeration:
```
$ amass -brute -w wordlist.txt example.com
```


Throttle the rate of DNS queries by number per minute:
```
$ amass -freq 120 example.com
```


Allow amass to include additional domains in the search using reverse whois information:
```
$ amass -whois example.com
```


You can have amass list all the domains discovered with reverse whois before performing the enumeration:
```
$ amass -whois -l example.com
```


Add some additional domains to the search:
```
$ amass example1.com example2.com example3.com
```

In the above example, the domains example2.com and example3.com are simply appended to the list potentially provided by the reverse whois information.


#### Infrastructure Options

**Caution:** If you use these options without specifying root domain names, amass will attempt to reach out to every IP address within the identified infrastructure and obtain names from TLS certificates. This is "loud" and can reveal your reconnaissance activities to the organization being investigated.

If you do provide root domain names on the command-line, these options will simply serve as constraints to the amass output.

To discover all domains hosted within target ASNs, use the following option:
```
$ amass -asn 13374,14618
```


To investigate within target CIDRs, use this option:
```
$ amass -net 192.184.113.0/24,104.154.0.0/15
```


To limit your enumeration to specific IPs or address ranges, use this option:
```
$ amass -addr 192.168.1.44,192.168.2.1-64
```


By default, port 443 will be checked for certificates, but the ports can be changed as follows:
```
$ amass -net 192.168.1.0/24 -p 80,443,8080
```


#### Using a Proxy (still under development)

The amass tool can send all its traffic through a proxy, such as socks4, socks4a, socks5, http and https. Do **not** use this to send the traffic through Tor, since that network does not support UDP traffic.
```
$ amass -vv -proxy socks5://user:password@192.168.1.1:5050 example.com
```


**Thank you** GameXG/ProxyClient for making it easy to implement this feature!


## Integrating amass Into Your Work

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
        result := <-output

        fmt.Println(result.Name)
    }()

    // Seed the default pseudo-random number generator
    rand.Seed(time.Now().UTC().UnixNano())
    // Setup the amass configuration
    config := amass.CustomConfig(&amass.AmassConfig{
        Domains:      []string{"example.com"},
        Output:       output,
    })
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


## Let Me Know What You Think

**NOTE: Still under development**

**Author: Jeff Foley @jeff_foley**

**Company: ClaritySec, Inc. / @claritysecinc**
