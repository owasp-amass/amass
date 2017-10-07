# Subdomain and Host Enumeration

### Obtain a large number of names without revealing your location to the target organization

[![](https://img.shields.io/badge/go-1.8-blue.svg)](https://github.com/moovweb/gvm) [![License](https://img.shields.io/hexpm/l/plug.svg)](https://www.apache.org/licenses/LICENSE-2.0)


The amass tool not only searches a few Internet data sources and then performs brute force subdomain enumeration, it also searches web archives to obtain web pages from the target organization without them being aware of it! Searching these web pages reveals additional subdomains and host names not likely to be provided by a wordlist file. All three methods can be employed together by amass, and have shown to be complementary.


## Install

1. Download [amass](https://github.com/caffix/amass):
```
$ go get -u github.com/caffix/amass
```

At this point, the amass binary should be in *$GOPATH/bin*.


2. Several wordlists can be found in the following directory:
```
$ ls $GOPATH/src/github.com/caffix/amass/wordlists
```


## Using amass

The most basic use of the tool:
```
$ amass example.com
```


Get amass to provide summary information:
```
$ amass -v example.com
```


Have amass print IP addresses with the discovered names:
```
$ amass -ip example.com
```


Throttle the rate of DNS queries by number per minute:
```
$ amass -limit 120 example.com
```

**The maximum rate supported is one DNS query every 50 milliseconds.**


Allow amass to included additional domains in the search using reverse whois information:
```
$ amass -whois example.com
```


You can have amass list all the domains discovered with reverse whois before performing the enumeration:
```
$ amass -whois -list example.com
```


Have amass perform brute force subdomain enumeration as well:
```
$ amass -brute wordlist_filepath.txt example.com
```


Have amass make a selected number of smart guesses based on successfully resolved names:
```
$ amass -smart 50000 example.com
```


Add some additional domains to the search:
```
$ amass example.com example1.com example2.com
```

In the above example, the domains example1.com and example2.com are simply appended to the list potentially provided by the reverse whois information.


All these options can be used together:
```
$ amass -v -ip -whois -brute wordlist_filepath.txt example.com example1.com
```

**Be sure that the target domain is the last parameter provided to amass, followed by any extra domains.**


## Settings for the amass Maltego Local Transform

1. Setup a new local transform within Maltego:

![alt text](https://github.com/caffix/amass/blob/master/examples/maltegosetup1.png "Setup")


2. Configure the local transform to properly execute the go program:

![alt text](https://github.com/caffix/amass/blob/master/examples/maltegosetup2.png "Configure")


3. Go into the Transform Manager, and disable the **debug info** option:

![alt text](https://github.com/caffix/amass/blob/master/examples/maltegosetup3.png "Disable Debug")


## Let me know what you think

**NOTE: Still under development**

**Author: Jeff Foley / @jeff_foley**

**Company: ClaritySec, Inc. / @claritysecinc**