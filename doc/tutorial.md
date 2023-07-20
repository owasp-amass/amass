# [![OWASP Logo](https://github.com/owasp-amass/amass/blob/master/images/owasp_logo.png) OWASP Amass](https://owasp.org/www-project-amass/) - An Extensive Tutorial

![Network graph](https://github.com/owasp-amass/amass/blob/master/images/network_06092018.png "Amass Network Mapping")

----

## Introduction

Whether you are a penetration tester, an auditor, a security researcher or the CISO/IT manager, you could have several valid reasons for mapping out the external attack surface of an organisation. This process is also referred to as reconnaissance or information gathering.

[The OWASP Amass Project](https://owasp.org/www-project-amass/) (Amass) can help with this to a large extent depending on your requirements. In this blog post, we will aim to demonstrate how one can use Amass to discover the majority of an organisation's externally exposed assets.

The focus will be on performing continuous subdomain discovery exercises. We have broken this blog post into different sections to make it easier to get to grips with the various functions of Amass. It should be noted that there may be assets out there that are not mapped to a domain and you will need to employ other techniques to uncover them, such as running network scans over the IP ranges owned by the organization. Although we will not fully demonstrate how to use all the functions offered by Amass, we are hoping that this blog will cover enough to give you a kick-start in mastering the collection tool.

## Why OWASP Amass?

A high number of open-source tools and software are available for enumerating subdomains, autonomous system numbers (ASNs), and other assets owned by an organization. Although most of these tools are great in utilizing specific methods, they are not always actively maintained and updated to keep up with the latest techniques and methodologies. So to speak the truth, most of the available tools are not complete and solely relying on these could give a false sense of security or lead to missing vulnerable assets. The reality is that subdomains can be disclosed anywhere nowadays, such as on social media, Pastebin, source code repositories, HTTP headers and so on.

Amass is backed by OWASP, which should provide prestige and confidence in the results. It is actively maintained and will likely be supported for a long time, meaning any future bugs will be resolved. Additionally, the adoption rate of Amass is high which potentially means better data consistency and integration with other tools. As such, it can constitute a better and more trustworthy tool to use in proof of concepts and engagements. This can make it easier to convince your clients or manager to use it for periodical mapping of the organization's attack surface.

There are a number of more technical reasons, which we will explain below and demonstrate in more detail later:

-   Comes with 3 subcommands, in other words functions:
    -   amass intel -- Discover target namespaces for enumerations
    -   amass enum -- Perform enumerations and network mapping
    -   amass db -- Manipulate the Amass graph database
-   Amass' subcommands can be used in conjunction, in some cases, which could allow you to create scripts that perform multiple Amass operations.
-   Supports > 80 sources, such as APIs and websites, at the time of writing as part of its subdomain discovery and information gathering techniques. These can be listed using the following command:
    -   amass enum -list
    -   ```AlienVault,ArchiveIt,Arquivo,Ask,Baidu,BinaryEdge,Bing,BufferOver,Censys,CertSpotter,CIRCL,CommonCrawl,Crtsh,[...],VirusTotal,Wayback,WhoisXML,Yahoo``` (full list [here](https://github.com/owasp-amass/amass))

-   It employs various information gathering techniques for DNS enumeration
    -   Brute-force of subdomains using a domain name wordlists and alteration wordlists
    -   Identify subdomains by reading SSL/TLS certificates, performing DNS zone transfers or checking certificate transparency logs
    -   Recursive subdomain discovery on identified domains
    -   Hashcat-style masks for brute-force of subdomains (this can be very useful if you have internal information on naming conventions and so on)
-   It can be configured using a configuration file which makes it easy to maintain, use or integrate with scripts

Lastly, we will not be going into the details of installing Amass in this blog post, but if you are interested, you can do so in a number of ways. You can compile from source if you have a properly configured Golang environment (Go >= 1.20), run it using Docker, or install it as a package if one is available for your distribution. Detailed installation instructions are available [here](./install.md).

## Amass Intel

The Amass intel subcommand, or module if you want, can aid with collecting open source intelligence on the organization and allow you to find further root domain names associated with the organization. To see the available options of this subcommand, simply type it at the terminal:

```bash
$ amass intel
[...]
Usage: amass intel [options] [-whois -d DOMAIN] [-addr ADDR -asn ASN -cidr CIDR]
  -active
        Attempt certificate name grabs
  -addr value
        IPs and ranges (192.168.1.1-254) separated by commas
  -asn value
        ASNs separated by commas (can be used multiple times)
[...]
```

It is probably worth noting at this point that another great perk of Amass is that all the subcommands attempt to maintain argument consistency.

This subcommand will use a number of information gathering techniques and data sources by default, such as WHOIS, in order to obtain intelligence and parent domains owned by the organization, unless these are explicitly disabled in Amass' configuration file. An example Amass configuration file is available [on the GitHub config repository](https://github.com/owasp-amass/config/blob/master/examples/config.yaml).

```bash

$ amass intel -d owasp.org -whois
appseceu.com
owasp.com
appsecasiapac.com
appsecnorthamerica.com
appsecus.com
[...]
owasp.org
appsecapac.com
appsecla.org
[...]
```

You can also confirm some of the results above by browsing to data sources manually. In the screenshot below, we have performed a reverse WHOIS search for "OWASP Foundation" and found similar domains:

<https://viewdns.info/reversewhois/?q=OWASP+Foundation>
![OWASP Amass information gathering techniques](../images/tutorial/viewdnsinfo_example.png?raw=true)

When performing searches with amass intel you can always run it with more configuration options, such as the "-active" argument which will attempt zone transfers and actively scan to fetch SSL/TLS certificates to extract information. As with any engagement, ensure you are authorized to perform active searches against the target.

It is worth noting at this point that some configuration flags will not work along with others and in this case Amass will simply ignore them.

Amass' findings will not always be accurate, this can be for several reasons, e.g. the data sources used by Amass may not be consistent or up to date. Amass attempts to further validate the information using DNS queries, and more validation techniques will be implemented in the future. Although Amass does a good job, users should still perform further verification checks on results that do not appear to be related to the target. This can be performed using a variety of methods such as:

-   Use utilities to resolve the domains (e.g. dig, nslookup)
-   Perform WHOIS lookups to confirm organizational details
-   Search findings, such as parent domains, on search engines

You can also look for organizational names with Amass which could return ASN IDs assigned to the target, an example is shown below:

```bash
$ amass intel -org 'Example Ltd'
111111, MAIN_PRODUCT -- Example Ltd
222222, SECONDARY_PRODUCT - Example Ltd
[...]

Please note that the above data is fictitious for demonstration purposes. Retrieved ASNs could then be fed back into Amass. The below command attempts to retrieve registered domains found within the specified ASN and return them along with the IP address they resolve to (127.0.0.1 in this case for demonstration purposes):

$ amass intel -active -asn 222222 -ip
some-example-ltd-domain.com 127.0.0.1
[...]
```

## Amass Enum

Let's move to Amass enum, which is where most of Amass' powerful capabilities reside. Amass enum allows you to perform DNS enumeration and mapping of the target to determine the attack surface exposed by organizations. The enumeration findings are stored in a graph database, which will be located in Amass' default output folder or the specified output directory with "-dir" flag. This is also the case with other Amass subcommands.

### Run Amass under Passive or Active Configuration

Amass enum can be executed under the context of a passive or an active configuration mode. The passive mode is much quicker, but Amass will not validate DNS information, for example by resolving the subdomains. You can run it passively using the "-passive" flag and you will not be able to enable many techniques or configurations, such as DNS brute-forcing and name alterations. There are several reasons for choosing passive mode over the active mode, for example:

-   You need to know all possible subdomains that have been used and may be reused in the future, perhaps because you need to constantly monitor the target's attack surface for changes or because you are working on a phishing engagement and looking for subdomains.
-   Your perimeter's security testing process validates DNS information at a later stage and need Amass results quickly.
-   Due to a security engagement's constraints or requirements, you can only perform passive information gathering.

In the below example, we are passively searching for subdomains on owasp.org:

```bash
$ amass enum -passive -d owasp.org
[...]
update-wiki.owasp.org
[...]
my.owasp.org
www.lists.owasp.org
www.ocms.owasp.org
[...]
```

It is worth stating at this point that although Amass intel will help gather IP ranges, ASNs and registered domains owned by an organization, Amass enum will identify all subdomains. This subdomain enumeration is completed in under 2 minutes on my test machine. Here's a slightly modified screenshot showing the results of this enumeration:

![OWASP Amass enum tutorial for subdomain discovery](../images/tutorial/amass_passive_run_example.png?raw=true)

Using Amass in active configuration mode means that you will have more accurate results and more assets could be discovered since all DNS enumeration techniques will be enabled. It should be noted that by "active configuration mode" we are not strictly referring to the "-active" flag, which enables zone transfers and port scanning of SSL/TLS services and grabbing their certificates to extract any subdomains from certificate fields (e.g. Common Name).

The below command (a detailed explanation of which follows later) can be considered active overall as it performs subdomain brute-forcing in multiple ways (wordlist, masks, etc.) along with the "-active" flag being enabled. All findings will be validated by Amass using the default or the specified resolvers:

```bash
$ amass enum -active -d owasp.org -brute -w /root/dns_lists/deepmagic.com-top50kprefixes.txt -ip -dir amass4owasp -config /root/amass/config.yaml -o amass_results_owasp.txt
```
![Performing subdomain discovery exercise with OWASP Amass](../images/tutorial/amass_active_run_example.png?raw=true)

The command we have used above specifies that the Amass graph database, along with log files, will be stored at "./amass4owasp". We have also asked Amass to display the IP address(es) it resolves names to with the "-ip" flag. We have provided Amass with the [deepmagic](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS) DNS wordlist with the "-w" argument, and also specified the location of the config.yaml file with "-config" and the output with "-o".

While the command above is hopefully straightforward, we would like to provide some further notes:

-   In this instance, Amass will check within the config.yaml file for DNS resolvers or use the default ones embedded within the Amass code. You can also specify your own DNS resolvers either with the use of the "-r" and "-rf" flags or within the config.yaml file. Using the "-r" flag you can specify the IP addresses of DNS resolvers at the command-line, while with the "-rf" you can specify a file containing these on each line.

-   We could have specified all these configurations in a config.yaml file and provided this to Amass with "-config". It's worth stating at this point that command-line arguments will take priority over what's specified in the config.yaml file. So, if you are disabling brute-force in the config.yaml file, but supply the "-brute" argument on the command line, then brute-force techniques will be used.

-   The command above, unless explicitly disabled with the use of the "-norecursive", will perform recursive DNS enumeration on subdomains identified by default.

At this point, you should also keep in mind that if you are performing multiple Amass operations within short periods of time from the same IP, the IP may be permanently blocked from some sources that Amass is scraping such as the Google/Yahoo search engines.

To conclude this section in a more interesting way, let's assume that for some reason the OWASP organization tends to create subdomains with "zzz" prefixes, such as zzz-dev.owasp.org. You can leverage the Amass' hashcat-style wordlist mask feature to brute-force all the combinations of "zzz-[a-z][a-z][a-z].owasp.org" using the following command:

```bash
$ amass enum -d owasp.org -norecursive -wm "zzz-?l?l?l" -dir amass4owasp
```

Note that in the configuration above we have explicitly disabled recursive DNS enumerations, as we were interested in quicker results using the mask only.

Finally, you can always check the Amass log file within the output directory to ensure your configuration is working as expected:

![OWASP Amass advanced subdomain discovery with hashcat masks](../images/tutorial/amass_logs_example2.png?raw=true)

## Amass DB

You can use this subcommand in order to interact with an Amass graph database, either the default or the one specified with the "-dir" flag.

For example, the below command would list all the names discovered during enumerations you have performed against owasp.org and stored in the "amass4owasp" graph database:

```bash
$ amass db -dir amass4owasp -names -d owasp.org
```

Next, with a similar command, you could retrieve the complete output for owasp.org and stored in the "amass4owasp" graph database:

```bash
$ amass db -dir amass4owasp -d owasp.org -show -ip
```

You may want to maintain the same Amass output directory for statistical or historical purposes, through which you perform all the subdomain enumeration exercises, as Amass tracking can be used only against the same graph database and output directory.

## Conclusion

In closing, OWASP Amass is a project that is becoming increasingly popular. We highly recommend that you incorporate Amass in your workflow/processes if you have information gathering and subdomain discovery requirements, and stay tuned as more and more features and improvements will be added with every release. Finally, you can always refer to the official [User's Guide](./user_guide.md) of Amass.

## Credits

This tutorial page was built based on [How to Use OWASP Amass: An Extensive Tutorial
](https://www.dionach.com/blog/how-to-use-owasp-amass-an-extensive-tutorial/) that has been published on [Dionach's website](https://www.dionach.com/).
