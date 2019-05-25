
# [![OWASP Logo](https://github.com/OWASP/Amass/blob/master/images/owasp_logo.png) OWASP Amass](https://www.owasp.org/index.php/OWASP_Amass_Project) - User's Guide

![Network graph](https://github.com/OWASP/Amass/blob/master/images/network_06092018.png "Amass Network Mapping")

----

## Simple Examples For Getting Started

The most basic use of the tool:

```bash
amass -d example.com
```

Typical parameters for DNS enumeration:

```bash
$ amass -src -ip -brute -min-for-recursive 1 -d example.com
[Google] www.example.com
[VirusTotal] ns.example.com
...
```

## Command-line Usage Information

Switches available through the amass CLI without subcommands:

| Flag | Description | Example |
|------|-------------|---------|
| -active | Enable active recon methods | amass -active -d example.com net -p 80,443,8080 |
| -aw | Path to a different wordlist file for alterations | amass -aw PATH -d example.com |
| -bl  | Blacklist of subdomain names that will not be investigated | amass -bl blah.example.com -d example.com |
| -blf | Path to a file providing blacklisted subdomains | amass -blf data/blacklist.txt -d example.com |
| -brute | Perform brute force subdomain enumeration | amass -brute -d example.com |
| -config | Path to the INI configuration file | amass -config config.ini |
| -d   | Domain names separated by commas (can be used multiple times) | amass -d example.com |
| -df  | Path to a file providing root domain names | amass -df domains.txt |
| -do  | Path to data operations output file | amass -do data.json -d example.com |
| -ef  | Path to a file providing data sources to exclude | amass -ef exclude.txt -d example.com |
| -exclude | Data source names separated by commas to be excluded | amass -exclude crtsh -d example.com |
| -h   | Show the amass usage information | amass -h |
| -if  | Path to a file providing data sources to include | amass -if include.txt -d example.com |
| -include | Data source names separated by commas to be included | amass -include crtsh -d example.com |
| -include-unresolvable | Output DNS names that did not resolve | amass -include-unresolvable -d example.com |
| -ip  | Show the IP addresses for discovered names | amass -ip -d example.com |
| -ipv4  | Show the IPv4 addresses for discovered names | amass -ipv4 -d example.com |
| -ipv6  | Show the IPv6 addresses for discovered names | amass -ipv6 -d example.com |
| -json | Path to the JSON output file | amass -json out.json -d example.com |
| -list | Print the names of all available data sources | amass -l |
| -log | Path to the log file where errors will be written | amass -log amass.log -d example.com |
| -max-dns-queries | Maximum number of concurrent DNS queries | amass -max-dns-queries 200 -d example.com |
| -min-for-recursive | Number of labels in a subdomain before recursive brute forcing | amass -brute -min-for-recursive 3 -d example.com |
| -nf | Path to a file providing already known subdomain names | amass -nf names.txt -d example.com |
| -noalts | Disable generation of altered names | amass -noalts -d example.com |
| -norecursive | Turn off recursive brute forcing | amass -brute -norecursive -d example.com |
| -o   | Path to the text output file | amass -o out.txt -d example.com |
| -oA  | Path prefix used for naming all output files | amass -oA amass_scan -d example.com |
| -passive | A purely passive mode of execution | amass --passive -d example.com |
| -r   | IP addresses of preferred DNS resolvers (can be used multiple times) | amass -r 8.8.8.8,1.1.1.1 -d example.com |
| -rf  | Path to a file providing preferred DNS resolvers | amass -rf data/resolvers.txt -d example.com |
| -src | Print data sources for the discovered names | amass -src -d example.com |
| -version | Print the version number of this Amass binary | amass -version |
| -w   | Path to a different wordlist file | amass -brute -w wordlist.txt -d example.com |

### The 'net' Subcommand

**Caution:** If you use the net subcommand, it will attempt to reach out to every IP address within the identified infrastructure and obtain additional domain names from reverse DNS requests and TLS certificates. This is "loud" and can reveal your reconnaissance activities to the organization being investigated, as well as expand the scope of your enumeration.

| Flag | Description | Example |
|------|-------------|---------|
| -org | Search string provided against AS description information | amass net -org Facebook |
| -asn  | ASNs separated by commas (can be used multiple times) | amass net -asn 13374,14618 |
| -cidr | CIDRs separated by commas (can be used multiple times) | amass net -cidr 104.154.0.0/15 |
| -addr | IPs and ranges (192.168.1.1-254) separated by commas | amass net -addr 192.168.2.1-64 |
| -p | Ports separated by commas (default: 443) | amass net -cidr 104.154.0.0/15 -p 443,8080 |
| -whois | All discovered domains are run through reverse whois | amass net -whois -asn 13374 |

### The 'viz' Subcommand

Create enlightening network graph visualizations that provide structure to the information you gather. This tool requires an input file generated by the amass '-do' flag.

Switches for outputting the DNS and infrastructure findings as a network graph:

| Flag | Description | Example |
|------|-------------|---------|
| -maltego | Output a Maltego Graph Table CSV file | amass viz -maltego |
| -d3  | Output a D3.js v4 force simulation HTML file | amass viz -d3 |
| -gexf | Output to Graph Exchange XML Format (GEXF) | amass viz -gephi |
| -graphistry | Output Graphistry JSON | amass viz -graphistry |
| -visjs | Output HTML that employs VisJS | amass viz -visjs |

### The 'db' Subcommand

Switches for interacting with the DNS and infrastructure findings in the graph database:

| Flag | Description | Example |
|------|-------------|---------|
| -dir | Path to the directory containing the graph database | amass db -dir PATH |
| -enums  | Print information for all available enumerations | amass db -enums |

### The 'track' Subcommand

Switches for performing Internet exposure monitoring across the enumerations in the graph database:

| Flag | Description | Example |
|------|-------------|---------|
| -history | Show the difference between all enumeration pairs | amass track -history |
| -last  | The number of recent enumerations to include in the tracking | amass track -last |
| -start  | Exclude all enumerations before a specified date (format: 01/02 15:04:05 2006 MST) | amass track -start DATE |

## The Configuration File

You will need a config file to use your API keys with Amass. See the [Example Configuration File](https://github.com/OWASP/Amass/blob/master/examples/config.ini) for more details.

## Importing OWASP Amass Results into Maltego

1. Convert the Amass data into a Maltego graph table CSV file:

```bash
amass viz -maltego
```

2. Import the CSV file with the correct Connectivity Table settings:

![Connectivity table](https://github.com/OWASP/Amass/blob/master/images/maltego_graph_import_wizard.png "Connectivity Table Settings")

3. All the Amass findings will be brought into your Maltego Graph:

![Maltego results](https://github.com/OWASP/Amass/blob/master/images/maltego_results.png "Maltego Results")

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
