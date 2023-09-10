# [![OWASP Logo](../images/owasp_logo.png) OWASP Amass](https://owasp.org/www-project-amass/) - Users' Guide

![Network graph](../images/network_06092018.png "Amass Network Mapping")

----

## Simple Examples For Getting Started

The amass tool and all the subcommands show options using the **'-h'** and **'-help'** flags:

```bash
amass -help
```

Check the version by performing the following:

```bash
amass -version
```

The most basic use of the tool for subdomain enumeration:

```bash
amass enum -d example.com
```

Typical parameters for DNS enumeration:

```bash
$ amass enum -brute -min-for-recursive 2 -d example.com
example.com (FQDN) --> node --> www.example.com (FQDN)
www.example.com (FQDN) --> a_record --> 123.456.789.01 (IPAddress)
...
```

Executing the tool via the Docker image:

```bash
docker run -v OUTPUT_DIR_PATH:/.config/amass/ caffix/amass:latest enum --list
```

The volume argument allows the Amass graph database to persist between executions and output files to be accessed on the host system. The first field (left of the colon) of the volume option is the amass output directory that is external to Docker, while the second field is the path, internal to Docker, where amass will write the output files.

## Command-line Usage Information

The amass tool has several subcommands shown below for handling your Internet exposure investigation.

| Subcommand | Description |
|------------|-------------|
| intel | Collect open source intelligence for investigation of the target organization |
| enum | Perform DNS enumeration and network mapping of systems exposed to the Internet |
| db | Manage the graph databases storing the enumeration results |

All subcommands have some default global arguments that can be seen below.

| Flag | Description | Example |
|------|-------------|---------|
| -h/-help | Show the program usage message | amass subcommand -h |
| -config | Path to the YAML configuration file | amass subcommand -config config.yaml |
| -dir | Path to the directory containing the graph database | amass subcommand -dir PATH -d example.com |
| -nocolor | Disable colorized output | amass subcommand -nocolor -d example.com |
| -silent | Disable all output during execution | amass subcommand -silent -json out.json -d example.com |

Each subcommand's own arguments are shown in the following sections.

### The 'intel' Subcommand

The intel subcommand can help you discover additional root domain names associated with the organization you are investigating. The data source sections of the configuration file are utilized by this subcommand in order to obtain passive intelligence, such as reverse whois information.

| Flag | Description | Example |
|------|-------------|---------|
| -active | Enable active recon methods | amass intel -active -addr 192.168.2.1-64 -p 80,443,8080 |
| -addr | IPs and ranges (192.168.1.1-254) separated by commas | amass intel -addr 192.168.2.1-64 |
| -asn | ASNs separated by commas (can be used multiple times) | amass intel -asn 13374,14618 |
| -cidr | CIDRs separated by commas (can be used multiple times) | amass intel -cidr 104.154.0.0/15 |
| -d | Domain names separated by commas (can be used multiple times) | amass intel -whois -d example.com |
| -demo | Censor output to make it suitable for demonstrations | amass intel -demo -whois -d example.com |
| -df | Path to a file providing root domain names | amass intel -whois -df domains.txt |
| -ef | Path to a file providing data sources to exclude | amass intel -whois -ef exclude.txt -d example.com |
| -exclude | Data source names separated by commas to be excluded | amass intel -whois -exclude crtsh -d example.com |
| -if | Path to a file providing data sources to include | amass intel -whois -if include.txt -d example.com |
| -include | Data source names separated by commas to be included | amass intel -whois -include crtsh -d example.com |
| -ip | Show the IP addresses for discovered names | amass intel -ip -whois -d example.com |
| -ipv4 | Show the IPv4 addresses for discovered names | amass intel -ipv4 -whois -d example.com |
| -ipv6 | Show the IPv6 addresses for discovered names | amass intel -ipv6 -whois -d example.com |
| -list | Print the names of all available data sources | amass intel -list |
| -log | Path to the log file where errors will be written | amass intel -log amass.log -whois -d example.com |
| -o | Path to the text output file | amass intel -o out.txt -whois -d example.com |
| -org | Search string provided against AS description information | amass intel -org Facebook |
| -p | Ports separated by commas (default: 80, 443) | amass intel -cidr 104.154.0.0/15 -p 443,8080 |
| -r | IP addresses of preferred DNS resolvers (can be used multiple times) | amass intel -r 8.8.8.8,1.1.1.1 -whois -d example.com |
| -rf | Path to a file providing preferred DNS resolvers | amass intel -rf data/resolvers.txt -whois -d example.com |
| -timeout | Number of minutes to execute the enumeration | amass intel -timeout 30 -d example.com |
| -v | Output status / debug / troubleshooting info | amass intel -v -whois -d example.com |
| -whois | All discovered domains are run through reverse whois | amass intel -whois -d example.com |

### The 'enum' Subcommand

This subcommand will perform DNS enumeration and network mapping while populating the selected graph database. All the setting available in the configuration file are relevant to this subcommand. The following flags are available for configuration:

#### Mode description

+ **Normal**: Run enum subcommand without specifing active or passive flag will seed the enumeration from data sources and leverage DNS to validate findings and further investigate the namespaces in scope (provided domain names)

  `amass enum -d example.com`

+ **Active**: It will perform all of the Normal mode and reach out to the discovered assets and attempt to obtain TLS certificates, perform DNS zone transfers, use NSEC walking, and perform web crawling.

  `amass enum -active -d example.com -p 80,443,8080`

+ **Passive**: It will only obtain information from data sources and blindly accept it.

  `amass enum --passive -d example.com`
  

| Flag | Description | Example |
|------|-------------|---------|
| -active | Enable active recon methods | amass enum -active -d example.com -p 80,443,8080 |
| -alts | Enable generation of altered names | amass enum -alts -d example.com |
| -aw | Path to a different wordlist file for alterations | amass enum -aw PATH -d example.com |
| -awm | "hashcat-style" wordlist masks for name alterations | amass enum -awm dev?d -d example.com |
| -bl | Blacklist of subdomain names that will not be investigated | amass enum -bl blah.example.com -d example.com |
| -blf | Path to a file providing blacklisted subdomains | amass enum -blf data/blacklist.txt -d example.com |
| -brute | Perform brute force subdomain enumeration | amass enum -brute -d example.com |
| -d | Domain names separated by commas (can be used multiple times) | amass enum -d example.com |
| -demo | Censor output to make it suitable for demonstrations | amass enum -demo -d example.com |
| -df | Path to a file providing root domain names | amass enum -df domains.txt |
| -dns-qps | Maximum number of DNS queries per second across all resolvers | amass enum -dns-qps 200 -d example.com |
| -ef | Path to a file providing data sources to exclude | amass enum -ef exclude.txt -d example.com |
| -exclude | Data source names separated by commas to be excluded | amass enum -exclude crtsh -d example.com |
| -if | Path to a file providing data sources to include | amass enum -if include.txt -d example.com |
| -iface | Provide the network interface to send traffic through | amass enum -iface en0 -d example.com |
| -include | Data source names separated by commas to be included | amass enum -include crtsh -d example.com |
| -ip | Show the IP addresses for discovered names | amass enum -ip -d example.com |
| -ipv4 | Show the IPv4 addresses for discovered names | amass enum -ipv4 -d example.com |
| -ipv6 | Show the IPv6 addresses for discovered names | amass enum -ipv6 -d example.com |
| -list | Print the names of all available data sources | amass enum -list |
| -log | Path to the log file where errors will be written | amass enum -log amass.log -d example.com |
| -max-depth | Maximum number of subdomain labels for brute forcing | amass enum -brute -max-depth 3 -d example.com |
| -min-for-recursive | Subdomain labels seen before recursive brute forcing (Default: 1) | amass enum -brute -min-for-recursive 3 -d example.com |
| -nf | Path to a file providing already known subdomain names (from other tools/sources) | amass enum -nf names.txt -d example.com |
| -norecursive | Turn off recursive brute forcing | amass enum -brute -norecursive -d example.com |
| -o | Path to the text output file | amass enum -o out.txt -d example.com |
| -oA | Path prefix used for naming all output files | amass enum -oA amass_scan -d example.com |
| -p | Ports separated by commas (default: 443) | amass enum -d example.com -p 443,8080 |
| -passive | A purely passive mode of execution | amass enum -passive -d example.com |
| -r | IP addresses of untrusted DNS resolvers (can be used multiple times) | amass enum -r 8.8.8.8,1.1.1.1 -d example.com |
| -rf | Path to a file providing untrusted DNS resolvers | amass enum -rf data/resolvers.txt -d example.com |
| -rqps | Maximum number of DNS queries per second for each untrusted resolver | amass enum -rqps 10 -d example.com |
| -scripts | Path to a directory containing ADS scripts | amass enum -scripts PATH -d example.com |
| -timeout | Number of minutes to execute the enumeration | amass enum -timeout 30 -d example.com |
| -tr | IP addresses of trusted DNS resolvers (can be used multiple times) | amass enum -tr 8.8.8.8,1.1.1.1 -d example.com |
| -trf | Path to a file providing trusted DNS resolvers | amass enum -trf data/trusted.txt -d example.com |
| -trqps | Maximum number of DNS queries per second for each trusted resolver | amass enum -trqps 20 -d example.com |
| -v | Output status / debug / troubleshooting info | amass enum -v -d example.com |
| -w | Path to a different wordlist file for brute forcing | amass enum -brute -w wordlist.txt -d example.com |
| -wm | "hashcat-style" wordlist masks for DNS brute forcing | amass enum -brute -wm ?l?l -d example.com |

## The Output Directory

Amass has several files that it outputs during an enumeration (e.g. the log file). If you are not using a database server to store the network graph information, then Amass creates a file based graph database in the output directory. These files are used again during future enumerations.

By default, the output directory is created in the operating system default root directory to use for user-specific configuration data and named *amass*. If this is not suitable for your needs, then the subcommands can be instructed to create the output directory in an alternative location using the **'-dir'** flag.

If you decide to use an Amass configuration file, it will be automatically discovered when put in the output directory and named **config.yaml**.

## The Configuration File

Configuration files are provided so users can specify the scope and options with Amass. See the [Example Configuration File](../examples/config.yaml) for more details.

API keys for data sources are stored in a separate file. See the [Example Data Sources File](../examples/datasources.yaml) for more details.

The location of the configuration file can be specified using the `-config` flag or the `AMASS_CONFIG` environment variable.

Amass automatically tries to discover the configuration file (named `config.yaml`) in the following locations:

| Operating System | Path |
| ---------------- | ---- |
| Linux / Unix | `$XDG_CONFIG_HOME/amass/config.yaml` or `$HOME/.config/amass/config.yaml` or `/etc/amass/config.yaml` |
| Windows | `%AppData%\amass\config.yaml` |
| OSX | `$HOME/Library/Application Support/amass/config.yaml` |

These are good places for you to put your configuration file.

Note that these locations are based on the [output directory](#the-output-directory). If you use the `-dir` flag, the location where Amass will try to discover the configuration file will change. For example, if you pass in `-dir ./my-out-dir`, Amass will try to discover a configuration file in `./my-out-dir/config.yaml`.

### Default Section

| Option | Description |
|--------|-------------|
| mode | Determines which mode the enumeration is performed in: default, passive or active |
| output_directory | The directory that stores the graph database and other output files |
| maximum_dns_queries | The maximum number of concurrent DNS queries that can be performed |

### The `resolvers` Section

| Option | Description |
|--------|-------------|
| resolver | The IP address of a DNS resolver and used globally by the amass package |

### The `scope` Section

| Option | Description |
|--------|-------------|
| address | IP address or range (e.g. a.b.c.10-245) that is in scope |
| asn | ASN that is in scope |
| cidr | CIDR (e.g. 192.168.1.0/24) that is in scope |
| port | Specifies a port to be used when actively pulling TLS certificates or crawling |

#### The `scope.domains` Section

| Option | Description |
|--------|-------------|
| domain | A root DNS domain name to be added to the enumeration scope |

#### The `scope.blacklisted` Section

| Option | Description |
|--------|-------------|
| subdomain | A DNS subdomain name to be considered out of scope during the enumeration |

### The `graphdbs` Section

#### The `graphdbs.postgres` Section

| Option | Description |
|--------|-------------|
| primary | When set to true, the graph database is specified as the primary db |
| url | URL in the form of "postgres://[username:password@]host[:port]/database-name?sslmode=disable" where Amass will connect to a PostgreSQL database |
| options | Additional PostgreSQL database options |

### The `bruteforce` Section

| Option | Description |
|--------|-------------|
| enabled | When set to true, brute forcing is performed during the enumeration |
| recursive | When set to true, brute forcing is performed on discovered subdomain names as well |
| minimum_for_recursive | Number of discoveries made in a subdomain before performing recursive brute forcing |
| wordlist_file | Path to a custom wordlist file to be used during the brute forcing |

### The `alterations` Section

| Option | Description |
|--------|-------------|
| enabled | When set to true, permuting resolved DNS names is performed during the enumeration |
| edit_distance | Number of times an edit operation will be performed on a name sample during fuzzy label searching |
| flip_words | When set to true, causes words in DNS names to be exchanged for others in the alteration word list |
| flip_numbers | When set to true, causes numbers in DNS names to be exchanged for other numbers |
| add_words | When set to true, causes other words in the alteration word list to be added to resolved DNS names |
| add_numbers | When set to true, causes numbers to be added and removed from resolved DNS names |
| wordlist_file | Path to a custom wordlist file that provides additional words to the alteration word list |

### The `data_sources` Section

| Option | Description |
|--------|-------------|
| ttl | The number of minutes that the responses of **all** data sources for the target are cached |

#### The `data_sources.SOURCENAME` Section

| Option | Description |
|--------|-------------|
| ttl | The number of minutes that the response of the data source for the target is cached |

##### The `data_sources.SOURCENAME.CREDENTIALSETID` Section

| Option | Description |
|--------|-------------|
| apikey | The API key to be used when accessing the data source |
| secret | An additional secret to be used with the API key |
| username | User for the data source account |
| password | Valid password for the user identified by the 'username' option |

#### The `data_sources.disabled` Section

| Option | Description |
|--------|-------------|
| data_source | One of the Amass data sources that is **not** to be used during the enumeration |

## The Graph Database

All Amass enumeration findings are stored in a graph database. This database is either located in a single file within the output directory or connected to remotely using settings provided by the configuration file.

When a new enumeration begins and a graph database already exists with previous findings for the same target(s), the subdomain names from those previous enumerations are utilized in the new enumeration. New DNS queries are performed against those subdomain names to ensure that they are still legitimate and to obtain current IP addresses.

There is nothing preventing multiple users from sharing a single (remote) graph database and leveraging each others findings across enumerations.

### Setting up PostgreSQL for OWASP Amass

Once you have the postgres server running on your machine and access to the psql tool, execute the follow two commands to initialize your amass database:

```bash
psql postgres://username:password@localhost:5432/ -c "CREATE DATABASE assetdb"
psql postgres://username:password@localhost:5432/ -c "ALTER DATABASE assetdb SET TIMEZONE to 'UTC'"
```

Now you can add the following setting into your Amass `config.yaml` file for storing and analyzing attack surface discoveries using PostgreSQL:

```yaml
options:
  database: "postgres://username:password@localhost:5432/assetdb?testing=works"
```
