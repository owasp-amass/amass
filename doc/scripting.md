# [![OWASP Logo](https://github.com/OWASP/Amass/blob/master/images/owasp_logo.png) OWASP Amass](https://owasp.org/www-project-amass/) - The Amass Scripting Engine Manual

![Network graph](https://github.com/OWASP/Amass/blob/master/images/network_06092018.png "Amass Network Mapping")

----

## Introduction

The Amass Scripting Engine allows users to provide their own data source implementations. Amass Data Source (file extension `.ads`) scripts are executed in an embedded [Lua](http://www.lua.org) programming environment, similar to the [Nmap Scripting Engine](https://nmap.org/book/nse.html). The scripts can provide findings to the Amass cyclic enumeration process using web scraping and crawling, REST APIs, TLS certificates, brute forcing, DNS name permutation, executing local programs, reading files and databases, etc.

This document will show the format of an Amass data source script, the callback functions that are triggered during enumerations, and the custom functions made available in the environment. These callbacks and custom functions allows scripts to receive requests from Amass and return discoveries to be shared with the architecture. Users can leverage the [Lua Programming Language](https://www.lua.org/pil/#2ed) and the [Lua Standard Library](https://www.lua.org/manual/5.1/manual.html) documentation to take full advantage of the Amass Scripting Engine.

The default Amass data source scripts can be found in [resources/scripts](../resources/scripts), and are separated by the various scripts types. In order to execute your own script, put the `.ads` file under a directory named `scripts` that exists in the Amass output directory. Amass will find the script in that directory and use it during each enumeration.

The Amass Scripting Engine also makes two Lua modules available to users: [gluaurl](https://github.com/cjoudrey/gluaurl) for URL parsing/building and [gopher-json](https://github.com/layeh/gopher-json) for simple JSON encoding/decoding. These modules are made available by default and can be used by scripts via `require("url")` and `require("json")`, respectively.

## Script Format

Amass data source scripts contain the `name` field, `type` field, and at least one callback function to receive Amass events. These fields can be defined just as you would any other Lua global variables. The callback functions must use the predetermined names shown in the subsection below. Their names must be lowercase as shown.

### `name` Field

The `name` field provides a unique identifier for the data source that will be shared throughout the enumeration. All script names are compared in lowercase and must be unique. The name should be short and not have spaces in order to provide output consistency. The following command will show already used names:

```bash
amass enum --list
```

### `type` Field

The `type` field provides the category of the data source implemented by the script. The following types are valid:

| Valid Value | Category |
|:------------|:---------|
| "dns"       | DNS Queries |
| "axfr"      | DNS Zone Transfers |
| "scrape"    | Web Scraping |
| "api"       | Various APIs |
| "cert"      | TLS Certificates |
| "archive"   | Web Archives |
| "brute"     | Brute Forcing |
| "alt"       | Name Alterations |
| "guess"     | Name Guessing |
| "rir"       | Regional Internet Registry |
| "ext"       | External Program / Data Source |

### `subdomainre` String

The `subdomainre` string is a global variable that contains a regular expression pattern that will match fully qualified domain names.

### `api` Table

If the `name` field for a script has a matching entry in the Amass configuration file for API authentication information, then a Lua table will be made global in the script. The `api` table fields are show below. Only the fields set in the configuration file will be set in the `api` table for the script.

| Field Name | Data Type |
|:-----------|:----------|
| username   | string    |
| password   | string    |
| key        | string    |
| secret     | string    |
| ttl        | number    |

### `start` Callback

Amass will execute the `start` function (if the script defines it) once, at the beginning of the enumeration process and before any other callbacks are executed. Most data source implementations use this callback as the place to set the rate limit (more about this later) for the script.

```lua
function start()
    setratelimit(1)
end
```

### `stop` Callback

Amass will execute the `stop` function (if the script defines it) once, at the end of the enumeration process and after all other callbacks are executed.

```lua
function stop()
    -- Cleanup code, etc.
end
```

### `vertical` Callback

Amass executes the `vertical` callback function when attempting to perform vertical domain name correlation. The function is provided the domain name of interest and the script sends back subdomain names it is able to discover.

```lua
function vertical(ctx, domain)
    -- Send back discovered subdomain names
    newname(ctx, name)
end
```

| Field Name | Data Type |
|:-----------|:----------|
| ctx        | UserData  |
| domain     | string    |

The `ctx` parameter is a reference to the context of the caller, which is necessary for many of the custom calls shown below.

### `horizontal` Callback

Amass executes the `horizontal` callback function when attempting to perform horizontal domain name correlation. The function is provided the domain name of interest and the script sends back associated domain names it is able to discover.

```lua
function horizontal(ctx, domain)
    -- Send back an associated domain name
    associated(ctx, domain, assoc)
end
```

| Field Name | Data Type |
|:-----------|:----------|
| ctx        | UserData  |
| domain     | string    |

The `ctx` parameter is a reference to the context of the caller, which is necessary for many of the custom calls shown below.

### `resolved` Callback

Amass executes the `resolved` callback function after successfully resolving the provided `name` via DNS query. The callback is executed for each DNS name validated this way.

```lua
function resolved(ctx, name, domain, records)
    crawl(ctx, "https://" .. name))
end
```

| Field Name | Data Type |
|:-----------|:----------|
| ctx        | UserData  |
| name       | string    |
| domain     | string    |
| records    | table     |

The `records` parameter is a table of tables that each contain the following fields:

| Field Name | Data Type |
|:-----------|:----------|
| rrname     | string    |
| rrtype     | number    |
| rrdata     | string    |

### `subdomain` Callback

Amass executes the `subdomain` callback function after successfully resolving the provided `name` via DNS query and checking that it is a proper subdomain name. A proper subdomain name must have more labels than the root domain name and be resolved with a hostname label. For example, if `example.com` is the root domain name, and the FQDN `www.depta.example.com` is successfully resolved, then the proper subdomain name `depta.example.com` will be provided to the `subdomain` callback function. The `times` parameter shares how many hostnames have been discovered within this proper subdomain name.

```lua
function subdomain(ctx, name, domain, times)
    if times == 1 then
        crawl(ctx, "https://" .. name))
    end
end
```

| Field Name | Data Type |
|:-----------|:----------|
| ctx        | UserData  |
| name       | string    |
| domain     | string    |
| times      | number    |

### `address` Callback

Amass executes the `address` callback function when attempting to discover additional FQDNs and IP addresses that are within scope. The function is provided an IP address that is within scope and the script sends back related findings.

```lua
function address(ctx, addr)
    -- Send back a related subdomain name
    newname(ctx, name)
    -- Send back a related IP address
    newaddr(ctx, ipaddr, domain)
end
```

| Field Name | Data Type |
|:-----------|:----------|
| ctx        | UserData  |
| addr       | string    |

### `asn` Callback

Amass executes the `asn` callback function when attempting to obtain autonomous system (AS) information from a provide IP address and IP that is within scope. The function is provided an IP address that is within scope and the script sends back the information for the associated AS using the `newasn` (more about this below) function.

```lua
function asn(ctx, addr)
    -- Send back a related AS information
    newasn(ctx, {
        ['addr']=addr,
        ['asn']=tonumber(asn),
        ['desc']=desc,
        prefix=cidr,
    })
end
```

| Field Name | Data Type |
|:-----------|:----------|
| ctx        | UserData  |
| addr       | string    |

### `config` Function

A script can obtain the configuration of the current enumeration process by calling the `config` function.

```lua
function vertical(ctx, domain)
    local cfg = config(ctx)

    print(cfg.mode)
end
```

| Field Name | Data Type |
|:-----------|:----------|
| ctx        | UserData  |

The `config` function returns a rather large table containing values explained in the [User Guide](./user_guide.md) and shown below.

| Field Name       | Data Type |
|:-----------------|:----------|
| mode             | string    |
| event_id         | string    |
| max_dns_queries  | number    |
| dns_record_types | table     |
| resolvers        | table     |
| provided_names   | table     |
| scope            | table     |
| brute_forcing    | table     |
| alterations      | table     |

Most of the tables are simply arrays of strings, but the `scope`, `brute_forcing` and `alterations` tables deserve additional explanation.

The `scope` table has the following fields:

| Field Name | Data Type |
|:-----------|:----------|
| domains    | table     |
| blacklist  | table     |
| addresses  | table     |
| cidrs      | table     |
| asns       | table     |
| ports      | table     |

The `brute_forcing` table has the following fields:

| Field Name        | Data Type |
|:------------------|:----------|
| active            | bool      |
| recursive         | bool      |
| min_for_recursive | number    |

The `alterations` table has the following fields:

| Field Name    | Data Type |
|:--------------|:----------|
| active        | bool      |
| flip_words    | bool      |
| flip_numbers  | bool      |
| add_words     | bool      |
| add_numbers   | bool      |
| edit_distance | number    |

### `brute_wordlist` Function

A script can obtain the wordlist used for brute forcing by the current enumeration process via the `brute_wordlist` function. The return value is an array of strings.

```lua
function vertical(ctx, domain)
    local wordlist = brute_wordlist(ctx)

    for i, word in pairs(wordlist) do
        print(word)
    end
end
```

| Field Name | Data Type |
|:-----------|:----------|
| ctx        | UserData  |

### `alt_wordlist` Function

A script can obtain the wordlist used for name alterations by the current enumeration process via the `alt_wordlist` function. The return value is an array of strings.

```lua
function vertical(ctx, domain)
    local wordlist = alt_wordlist(ctx)

    for i, word in pairs(wordlist) do
        print(word)
    end
end
```

| Field Name | Data Type |
|:-----------|:----------|
| ctx        | UserData  |

### `log` Function

A script can contribute to the enumeration log file by sending a message through the `log` function.

```lua
function sendmsg(ctx, msg)
    log(ctx, name .. ": " .. msg)
end
```

| Field Name | Data Type |
|:-----------|:----------|
| ctx        | UserData  |
| msg        | string    |

### `outputdir` Function

A script can request the filepath to the Amass output directory by executing the `outputdir` function. The returned path can be relative.

```lua
function get_bin(ctx)
    local path = outputdir(ctx)

    return path .. "/bin"
end
```

| Field Name | Data Type |
|:-----------|:----------|
| ctx        | UserData  |

### `inscope` Function

A script can check if a FQDN is in scope of the enumeration process by executing the `inscope` function. The function returns `true` if the name is in scope and `false` otherwise.

```lua
function get_names(ctx, sub)
    if inscope(ctx, sub) then
        crawl(ctx, "https://" .. sub))
    end
end
```

| Field Name | Data Type |
|:-----------|:----------|
| ctx        | UserData  |
| fqdn       | string    |

### `setratelimit` Function

A script can set the number of seconds to wait between each execution of a callback function by using the `setratelimit` function.

```lua
function start()
    setratelimit(2)
end
```

| Field Name | Data Type |
|:-----------|:----------|
| seconds    | number    |

### `checkratelimit` Function

A script can check if the rate limit bucket has been exceeded, and if so, will block for the appropriate amount of time by executing the `checkratelimit` function.

```lua
function vertical(ctx, domain)
    -- Obtain several subdomain names
    for i, n in pairs(subs) do
        checkratelimit()
        crawl(ctx, "https://" .. n))
    end
end
```

### `find` Function

The `find` function performs simple regular expression pattern matching. The function accepts a string containing content to be searched and a regular expression pattern as [defined by the Go standard library](https://golang.org/pkg/regexp/). The `find` function returns a Lua table containing all the matches found in the provided string.

```lua
function vertical(ctx, domain)
    local url = "https://" .. domain
    local page, err = request({['url']=url})
    if (err ~= nil and err ~= "") then
        return
    end

    local matches = find(page, subdomainre)
    if (matches == nil or #matches == 0) then
        return
    end

    for i, sub in pairs(matches) do
        newname(ctx, sub)
    end
end
```

| Field Name | Data Type |
|:-----------|:----------|
| content    | string    |
| pattern    | string    |

### `submatch` Function

The `submatch` function performs simple regular expression pattern matching that supports submatches. The function accepts a string containing content to be searched and a regular expression pattern as [defined by the Go standard library](https://golang.org/pkg/regexp/). The `submatch` function returns a Lua table containing the leftmost match found in the provided string and the submatches. The matches are in the expected order of the 1-based array (table) returned by the function.

```lua
function vertical(ctx, domain)
    local url = "https://" .. domain
    local page, err = request({['url']=url})
    if (err ~= nil and err ~= "") then
        return
    end

    -- Create the pattern that contains submatches

    local matches = submatch(page, pattern)
    -- Send the first submatch
    if (matches ~= nil and #matches >=2 and matches[2] ~= "") then
        newname(ctx, matches[2])
    end
end
```

| Field Name | Data Type |
|:-----------|:----------|
| content    | string    |
| pattern    | string    |

### `request` Function

The `request` function performs HTTP(s) client requests for Amass data source scripts. The function returns the page content and an error value. The function accepts an options table that can include the fields shown below.

```lua
function vertical(ctx, domain)
    local url = "https://" .. domain
    local page, err = request(ctx, {
        method="POST",
        data=body,
        ['url']=url,
        headers={['Content-Type']="application/json"},
        id=api["key"],
        pass=api["secret"],
    })
    if (err ~= nil and err ~= "") then
        return
    end

    -- Utilize the body provided in the response
end
```

| Field Name | Data Type |
|:-----------|:----------|
| ctx        | UserData  |
| params     | table     |

The `params` table has the following fields:

| Field Name | Data Type |
|:-----------|:----------|
| method     | string    |
| data       | string    |
| url        | string    |
| headers    | table     |
| id         | string    |
| pass       | string    |

### `scrape` Function

The `scrape` function performs HTTP(s) client requests for Amass data source scripts. The function returns a boolean value indicating the success of the client request. The body of the response is automatically checked for subdomain names that are in scope of the enumeration process. The function accepts an options table that can include the fields shown below.

```lua
function vertical(ctx, domain)
    local url = "https://" .. domain
    local ok = scrape(ctx, {
        ['url']=url,
        headers={['Content-Type']="application/json"},
        id=api["username"],
        pass=api["password"],
    })
end
```

| Field Name | Data Type |
|:-----------|:----------|
| url        | string    |
| headers    | table     |
| id         | string    |
| pass       | string    |

### `crawl` Function

The `crawl` function performs HTTP(s) web crawling/spidering for Amass data source scripts. The body of the responses are automatically checked for subdomain names that are in scope of the enumeration process. The crawler will not follow more than `max` links unless the provided value is `0`.

```lua
function vertical(ctx, domain)
    local url = "https://" .. domain

    crawl(ctx, url, 50)
end
```

| Field Name | Data Type |
|:-----------|:----------|
| ctx        | UserData  |
| url        | string    |
| max        | number    |

### `newname` Function

The `newname` function allows Amass data source scripts to submit a discovered FQDN. The `fqdn` parameter is automatically checked against the enumeration scope.

```lua
function vertical(ctx, domain)
    -- Discover subdomain names

    newname(ctx, fqdn)
end
```

| Field Name | Data Type |
|:-----------|:----------|
| ctx        | UserData  |
| fqdn       | string    |

### `associated` Function

The `associated` function allows Amass data source scripts to submit a discovered domain name that is associated with a domain name provided by the current enumeration process.

```lua
function horizontal(ctx, domain)
    -- Discover domain names associated with the provided domain parameter

    associated(ctx, domain, assoc)
end
```

| Field Name | Data Type |
|:-----------|:----------|
| ctx        | UserData  |
| domain     | string    |
| assoc      | string    |

### `newaddr` Function

The `newaddr` function allows Amass data source scripts to submit a discovered IP address. The `fqdn` parameter is automatically checked against the enumeration scope.

```lua
function vertical(ctx, domain)
    -- Discover subdomain names and associated IP addresses

    newaddr(ctx, addr, fqdn)
end
```

| Field Name | Data Type |
|:-----------|:----------|
| ctx        | UserData  |
| addr       | string    |
| fqdn       | string    |

### `newasn` Function

The `newasn` function allows Amass data source scripts to submit discovered autonomous system information related to the provided `addr` parameter. The function accepts a table of return values that is defined below.

```lua
function asn(ctx, addr)
    -- Send back a related AS information
    newasn(ctx, {
        ['addr']=addr,
        ['asn']=tonumber(asn),
        ['desc']=desc,
        prefix=cidr,
    })
end
```

| Field Name | Data Type |
|:-----------|:----------|
| addr       | string    |
| asn        | number    |
| desc       | string    |
| prefix     | string    |
