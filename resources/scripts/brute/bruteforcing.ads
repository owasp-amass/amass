-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "Brute Forcing"
type = "brute"

probes = {"www", "online", "webserver", "ns", "ns1", "mail", "smtp", "webmail", "shop", "dev",
            "prod", "test", "vpn", "ftp", "ssh", "secure", "whm", "admin", "webdisk", "mobile",
            "remote", "server", "cpanel", "cloud", "autodiscover", "api", "m", "blog"}

function vertical(ctx, domain)
    local cfg = config(ctx)
    if (cfg.mode == "passive") then
        return
    end

    if cfg['brute_forcing'].active then
        make_names(ctx, domain)
    end
end

function resolved(ctx, name, domain, records)
    local cfg = config(ctx)
    if (cfg.mode == "passive") then
        return
    end

    local nparts = split(name, ".")
    local dparts = split(domain, ".")
    -- Do not process resolved root domain names
    if (#nparts == #dparts) then
        return
    end

    -- Do not generate names from CNAMEs or names without A/AAAA records
    if (#records == 0 or (has_cname(records) or not has_addr(records))) then
        return
    end

    local bf = cfg['brute_forcing']
    if (bf.active and bf.recursive and (bf['min_for_recursive'] == 0)) then
        make_names(ctx, name)
    end
end

function subdomain(ctx, name, domain, times)
    local cfg = config(ctx)
    if (cfg.mode == "passive") then
        return
    end

    local bf = cfg['brute_forcing']
    if (bf.active and bf.recursive and (bf['min_for_recursive'] == times)) then
        make_names(ctx, name)
    end
end

function make_names(ctx, base)
    local wordlist = brute_wordlist(ctx)

    for i, word in pairs(wordlist) do
        new_name(ctx, word .. "." .. base)
    end
end

function has_cname(records)
    if (#records == 0) then
        return false
    end

    for _, rec in pairs(records) do
        if rec.rrtype == 5 then
            return true
        end
    end

    return false
end

function has_addr(records)
    if (#records == 0) then
        return false
    end

    for _, rec in pairs(records) do
        if (rec.rrtype == 1 or rec.rrtype == 28) then
            return true
        end
    end

    return false
end

function split(str, delim)
    local result = {}
    local pattern = "[^%" .. delim .. "]+"

    local matches = find(str, pattern)
    if (matches == nil or #matches == 0) then
        return result
    end

    for _, match in pairs(matches) do
        table.insert(result, match)
    end

    return result
end
