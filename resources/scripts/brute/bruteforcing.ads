-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

name = "Brute Forcing"
type = "brute"

local cfg
local probes = {"www", "online", "webserver", "ns", "ns1", "mail", "smtp", "webmail", "shop", "dev",
            "prod", "test", "vpn", "ftp", "ssh", "secure", "whm", "admin", "webdisk", "mobile",
            "remote", "server", "cpanel", "cloud", "autodiscover", "api", "m", "blog"}

function start()
    cfg = config()
end

function vertical(ctx, domain)
    if (cfg ~= nil and cfg.mode ~= "passive" and 
        cfg.brute_forcing ~= nil and cfg['brute_forcing'].active) then
        make_names(ctx, domain)
    end
end

function resolved(ctx, name, domain, records)
    if (cfg == nil or cfg.mode == "passive") then
        return
    end

    local bf = cfg.brute_forcing
    if (bf == nil or not bf.active or not bf.recursive or bf.min_for_recursive ~= 0) then
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
    -- Do not allow the recursive brute forcing to go beyond the maximum depth
    if (bf.max_depth == nil or (bf.max_depth > 0 and #nparts > bf.max_depth + #dparts)) then
        return
    end
    make_names(ctx, name)
end

function subdomain(ctx, name, domain, times)
    if (cfg == nil or cfg.mode == "passive") then
        return
    end

    local bf = cfg.brute_forcing
    if (bf == nil or not bf.active or not bf.recursive or bf.min_for_recursive ~= times) then
        return
    end

    local nparts = split(name, ".")
    local dparts = split(domain, ".")
    -- Do not allow the recursive brute forcing to go beyond the maximum depth
    if (bf.max_depth == nil or (bf.max_depth > 0 and #nparts > bf.max_depth + #dparts)) then
        return
    end
    make_names(ctx, name)
end

function make_names(ctx, base)
    local wordlist = brute_wordlist(ctx)

    for _, word in pairs(wordlist) do
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
