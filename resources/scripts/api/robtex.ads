-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Robtex"
type = "api"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    local cfg = datasrc_config()
    if (cfg == nil) then
        return
    end

    local url = "https://freeapi.robtex.com/pdns/forward/" .. domain
    local resp, err = request(ctx, {
        ['url']=url,
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local j = json.decode("{\"results\": [" .. resp .. "]}")
    if (j == nil or #(j.results) == 0) then
        return
    end

    for _, rr in pairs(j.results) do
        if (rr.rrtype == "A") then
            local d = ipinfo(ctx, rr.rrdata, cfg.ttl)
            if (d == nil) then
                return
            end
            extractnames(ctx, d)
        elseif (rr.rrtype == "NS" or rr.rrtype == "MX") then
            sendnames(ctx, rr.rrdata)
        end
    end
end

function asn(ctx, addr, asn)
    local cfg = datasrc_config()
    if (cfg == nil) then
        return
    end

    local d
    local prefix
    if (asn == 0) then
        if (addr == "") then
            return
        end

        d = ipinfo(ctx, addr, cfg.ttl)
        if (d == nil) then
            return
        end

        asn = d.as
        prefix = d.bgproute
    end

    local cidrs = netblocks(ctx, asn, cfg.ttl)
    if (cidrs == nil or #cidrs == 0) then
        return
    end

    if (prefix == "") then
        prefix = cidrs[1]
        parts = split(prefix, "/")
        addr = parts[1]

        d = ipinfo(ctx, addr, cfg.ttl)
        if (d == nil) then
            return
        end
    end

    extractnames(ctx, d)

    local desc = d.asname
    if (desc == nil) then
        desc = ""
    end
    if (d.whoisdesc ~= nil and string.len(desc) < string.len(d.whoisdesc)) then
        desc = d.whoisdesc
    end
    if (d.asdesc ~= nil and string.len(d.asdesc) > 0) then
        desc = desc .. " - " .. d.asdesc
    elseif (d.routedesc ~= nil and string.len(d.routedesc) > 0) then
        desc = desc .. " - " .. d.routedesc
    end

    newasn(ctx, {
        ['addr']=addr,
        ['asn']=asn,
        ['prefix']=prefix,
        ['desc']=desc,
        ['netblocks']=cidrs,
    })
end

function ipinfo(ctx, addr, ttl)
    local url = "https://freeapi.robtex.com/ipquery/" .. addr
    local resp, err = request(ctx, {
        ['url']=url,
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return nil
    end

    local j = json.decode(resp)
    if (j == nil or j.status ~= "ok") then
        return nil
    end

    return j
end

function extractnames(ctx, djson)
    local sections = {"act", "acth", "pas", "pash"}

    for _, s in pairs(sections) do
        if (djson[s] ~= nil and #(djson[s]) > 0) then
            for _, name in pairs(djson[s]) do
                if inscope(ctx, name.o) then
                    newname(ctx, name.o)
                end
            end
        end
    end
end

function netblocks(ctx, asn, ttl)
    local url = "https://freeapi.robtex.com/asquery/" .. tostring(asn)
    local resp, err = request(ctx, {
        ['url']=url,
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return nil
    end

    local j = json.decode(resp)
    if (j == nil or j.status ~= "ok") then
        return nil
    end

    local netblocks = {}
    for _, net in pairs(j.nets) do
        table.insert(netblocks, net.n)
    end

    if (#netblocks == 0) then
        return nil
    end
    return netblocks
end

function sendnames(ctx, content)
    local names = find(content, subdomainre)
    if (names == nil) then
        return
    end

    local found = {}
    for i, v in pairs(names) do
        if (found[v] == nil) then
            newname(ctx, v)
            found[v] = true
        end
    end
end

function split(str, delim)
    local result = {}
    local pattern = "[^%" .. delim .. "]+"

    local matches = find(str, pattern)
    if (matches == nil or #matches == 0) then
        return result
    end

    for i, match in pairs(matches) do
        table.insert(result, match)
    end

    return result
end
