-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Robtex"
type = "api"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local cfg = datasrc_config()
    if (cfg == nil) then
        return
    end

    local vurl = "https://freeapi.robtex.com/pdns/forward/" .. domain
    local resp, err = request(ctx, {['url']=vurl})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
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
            extract_names(ctx, d)
        elseif (rr.rrtype == "NS" or rr.rrtype == "MX") then
            send_names(ctx, rr.rrdata)
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

        d = ip_info(ctx, addr, cfg.ttl)
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

        d = ip_info(ctx, addr, cfg.ttl)
        if (d == nil) then
            return
        end
    end

    extract_names(ctx, d)

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

    new_asn(ctx, {
        ['addr']=addr,
        ['asn']=asn,
        ['prefix']=prefix,
        ['desc']=desc,
        ['netblocks']=cidrs,
    })
end

function ip_info(ctx, addr, ttl)
    local url = "https://freeapi.robtex.com/ipquery/" .. addr
    local resp, err = request(ctx, {['url']=url})
    if (err ~= nil and err ~= "") then
        log(ctx, "ip_info request to service failed: " .. err)
        return nil
    end

    local j = json.decode(resp)
    if (j == nil or j.status ~= "ok") then
        return nil
    end

    return j
end

function extract_names(ctx, djson)
    local sections = {"act", "acth", "pas", "pash"}

    for _, s in pairs(sections) do
        if (djson[s] ~= nil and #(djson[s]) > 0) then
            for _, name in pairs(djson[s]) do
                if in_scope(ctx, name.o) then
                    new_name(ctx, name.o)
                end
            end
        end
    end
end

function netblocks(ctx, asn, ttl)
    local url = "https://freeapi.robtex.com/asquery/" .. tostring(asn)
    local resp, err = request(ctx, {['url']=url})
    if (err ~= nil and err ~= "") then
        log(ctx, "netblocks request to service failed: " .. err)
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
