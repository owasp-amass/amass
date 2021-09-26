-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "BGPView"
type = "api"

function start()
    set_rate_limit(1)
end

function asn(ctx, addr, asn)
    local prefix

    if (asn == 0) then
        if (addr == "") then
            return
        end

        local ip, prefix = get_cidr(ctx, addr)
        if (ip == "" or prefix == nil) then
            return
        end

        asn = get_asn(ctx, ip, prefix)
        if (asn == 0) then
            return
        end
    end

    local a = as_info(ctx, asn)
    if (a == nil) then
        return
    end

    local cidrs = netblocks(ctx, asn)
    if (cidrs == nil or #cidrs == 0) then
        return
    end

    if (prefix == "") then
        prefix = cidrs[1]
        parts = split(prefix, "/")
        addr = parts[1]
    end

    new_asn(ctx, {
        ['addr']=addr,
        ['asn']=asn,
        ['prefix']=prefix,
        ['cc']=a.cc,
        ['registry']=a.registry,
        ['desc']=a.desc,
        ['netblocks']=cidrs,
    })
end

function get_cidr(ctx, addr)
    local url = "https://api.bgpview.io/ip/" .. addr
    local resp, err = request(ctx, {['url']=url})
    if (err ~= nil and err ~= "") then
        log(ctx, "get_cidr request to service failed: " .. err)
        return "", 0
    end

    local j = json.decode(resp)
    if (j == nil or j.status ~= "ok" or j.status_message ~= "Query was successful") then
        return "", 0
    end

    local ip = j.data.rir_allocation.ip
    local cidr = j.data.rir_allocation.cidr
    return ip, cidr
end

function get_asn(ctx, ip, mask)
    local url = "https://api.bgpview.io/prefix/" .. ip .. "/" .. tostring(mask)
    local resp, err = request(ctx, {['url']=url})
    if (err ~= nil and err ~= "") then
        log(ctx, "get_asn request to service failed: " .. err)
        return 0
    end

    local j = json.decode(resp)
    if (j == nil or j.status ~= "ok" or j.status_message ~= "Query was successful") then
        return 0
    end

    local last = #(j.data.asns)
    if (last == 0) then
        return 0
    end

    return j.data.asns[last].asn
end

function as_info(ctx, asn)
    local url = "https://api.bgpview.io/asn/" .. tostring(asn)
    local resp, err = request(ctx, {['url']=url})
    if (err ~= nil and err ~= "") then
        log(ctx, "as_info request to service failed: " .. err)
        return nil
    end

    local j = json.decode(resp)
    if (j == nil or j.data == nil or j.status ~= "ok" or j.status_message ~= "Query was successful") then
        return nil
    end

    local registry = ""
    if (#(j.data.rir_allocation) > 0) then
        registry = j.data.rir_allocation.rir_name
    end

    local name = ""
    if (j.data.name ~= nil) then
        name = name .. j.data.name
    end
    if (j.data.description_full ~= nil) then
        name = name .. " -"
        for _, desc in pairs(j.data.description_full) do
            name = name .. " " .. desc
        end
    end

    return {
        ['asn']=asn,
        desc=name,
        cc=j.data.country_code,
        ['registry']=registry,
    }
end

function netblocks(ctx, asn)
    local url = "https://api.bgpview.io/asn/" .. tostring(asn) .. "/prefixes"
    local resp, err = request(ctx, {['url']=url})
    if (err ~= nil and err ~= "") then
        log(ctx, "netblocks request to service failed: " .. err)
        return nil
    end

    local j = json.decode(resp)
    if (j == nil or j.status ~= "ok" or j.status_message ~= "Query was successful") then
        return nil
    end

    local netblocks = {}
    for _, p in pairs(j.data.ipv4_prefixes) do
        table.insert(netblocks, p.ip .. "/" .. tostring(p.cidr))
    end
    for _, p in pairs(j.data.ipv6_prefixes) do
        table.insert(netblocks, p.ip .. "/" .. tostring(p.cidr))
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

    for _, match in pairs(matches) do
        table.insert(result, match)
    end

    return result
end
