-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "Robtex"
type = "api"

function start()
    set_rate_limit(7)
end

function vertical(ctx, domain)
    local url = "https://freeapi.robtex.com/pdns/forward/" .. domain

    local resp, err = request(ctx, {['url']=url})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "vertical request to service returned with status: " .. resp.status)
        return
    end

    local d = json.decode("{\"results\": [" .. resp.body .. "]}")
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return
    elseif (d.results == nil or #(d.results) == 0) then
        return
    end

    for _, rr in pairs(d.results) do
        if (rr.rrtype ~= nil and rr.rrtype == "A") then
            local ip = ipinfo(ctx, rr.rrdata)
            if (ip ~= nil) then
                extract_names(ctx, ip)
            end
        elseif (rr.rrtype ~= nil and (rr.rrtype == "NS" or rr.rrtype == "MX")) then
            send_names(ctx, rr.rrdata)
        end
    end
end

function asn(ctx, addr, asn)
    local d
    local prefix

    if (asn == 0) then
        if (addr == "") then
            return
        end

        d = ip_info(ctx, addr)
        if (d == nil) then
            return
        end
        asn = d.as
        prefix = d.bgproute
        extract_names(ctx, d)
    end

    local cidrs = netblocks(ctx, asn)
    if (cidrs == nil or #cidrs == 0) then
        return
    end

    if (prefix == "") then
        prefix = cidrs[1]
        parts = split(prefix, "/")
        addr = parts[1]

        d = ip_info(ctx, addr)
        if (d == nil) then
            return
        end
        extract_names(ctx, d)
    end

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

function ip_info(ctx, addr)
    local url = "https://freeapi.robtex.com/ipquery/" .. addr

    local resp, err = request(ctx, {['url']=url})
    if (err ~= nil and err ~= "") then
        log(ctx, "ip_info request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "ip_info request to service returned with status: " .. resp.status)
        return
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON ip_info response")
        return nil
    elseif (d.status == nil or d.status ~= "ok") then
        return nil
    end
    return d
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

function netblocks(ctx, asn)
    local url = "https://freeapi.robtex.com/asquery/" .. tostring(asn)

    local resp, err = request(ctx, {['url']=url})
    if (err ~= nil and err ~= "") then
        log(ctx, "netblocks request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "netblocks request to service returned with status: " .. resp.status)
        return
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON netblocks response")
        return nil
    elseif (d.status == nil or d.status ~= "ok" or d.nets == nil) then
        return nil
    end

    local netblocks = {}
    for _, net in pairs(d.nets) do
        if (net ~= nil and net.n ~= nil and net.n ~= "") then
            table.insert(netblocks, net.n)
        end
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
    for _, match in pairs(matches) do
        table.insert(result, match)
    end
    return result
end
