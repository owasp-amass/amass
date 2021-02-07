-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "BGPView"
type = "api"

function start()
    setratelimit(1)
end

function asn(ctx, addr, asn)
    if asn == 0 then
        if addr == "" then
            return
        end

        local ip, cidr = getcidr(addr)
        if ip == "" then
            return
        end

        asn = getasn(ip, cidr)
        if asn == 0 then
            return
        end
    end

    local a = asinfo(asn)
    if a == nil then
        return
    end

    newasn(ctx, {
        ['addr']=addr,
        ['asn']=asn,
        ['prefix']=a.prefix,
        ['cc']=a.cc,
        ['registry']=a.registry,
        ['desc']=a.desc,
        ['netblocks']=netblocks(asn),
    })
end

function getcidr(addr)
    local resp = cacherequest("https://api.bgpview.io/ip/" .. addr)
    if resp == "" then
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

function getasn(ip, cidr)
    local resp = cacherequest("https://api.bgpview.io/prefix/" .. ip .. "/" .. tostring(cidr))
    if resp == "" then
        return 0
    end

    local j = json.decode(resp)
    if (j == nil or j.status ~= "ok" or j.status_message ~= "Query was successful") then
        return 0
    end

    local last = #(j.data.asns)
    if last == 0 then
        return 0
    end

    return j.data.asns[last].asn
end

function asinfo(asn)
    resp = cacherequest("https://api.bgpview.io/asn/" .. tostring(asn))
    if resp == "" then
        return nil
    end

    j = json.decode(resp)
    if (j == nil or j.status ~= "ok" or j.status_message ~= "Query was successful") then
        return nil
    end

    local registry = ""
    if #(j.data.rir_allocation) > 0 then
        registry = j.data.rir_allocation.rir_name
    end

    return {
        ['asn']=asn,
        prefix=ip .. "/" .. tostring(cidr),
        desc=j.data.name .. " - " .. j.data.description_full,
        cc=j.data.country_code,
        ['registry']=registry,
    }
end

function netblocks(asn)
    local resp = cacherequest("https://api.bgpview.io/asn/" .. tostring(asn) .. "/prefixes")
    if resp == "" then
        return nil
    end

    local j = json.decode(resp)
    if (j == nil or j.status ~= "ok" or j.status_message ~= "Query was successful") then
        return nil
    end

    local netblocks = {}
    for i, p in pairs(j.data.ipv4_prefixes) do
        table.insert(netblocks, p.ip .. "/" .. tostring(p.cidr))
    end
    for i, p in pairs(j.data.ipv6_prefixes) do
        table.insert(netblocks, p.ip .. "/" .. tostring(p.cidr))
    end
    return netblocks
end

function cacherequest(url)
    local resp
    local cfg = datasrc_config()
    -- Check if the response data is in the graph database
    if (cfg and cfg.ttl ~= nil and cfg.ttl > 0) then
        resp = obtain_response(url, cfg.ttl)
    end

    if (resp == nil or resp == "") then
        local err

        checkratelimit()
        resp, err = request(ctx, {
            ['url']=url,
            headers={['Content-Type']="application/json"},
        })
        if (err ~= nil and err ~= "") then
            return ""
        end

        if (cfg and cfg.ttl ~= nil and cfg.ttl > 0) then
            cache_response(url, resp)
        end
    end

    return resp
end
