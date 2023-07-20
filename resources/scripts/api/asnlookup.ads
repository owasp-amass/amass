-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "ASNLookup"
type = "api"

function start()
    set_rate_limit(1)
end

function check()
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    if (c ~= nil and c.key ~= nil and c.key ~= "") then
        return true
    end
    return false
end

function asn(ctx, addr, asn)
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    local api_url
    if (asn ~= 0) then
        api_url = asn_url(asn)
    else
        api_url = ip_url(addr)
    end

    local resp, err = request(ctx, {
        ['url']=api_url,
        ['header']={
            ['X-RapidAPI-Host']="asn-lookup.p.rapidapi.com",
            ['X-RapidAPI-Key']=c.key,
        },
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "vertical request to service returned with status: " .. resp.status)
        return
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return
    end

    for _, item in pairs(d) do
        local registry
        for v in string.gmatch(item.orgID, "-(%w+)") do
            registry = v
        end

        local netblocks = item.ipv4_prefix
        for _, prefix in pairs(item.ipv6_prefix) do
            table.insert(netblocks, prefix)
        end

        new_asn(ctx, {
            ['addr']=addr,
            ['asn']=item.asnHandle,
            ['cc']=item.orgCountry,
            ['desc']=item.orgName,
            ['registry']=registry,
            ['netblocks']=netblocks,
        })
    end
end

function asn_url(target)
    return "https://asn-lookup.p.rapidapi.com/api?asn=" .. target
end

function ip_url(target)
    return "https://asn-lookup.p.rapidapi.com/api?ip=" .. target
end
