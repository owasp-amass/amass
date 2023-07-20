-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "IPinfo"
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

    local prefix
    if (asn == 0) then
        if (addr == "") then
            return
        end

        asn, prefix = get_asn(ctx, addr, cfg.ttl, c.key)
        if (asn == 0) then
            return
        end
    end

    local a = as_info(ctx, asn, cfg.ttl, c.key)
    if (a == nil) then
        return
    end

    new_asn(ctx, {
        ['addr']=addr,
        ['asn']=asn,
        ['prefix']=prefix,
        ['cc']=a.cc,
        ['registry']=a.registry,
        ['desc']=a.desc,
        ['netblocks']=a.netblocks,
    })
end

function get_asn(ctx, addr, ttl, token)
    local u = "https://ipinfo.io/" .. addr .. "/asn?token=" .. token

    local resp, err = request(ctx, {['url']=u})
    if (err ~= nil and err ~= "") then
        log(ctx, "get_asn request to service failed: " .. err)
        return 0, ""
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "get_asn request to service returned with status: " .. resp.status)
        return 0, ""
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return 0, ""
    elseif (d.error ~= nil or d.asn == nil) then
        return 0, ""
    end

    return tonumber(string.sub(d.asn, 3)), d.route
end

function as_info(ctx, asn, ttl, token)
    local strasn = "AS" .. tostring(asn)
    local u = "https://ipinfo.io/" .. strasn .. "/json?token=" .. token

    local resp, err = request(ctx, {['url']=u})
    if (err ~= nil and err ~= "") then
        log(ctx, "as_info request to service failed: " .. err)
        return nil
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "as_info request to service returned with status: " .. resp.status)
        return nil
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return nil
    elseif (d.asn == nil or d.asn ~= strasn) then
        return nil
    end

    local netblocks = {}
    for _, p in pairs(d.prefixes) do
        table.insert(netblocks, p.netblock)
    end
    for _, p in pairs(d.prefixes6) do
        table.insert(netblocks, p.netblock)
    end

    return {
        ['desc']=d.name,
        ['cc']=d.country,
        ['registry']=d.registry,
        ['netblocks']=netblocks,
    }
end
