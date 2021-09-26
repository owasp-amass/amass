-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "IPinfo"
type = "api"

function start()
    set_rate_limit(1)
end

function check()
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
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
    if cfg ~= nil then
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
    local resp = cache_request(ctx, u, ttl)
    if (resp == "") then
        log(ctx, "asn request to service failed: " .. err)
        return 0, ""
    end

    local j = json.decode(resp)
    if (j == nil or j.error ~= nil or j.asn == nil) then
        return 0, ""
    end

    return tonumber(string.sub(j.asn, 3)), j.route
end

function as_info(ctx, asn, ttl, token)
    local strasn = "AS" .. tostring(asn)
    resp = cache_request(ctx, "https://ipinfo.io/" .. strasn .. "/json?token=" .. token, ttl)
    if (resp == "") then
        log(ctx, "asn request to service failed: " .. err)
        return nil
    end

    local j = json.decode(resp)
    if (j == nil or j.asn == nil or j.asn ~= strasn) then
        return nil
    end

    local netblocks = {}
    for _, p in pairs(j.prefixes) do
        table.insert(netblocks, p.netblock)
    end
    for _, p in pairs(j.prefixes6) do
        table.insert(netblocks, p.netblock)
    end

    return {
        ['desc']=j.name,
        ['cc']=j.country,
        ['registry']=j.registry,
        ['netblocks']=netblocks,
    }
end

function cache_request(ctx, url, ttl)
    local resp, err = request(ctx, {['url']=url})
    if (err ~= nil and err ~= "") then
        return ""
    end

    return resp
end
